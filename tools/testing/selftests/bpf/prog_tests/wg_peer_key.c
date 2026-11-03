// SPDX-License-Identifier: GPL-2.0

/*
 * Two WireGuard clients, A and B, each in its own netns, talk to a server
 * netns over separate veth links:
 *
 *   NS_A  wg0 10.0.0.1 -- veth 192.168.241.0/24 --+
 *                                                  NS_SRV wg0 10.0.0.2
 *   NS_B  wg0 10.0.0.3 -- veth 192.168.242.0/24 --+
 *
 * The wg0 addresses also have IPv6 counterparts fd00::1, fd00::2, fd00::3.
 * Programs on the server's wg0 (ingress and egress) and on its veth to A
 * record what bpf_skb_wg_rx_peer_key() returns for UDP packets, keyed by
 * destination port. A tc mirred rule on the server's veth to B redirects
 * one port onto wg0's ingress.
 */

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/genetlink.h>
#include <linux/if_packet.h>
#include <linux/wireguard.h>

#include <test_progs.h>
#include <network_helpers.h>

#include "netlink_helpers.h"
#include "wg_peer_key.h"
#include "wg_peer_key.skel.h"
#include "wg_peer_key_fail.skel.h"

#define NS_SRV		"wgpk_srv"
#define NS_A		"wgpk_a"
#define NS_B		"wgpk_b"

#define WG_PORT_SRV	51821
#define WG_PORT_CLI	51820

/* Fixed test keys, generated with wg genkey / wg pubkey */
static const __u8 priv_srv[WG_KEY_LEN] = {
	0x68, 0x46, 0x47, 0x3e, 0x8b, 0xf3, 0x0b, 0x1a, 0x65, 0xe7, 0x1d, 0x7c,
	0xd4, 0xc0, 0x4b, 0xd4, 0x36, 0x04, 0xf6, 0x24, 0x0c, 0x26, 0x7a, 0xdc,
	0xc3, 0xa8, 0xac, 0x55, 0x04, 0x53, 0xe5, 0x7b,
};

static const __u8 pub_srv[WG_KEY_LEN] = {
	0x84, 0x6c, 0xc6, 0xcd, 0x92, 0x2b, 0xc0, 0x86, 0x08, 0x87, 0x2c, 0x2e,
	0xff, 0x2f, 0x9c, 0xc0, 0x4f, 0x58, 0xb5, 0x86, 0x5a, 0xd3, 0x32, 0xa4,
	0x67, 0x01, 0xca, 0x8f, 0x1c, 0x06, 0xfc, 0x45,
};

static const __u8 priv_a[WG_KEY_LEN] = {
	0x98, 0x45, 0x80, 0xd8, 0x4b, 0xb9, 0xf4, 0xab, 0x2d, 0x76, 0x03, 0x4d,
	0xc1, 0xdf, 0x94, 0x0c, 0x6f, 0x96, 0x05, 0x71, 0x36, 0x76, 0x5b, 0xf4,
	0x9c, 0x87, 0xfa, 0xf8, 0x6b, 0x20, 0x33, 0x79,
};

static const __u8 pub_a[WG_KEY_LEN] = {
	0x21, 0x18, 0x95, 0xfb, 0x5b, 0x61, 0x56, 0xeb, 0x9c, 0xf3, 0xbe, 0x15,
	0x26, 0x9c, 0xa7, 0x34, 0xc6, 0x82, 0xbd, 0x7f, 0x8e, 0x68, 0xd0, 0xc1,
	0x77, 0x4d, 0xd8, 0x3f, 0x4d, 0xad, 0xb4, 0x48,
};

static const __u8 priv_b[WG_KEY_LEN] = {
	0x78, 0x58, 0x7f, 0x48, 0x30, 0x06, 0xde, 0x16, 0xaf, 0xd1, 0x40, 0x6f,
	0x69, 0xbc, 0x81, 0x6b, 0x5a, 0x18, 0x1e, 0x29, 0xd0, 0x1d, 0x0a, 0x95,
	0x0f, 0xc3, 0x79, 0x2d, 0xc6, 0xfe, 0x4e, 0x4d,
};

static const __u8 pub_b[WG_KEY_LEN] = {
	0xff, 0x0b, 0x1f, 0xae, 0x6e, 0x6a, 0x7e, 0xed, 0x6e, 0x40, 0x7e, 0x2f,
	0xde, 0x8a, 0x19, 0xf0, 0x2c, 0x14, 0x8d, 0xb2, 0xf1, 0x92, 0x8f, 0x7c,
	0xe9, 0x9c, 0x0c, 0xb4, 0xba, 0x70, 0x3f, 0x01,
};

static const __u8 zero_key[WG_KEY_LEN];

struct wg_peer_cfg {
	const __u8 *pubkey;
	const char *endpoint;
	__u16 endpoint_port;
	const char *allowed_ip;
	const char *allowed_ip6;
};

struct genl_req {
	struct nlmsghdr n;
	struct genlmsghdr g;
	char buf[1024];
};

static int wg_genl_family(struct rtnl_handle *rth)
{
	struct genl_req req = {
		.n.nlmsg_len	= NLMSG_LENGTH(GENL_HDRLEN),
		.n.nlmsg_type	= GENL_ID_CTRL,
		.n.nlmsg_flags	= NLM_F_REQUEST,
		.g.cmd		= CTRL_CMD_GETFAMILY,
		.g.version	= 1,
	};
	struct nlmsghdr *answer = NULL;
	struct rtattr *rta;
	int len, id = -1;

	addattrstrz(&req.n, sizeof(req), CTRL_ATTR_FAMILY_NAME, WG_GENL_NAME);
	if (rtnl_talk(rth, &req.n, &answer) < 0)
		return -1;

	len = answer->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
	rta = (struct rtattr *)((char *)NLMSG_DATA(answer) + GENL_HDRLEN);
	for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len))
		if (rta->rta_type == CTRL_ATTR_FAMILY_ID)
			id = *(__u16 *)RTA_DATA(rta);
	free(answer);
	return id;
}

/* Equivalent of "wg set", in the current netns */
static int wg_set_device(const char *ifname, const __u8 *privkey, __u16 port,
			 const struct wg_peer_cfg *peers, int nr_peers)
{
	struct genl_req req = {
		.n.nlmsg_len	= NLMSG_LENGTH(GENL_HDRLEN),
		.n.nlmsg_flags	= NLM_F_REQUEST,
		.g.cmd		= WG_CMD_SET_DEVICE,
		.g.version	= WG_GENL_VERSION,
	};
	struct rtattr *peers_nest, *peer, *aips, *aip;
	struct rtnl_handle rth;
	int family, i, err = -1;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC) < 0)
		return -1;
	family = wg_genl_family(&rth);
	if (family < 0)
		goto out;
	req.n.nlmsg_type = family;

	addattrstrz(&req.n, sizeof(req), WGDEVICE_A_IFNAME, ifname);
	addattr_l(&req.n, sizeof(req), WGDEVICE_A_PRIVATE_KEY, privkey,
		  WG_KEY_LEN);
	addattr16(&req.n, sizeof(req), WGDEVICE_A_LISTEN_PORT, port);
	peers_nest = addattr_nest(&req.n, sizeof(req),
				  WGDEVICE_A_PEERS | NLA_F_NESTED);
	for (i = 0; i < nr_peers; i++) {
		struct sockaddr_in sin = {
			.sin_family	= AF_INET,
			.sin_port	= htons(peers[i].endpoint_port),
		};
		struct in6_addr ip6;
		struct in_addr ip;

		if (inet_pton(AF_INET, peers[i].endpoint, &sin.sin_addr) != 1 ||
		    inet_pton(AF_INET, peers[i].allowed_ip, &ip) != 1 ||
		    inet_pton(AF_INET6, peers[i].allowed_ip6, &ip6) != 1)
			goto out;

		peer = addattr_nest(&req.n, sizeof(req), NLA_F_NESTED);
		addattr_l(&req.n, sizeof(req), WGPEER_A_PUBLIC_KEY,
			  peers[i].pubkey, WG_KEY_LEN);
		addattr_l(&req.n, sizeof(req), WGPEER_A_ENDPOINT, &sin,
			  sizeof(sin));
		aips = addattr_nest(&req.n, sizeof(req),
				    WGPEER_A_ALLOWEDIPS | NLA_F_NESTED);
		aip = addattr_nest(&req.n, sizeof(req), NLA_F_NESTED);
		addattr16(&req.n, sizeof(req), WGALLOWEDIP_A_FAMILY, AF_INET);
		addattr_l(&req.n, sizeof(req), WGALLOWEDIP_A_IPADDR, &ip,
			  sizeof(ip));
		addattr8(&req.n, sizeof(req), WGALLOWEDIP_A_CIDR_MASK, 32);
		addattr_nest_end(&req.n, aip);
		aip = addattr_nest(&req.n, sizeof(req), NLA_F_NESTED);
		addattr16(&req.n, sizeof(req), WGALLOWEDIP_A_FAMILY, AF_INET6);
		addattr_l(&req.n, sizeof(req), WGALLOWEDIP_A_IPADDR, &ip6,
			  sizeof(ip6));
		addattr8(&req.n, sizeof(req), WGALLOWEDIP_A_CIDR_MASK, 128);
		addattr_nest_end(&req.n, aip);
		addattr_nest_end(&req.n, aips);
		addattr_nest_end(&req.n, peer);
	}
	addattr_nest_end(&req.n, peers_nest);

	err = rtnl_talk(&rth, &req.n, NULL);
out:
	rtnl_close(&rth);
	return err;
}

static int wg_set_device_ns(const char *ns, const __u8 *privkey, __u16 port,
			    const struct wg_peer_cfg *peers, int nr_peers)
{
	struct nstoken *tok;
	int err;

	tok = open_netns(ns);
	if (!ASSERT_OK_PTR(tok, "open_netns"))
		return -1;
	err = wg_set_device("wg0", privkey, port, peers, nr_peers);
	close_netns(tok);
	return err;
}

static int setup_topology(void)
{
	const struct wg_peer_cfg srv_peers[] = {
		{ pub_a, "192.168.241.1", WG_PORT_CLI, "10.0.0.1", "fd00::1" },
		{ pub_b, "192.168.242.1", WG_PORT_CLI, "10.0.0.3", "fd00::3" },
	};
	const struct wg_peer_cfg a_peer = {
		pub_srv, "192.168.241.2", WG_PORT_SRV, "10.0.0.2", "fd00::2"
	};
	const struct wg_peer_cfg b_peer = {
		pub_srv, "192.168.242.2", WG_PORT_SRV, "10.0.0.2", "fd00::2"
	};

	if (!ASSERT_OK(make_netns(NS_A), "make_netns a"))
		goto fail;
	if (!ASSERT_OK(make_netns(NS_B), "make_netns b"))
		goto fail;

	SYS(fail, "ip -n %s link add veth0 type veth peer name vetha netns %s",
	    NS_A, NS_SRV);
	SYS(fail, "ip -n %s link add veth0 type veth peer name vethb netns %s",
	    NS_B, NS_SRV);
	SYS(fail, "ip -n %s addr add 192.168.241.1/24 dev veth0", NS_A);
	SYS(fail, "ip -n %s addr add 192.168.241.2/24 dev vetha", NS_SRV);
	SYS(fail, "ip -n %s addr add 192.168.242.1/24 dev veth0", NS_B);
	SYS(fail, "ip -n %s addr add 192.168.242.2/24 dev vethb", NS_SRV);
	SYS(fail, "ip -n %s link set veth0 up", NS_A);
	SYS(fail, "ip -n %s link set veth0 up", NS_B);
	SYS(fail, "ip -n %s link set vetha up", NS_SRV);
	SYS(fail, "ip -n %s link set vethb up", NS_SRV);

	SYS(fail, "ip -n %s link add wg0 type wireguard", NS_A);
	SYS(fail, "ip -n %s link add wg0 type wireguard", NS_B);
	SYS(fail, "ip -n %s addr add 10.0.0.2/24 dev wg0", NS_SRV);
	SYS(fail, "ip -n %s addr add 10.0.0.1/24 dev wg0", NS_A);
	SYS(fail, "ip -n %s addr add 10.0.0.3/24 dev wg0", NS_B);
	SYS(fail, "ip -n %s addr add fd00::2/64 dev wg0 nodad", NS_SRV);
	SYS(fail, "ip -n %s addr add fd00::1/64 dev wg0 nodad", NS_A);
	SYS(fail, "ip -n %s addr add fd00::3/64 dev wg0 nodad", NS_B);

	if (!ASSERT_OK(wg_set_device_ns(NS_SRV, priv_srv, WG_PORT_SRV,
					srv_peers, 2), "wg_set srv"))
		goto fail;
	if (!ASSERT_OK(wg_set_device_ns(NS_A, priv_a, WG_PORT_CLI, &a_peer, 1),
		       "wg_set a"))
		goto fail;
	if (!ASSERT_OK(wg_set_device_ns(NS_B, priv_b, WG_PORT_CLI, &b_peer, 1),
		       "wg_set b"))
		goto fail;

	SYS(fail, "ip -n %s link set wg0 up", NS_SRV);
	SYS(fail, "ip -n %s link set wg0 up", NS_A);
	SYS(fail, "ip -n %s link set wg0 up", NS_B);

	/* act_mirred is the other way to put a packet on wg0's ingress */
	SYS(fail, "tc -n %s qdisc add dev vethb clsact", NS_SRV);
	SYS(fail, "tc -n %s filter add dev vethb ingress protocol ip flower ip_proto udp dst_port %d action mirred ingress redirect dev wg0",
	    NS_SRV, WG_PK_PORT_MIRRED);
	return 0;
fail:
	return -1;
}

static void cleanup_topology(void)
{
	remove_netns(NS_SRV);
	remove_netns(NS_A);
	remove_netns(NS_B);
}

/*
 * Send one UDP datagram from @ns. @src is bound with IP_TRANSPARENT, so it
 * need not be a local address.
 */
static int send_udp(const char *ns, const char *src, const char *dst,
		    __u16 port)
{
	int family = strchr(dst, ':') ? AF_INET6 : AF_INET;
	struct sockaddr_storage sa;
	struct nstoken *tok;
	int fd, err = -1, one = 1;
	socklen_t len;

	tok = open_netns(ns);
	if (!tok)
		return -1;
	fd = socket(family, SOCK_DGRAM, 0);
	if (fd < 0)
		goto out;
	if (src) {
		if (make_sockaddr(family, src, 0, &sa, &len) ||
		    setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) ||
		    bind(fd, (struct sockaddr *)&sa, len))
			goto out_close;
	}
	if (make_sockaddr(family, dst, port, &sa, &len))
		goto out_close;
	if (sendto(fd, "x", 1, 0, (struct sockaddr *)&sa, len) == 1)
		err = 0;
out_close:
	close(fd);
out:
	close_netns(tok);
	return err;
}

/*
 * Send an Ethernet frame carrying @len bytes, too few for an IPv4 header,
 * with ethertype IPv4 out of @ifname in @ns.
 */
static int send_short_frame(const char *ns, const char *ifname, size_t len)
{
	struct sockaddr_ll sll = {
		.sll_family	= AF_PACKET,
		.sll_protocol	= htons(ETH_P_IP),
		.sll_halen	= ETH_ALEN,
	};
	char frame[ETH_HLEN + 16] = {};
	struct ethhdr *eth = (struct ethhdr *)frame;
	struct nstoken *tok;
	int fd, err = -1;

	if (len > sizeof(frame) - ETH_HLEN)
		return -1;
	tok = open_netns(ns);
	if (!tok)
		return -1;
	sll.sll_ifindex = if_nametoindex(ifname);
	memset(eth->h_dest, 0xff, ETH_ALEN);
	memset(sll.sll_addr, 0xff, ETH_ALEN);
	eth->h_source[0] = 0x02;
	eth->h_proto = htons(ETH_P_IP);
	fd = socket(AF_PACKET, SOCK_RAW, 0);
	if (fd < 0)
		goto out;
	if (sendto(fd, frame, ETH_HLEN + len, 0, (struct sockaddr *)&sll,
		   sizeof(sll)) == ETH_HLEN + len)
		err = 0;
	close(fd);
out:
	close_netns(tok);
	return err;
}

static long srv_wg0_stat(const char *name)
{
	char cmd[128];
	long val = -1;
	FILE *f;

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s cat /sys/class/net/wg0/statistics/%s",
		 NS_SRV, name);
	f = popen(cmd, "r");
	if (!f)
		return -1;
	if (fscanf(f, "%ld", &val) != 1)
		val = -1;
	pclose(f);
	return val;
}

/*
 * The first packet to a peer waits for the handshake, so keep sending until
 * the program has seen one.
 */
static bool send_until_hit(const char *ns, const char *src, const char *dst,
			   __u16 port, __u32 *hits)
{
	int i;

	for (i = 0; i < 50; i++) {
		if (send_udp(ns, src, dst, port))
			return false;
		usleep(100000);
		if (READ_ONCE(*hits))
			return true;
	}
	return false;
}

static bool send_short_until_hit(__u32 *hits)
{
	int i;

	for (i = 0; i < 50; i++) {
		if (send_short_frame(NS_A, "veth0", 8))
			return false;
		usleep(100000);
		if (READ_ONCE(*hits))
			return true;
	}
	return false;
}

static void check_key(const char *name, const struct wg_result *r,
		      const __u8 *want, const __u8 *other)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "%s ret", name);
	ASSERT_EQ(r->ret, 0, buf);
	snprintf(buf, sizeof(buf), "%s key", name);
	ASSERT_OK(memcmp(r->key, want, WG_KEY_LEN), buf);
	snprintf(buf, sizeof(buf), "%s key is not the other peer's", name);
	ASSERT_NEQ(memcmp(r->key, other, WG_KEY_LEN), 0, buf);
}

static void check_error(const char *name, int ret, int want, const __u8 *key,
			size_t len)
{
	ASSERT_EQ(ret, want, name);
	ASSERT_OK(memcmp(key, zero_key, len), "key zeroed on error");
}

static int attach(struct bpf_program *prog, const char *ifname,
		  struct bpf_link **link)
{
	struct nstoken *tok;
	int ifindex;

	tok = open_netns(NS_SRV);
	if (!ASSERT_OK_PTR(tok, "open_netns"))
		return -1;
	ifindex = if_nametoindex(ifname);
	if (ASSERT_GT(ifindex, 0, ifname))
		*link = bpf_program__attach_tcx(prog, ifindex, NULL);
	close_netns(tok);
	return ASSERT_OK_PTR(*link, "attach_tcx") ? 0 : -1;
}

static void run_attribution(void)
{
	struct bpf_link *l_in = NULL, *l_eg = NULL, *l_veth = NULL;
	struct __sk_buff ctx = {};
	struct ipv4_packet pkt;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt,
		.data_size_in = sizeof(pkt),
		.ctx_in = &ctx,
		.ctx_size_in = sizeof(ctx),
	);
	struct wg_peer_key__bss *bss;
	struct wg_peer_key *skel;
	long frame_errors;
	struct nstoken *tok;
	int wg_ifindex, i, err;

	tok = open_netns(NS_SRV);
	if (!ASSERT_OK_PTR(tok, "open_netns"))
		return;
	wg_ifindex = if_nametoindex("wg0");
	close_netns(tok);
	if (!ASSERT_GT(wg_ifindex, 0, "srv wg0 ifindex"))
		return;
	ctx.ifindex = wg_ifindex;

	skel = wg_peer_key__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;
	skel->rodata->wg_ifindex = wg_ifindex;
	if (!ASSERT_OK(wg_peer_key__load(skel), "skel_load"))
		goto out;

	if (attach(skel->progs.wg_ingress, "wg0", &l_in) ||
	    attach(skel->progs.wg_egress, "wg0", &l_eg) ||
	    attach(skel->progs.veth_ingress, "vetha", &l_veth))
		goto out;

	bss = skel->bss;

	/* Exactness: each peer's traffic returns that peer's key */
	if (ASSERT_TRUE(send_until_hit(NS_A, NULL, "10.0.0.2", WG_PK_PORT_A,
				       &bss->res_a.hits), "traffic A")) {
		check_key("A", &bss->res_a, pub_a, pub_b);
		check_error("short buffer ret", bss->res_short.ret, -EINVAL,
			    bss->res_short.key, sizeof(bss->res_short.key));
	}
	if (ASSERT_TRUE(send_until_hit(NS_B, NULL, "10.0.0.2", WG_PK_PORT_B,
				       &bss->res_b.hits), "traffic B"))
		check_key("B", &bss->res_b, pub_b, pub_a);
	if (ASSERT_TRUE(send_until_hit(NS_A, NULL, "fd00::2", WG_PK_PORT_A6,
				       &bss->res_a6.hits), "traffic A6"))
		check_key("A6", &bss->res_a6, pub_a, pub_b);
	if (ASSERT_TRUE(send_until_hit(NS_B, NULL, "fd00::2", WG_PK_PORT_B6,
				       &bss->res_b6.hits), "traffic B6"))
		check_key("B6", &bss->res_b6, pub_b, pub_a);

	/*
	 * WireGuard drops a packet A sends with B's source before the hook.
	 * The next packet the program sees on this port must be A's own.
	 */
	frame_errors = srv_wg0_stat("rx_frame_errors");
	if (!ASSERT_GE(frame_errors, 0, "rx_frame_errors before"))
		goto out;
	for (i = 0; i < 5; i++)
		if (!ASSERT_OK(send_udp(NS_A, "10.0.0.3", "10.0.0.2",
					WG_PK_PORT_SPOOF), "send spoofed"))
			goto out;
	usleep(500000);
	ASSERT_EQ(srv_wg0_stat("rx_frame_errors"), frame_errors + 5,
		  "spoofed packets dropped by wg");
	ASSERT_EQ(READ_ONCE(bss->res_spoof.hits), 0, "spoofed packets unseen");
	if (ASSERT_TRUE(send_until_hit(NS_A, NULL, "10.0.0.2",
				       WG_PK_PORT_SPOOF, &bss->res_spoof.hits),
			"traffic spoof control")) {
		ASSERT_EQ(bss->res_spoof.saddr, inet_addr("10.0.0.1"),
			  "first spoof-port packet is from 10.0.0.1");
		check_key("spoof control", &bss->res_spoof, pub_a, pub_b);
	}

	if (ASSERT_TRUE(send_until_hit(NS_SRV, NULL, "10.0.0.1",
				       WG_PK_PORT_EGRESS,
				       &bss->res_egress.hits),
			"traffic egress"))
		check_error("egress ret", bss->res_egress.ret, -EOPNOTSUPP,
			    bss->res_egress.key, WG_KEY_LEN);

	if (ASSERT_TRUE(send_until_hit(NS_A, NULL, "192.168.241.2",
				       WG_PK_PORT_VETH, &bss->res_veth.hits),
			"traffic veth"))
		check_error("veth ret", bss->res_veth.ret, -EOPNOTSUPP,
			    bss->res_veth.key, WG_KEY_LEN);

	/* Redirected packets get the key of the peer owning their source */
	if (ASSERT_TRUE(send_until_hit(NS_A, "10.0.0.1", "192.168.241.2",
				       WG_PK_PORT_INJECT,
				       &bss->res_inject.hits),
			"traffic inject"))
		check_key("inject", &bss->res_inject, pub_a, pub_b);
	if (ASSERT_TRUE(send_until_hit(NS_A, "10.0.0.3", "192.168.241.2",
				       WG_PK_PORT_INJECT_B,
				       &bss->res_inject_b.hits),
			"traffic inject B"))
		check_key("inject B", &bss->res_inject_b, pub_b, pub_a);
	if (ASSERT_TRUE(send_until_hit(NS_B, "10.0.0.3", "192.168.242.2",
				       WG_PK_PORT_MIRRED,
				       &bss->res_mirred.hits),
			"traffic mirred"))
		check_key("mirred", &bss->res_mirred, pub_b, pub_a);

	if (ASSERT_TRUE(send_until_hit(NS_A, NULL, "192.168.241.2",
				       WG_PK_PORT_NOENT, &bss->res_noent.hits),
			"traffic noent"))
		check_error("noent ret", bss->res_noent.ret, -ENOENT,
			    bss->res_noent.key, WG_KEY_LEN);

	/* An 8 byte frame redirected onto wg0 has no room for an IPv4 header */
	if (ASSERT_TRUE(send_short_until_hit(&bss->res_short_hdr.hits),
			"traffic short header"))
		check_error("short header ret", bss->res_short_hdr.ret,
			    -EINVAL, bss->res_short_hdr.key, WG_KEY_LEN);

	/* test_run sets skb->dev from ifindex but is not at TC ingress */
	tok = open_netns(NS_SRV);
	if (!ASSERT_OK_PTR(tok, "open_netns"))
		goto out;
	pkt = pkt_v4;
	pkt.iph.saddr = inet_addr("10.0.0.1");
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.wg_test_run),
				     &topts);
	close_netns(tok);
	if (ASSERT_OK(err, "test_run") &&
	    ASSERT_EQ(bss->res_test_run.hits, 1, "test_run hits"))
		check_error("test_run ret", bss->res_test_run.ret,
			    -EOPNOTSUPP, bss->res_test_run.key, WG_KEY_LEN);
out:
	bpf_link__destroy(l_veth);
	bpf_link__destroy(l_eg);
	bpf_link__destroy(l_in);
	wg_peer_key__destroy(skel);
}

void test_wg_peer_key(void)
{
	if (!ASSERT_OK(make_netns(NS_SRV), "make_netns srv"))
		goto out;
	/* Kernels built without WireGuard cannot run any of this */
	if (SYS_NOFAIL("ip -n %s link add wg0 type wireguard", NS_SRV)) {
		printf("%s:SKIP:wireguard link type unavailable (CONFIG_WIREGUARD or iproute2)\n",
		       __func__);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(setup_topology(), "setup_topology"))
		goto out;

	if (test__start_subtest("attribution"))
		run_attribution();
	RUN_TESTS(wg_peer_key_fail);
out:
	cleanup_topology();
}
