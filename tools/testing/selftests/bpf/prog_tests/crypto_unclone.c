// SPDX-License-Identifier: GPL-2.0

/*
 * A packet socket on the device clones the frame before tc ingress runs
 * and must still read the original bytes.
 */

#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#include "test_progs.h"
#include "network_helpers.h"
#include "crypto_unclone.skel.h"

#define NS "crypto_unclone_ns"
#define PAYLOAD_OFF ((int)(ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr)))

static const char payload[16] = "plaintextpayload";

static int raw_sock(const char *ifname)
{
	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = if_nametoindex(ifname),
	};
	struct timeval tv = { .tv_sec = 2 };
	int fd;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (bind(fd, (void *)&sll, sizeof(sll))) {
		close(fd);
		return -1;
	}
	return fd;
}

static void send_frame(int fd, __u16 port)
{
	__u8 frame[PAYLOAD_OFF + 16] = {};
	struct ethhdr *eth = (void *)frame;
	struct iphdr *iph = (void *)(eth + 1);
	struct udphdr *udph = (void *)(iph + 1);

	memset(eth->h_dest, 0xff, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);
	iph->version = 4;
	iph->ihl = 5;
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->tot_len = htons(sizeof(frame) - ETH_HLEN);
	iph->saddr = htonl(0x0a010101);
	iph->daddr = htonl(0x0a010102);
	udph->dest = htons(port);
	udph->source = htons(port);
	udph->len = htons(sizeof(*udph) + 16);
	memcpy(udph + 1, payload, 16);
	ASSERT_EQ(send(fd, frame, sizeof(frame), 0), sizeof(frame), "send");
}

static bool setup_ctx(struct crypto_unclone *skel, const char *algo)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	strcpy(skel->data->algo, algo);
	return ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.unclone_setup),
						&opts), "setup") &&
	       ASSERT_OK(skel->data->status, "setup status");
}

static void run_arm(struct crypto_unclone *skel, struct bpf_program *prog,
		    const char *name)
{
	LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, opts);
	struct ethhdr *eth;
	struct iphdr *iph;
	int tx = -1, rx = -1, n, hits, i;
	__u8 buf[2048];

	hook.ifindex = if_nametoindex("veth1");
	if (!ASSERT_OK(bpf_tc_hook_create(&hook), "hook"))
		return;
	opts.prog_fd = bpf_program__fd(prog);
	if (!ASSERT_OK(bpf_tc_attach(&hook, &opts), "attach"))
		goto out;

	rx = raw_sock("veth1");
	tx = raw_sock("veth0");
	if (!ASSERT_GE(rx, 0, "rx") || !ASSERT_GE(tx, 0, "tx"))
		goto out;

	hits = skel->bss->hits;
	send_frame(tx, skel->data->udp_port);
	eth = (void *)buf;
	iph = (void *)(eth + 1);
	do {
		n = recv(rx, buf, sizeof(buf), 0);
	} while (n > 0 && (n < PAYLOAD_OFF + 16 || eth->h_proto != htons(ETH_P_IP) ||
			   iph->protocol != IPPROTO_UDP));
	if (!ASSERT_GE(n, PAYLOAD_OFF + 16, "recv"))
		goto out;
	/* The socket can wake us before the program has run. */
	for (i = 0; i < 100 && skel->bss->hits == hits; i++)
		usleep(10000);
	ASSERT_EQ(skel->bss->hits, hits + 1, "prog ran");
	ASSERT_OK(skel->data->status, "crypt status");
	ASSERT_OK(memcmp(buf + PAYLOAD_OFF, payload, 16), name);
out:
	if (tx >= 0)
		close(tx);
	if (rx >= 0)
		close(rx);
	hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
	bpf_tc_hook_destroy(&hook);
}

void test_crypto_unclone(void)
{
	struct crypto_unclone *skel;
	struct netns_obj *ns;

	skel = crypto_unclone__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;
	memcpy(skel->bss->key, "testtest12345678", 16);

	ns = netns_new(NS, true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		goto out;
	SYS(out, "ip link add veth0 type veth peer name veth1");
	SYS(out, "ip link set veth0 up");
	SYS(out, "ip link set veth1 up");

	if (test__start_subtest("dynptr_write") && setup_ctx(skel, "ecb(aes)"))
		run_arm(skel, skel->progs.unclone_write, "socket sees plaintext");
	if (test__start_subtest("crypto_inplace") && setup_ctx(skel, "ecb(aes)"))
		run_arm(skel, skel->progs.unclone_crypt, "socket sees plaintext");
	if (test__start_subtest("cbc_inplace_local_iv") && setup_ctx(skel, "cbc(aes)"))
		run_arm(skel, skel->progs.unclone_local_iv, "socket sees plaintext");
	if (test__start_subtest("cbc_iv_in_packet") && setup_ctx(skel, "cbc(aes)"))
		run_arm(skel, skel->progs.unclone_iv, "socket sees original iv");
	if (test__start_subtest("pkt_ptr_across_call") && setup_ctx(skel, "ecb(aes)"))
		run_arm(skel, skel->progs.unclone_pkt_ptr, "socket sees plaintext");
out:
	netns_free(ns);
	crypto_unclone__destroy(skel);
}
