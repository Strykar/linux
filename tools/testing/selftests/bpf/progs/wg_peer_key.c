// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_tracing_net.h"
#include "wg_peer_key.h"

extern int bpf_skb_wg_rx_peer_key(struct __sk_buff *skb, __u8 *key,
				  __u32 key__sz) __ksym;

const volatile __u32 wg_ifindex;

struct wg_result res_a;
struct wg_result res_b;
struct wg_result res_a6;
struct wg_result res_b6;
struct wg_result res_egress;
struct wg_result res_veth;
struct wg_result res_inject;
struct wg_result res_inject_b;
struct wg_result res_noent;
struct wg_result res_mirred;
struct wg_result res_spoof;
struct wg_result res_short_hdr;
struct wg_result res_test_run;
struct wg_short_result res_short;

/*
 * Parse relative to the network header: a packet that act_mirred redirects
 * onto wg0 keeps the mac header of the device it came from.
 */
static int udp_dport(struct __sk_buff *skb, __u32 *saddr)
{
	struct udphdr udph;
	__u32 l4off;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr iph;

		if (bpf_skb_load_bytes_relative(skb, 0, &iph, sizeof(iph),
						BPF_HDR_START_NET) ||
		    iph.ihl != 5 || iph.protocol != IPPROTO_UDP)
			return -1;
		*saddr = iph.saddr;
		l4off = sizeof(iph);
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6h;

		if (bpf_skb_load_bytes_relative(skb, 0, &ip6h, sizeof(ip6h),
						BPF_HDR_START_NET) ||
		    ip6h.nexthdr != IPPROTO_UDP)
			return -1;
		l4off = sizeof(ip6h);
	} else {
		return -1;
	}
	if (bpf_skb_load_bytes_relative(skb, l4off, &udph, sizeof(udph),
					BPF_HDR_START_NET))
		return -1;
	return bpf_ntohs(udph.dest);
}

/*
 * Keep only the first packet of each kind, so retries and duplicates cannot
 * change a result while userspace reads it.
 */
static void record(struct __sk_buff *skb, struct wg_result *r, __u32 saddr)
{
	__u8 key[WG_PK_KEY_LEN];
	int ret;

	if (r->hits)
		return;
	__builtin_memset(key, 0xff, sizeof(key));
	ret = bpf_skb_wg_rx_peer_key(skb, key, sizeof(key));
	__builtin_memcpy(r->key, key, sizeof(key));
	r->ret = ret;
	r->saddr = saddr;
	barrier();
	r->hits = 1;
}

static void record_short(struct __sk_buff *skb, struct wg_short_result *r)
{
	__u8 key[16];
	int ret;

	if (r->hits)
		return;
	__builtin_memset(key, 0xff, sizeof(key));
	ret = bpf_skb_wg_rx_peer_key(skb, key, sizeof(key));
	__builtin_memcpy(r->key, key, sizeof(key));
	r->ret = ret;
	barrier();
	r->hits = 1;
}

SEC("tc/ingress")
int wg_ingress(struct __sk_buff *skb)
{
	__u32 saddr = 0;
	int dport;

	/* Only a redirected frame can be too short for an IPv4 header */
	if (skb->protocol == bpf_htons(ETH_P_IP) &&
	    skb->len < sizeof(struct iphdr)) {
		record(skb, &res_short_hdr, 0);
		return TCX_PASS;
	}

	dport = udp_dport(skb, &saddr);
	switch (dport) {
	case WG_PK_PORT_A:
		record(skb, &res_a, saddr);
		record_short(skb, &res_short);
		break;
	case WG_PK_PORT_B:
		record(skb, &res_b, saddr);
		break;
	case WG_PK_PORT_A6:
		record(skb, &res_a6, saddr);
		break;
	case WG_PK_PORT_B6:
		record(skb, &res_b6, saddr);
		break;
	case WG_PK_PORT_INJECT:
		record(skb, &res_inject, saddr);
		break;
	case WG_PK_PORT_INJECT_B:
		record(skb, &res_inject_b, saddr);
		break;
	case WG_PK_PORT_NOENT:
		record(skb, &res_noent, saddr);
		break;
	case WG_PK_PORT_MIRRED:
		record(skb, &res_mirred, saddr);
		break;
	case WG_PK_PORT_SPOOF:
		record(skb, &res_spoof, saddr);
		break;
	}
	return TCX_PASS;
}

SEC("tc/egress")
int wg_egress(struct __sk_buff *skb)
{
	__u32 saddr = 0;

	if (udp_dport(skb, &saddr) == WG_PK_PORT_EGRESS)
		record(skb, &res_egress, saddr);
	return TCX_PASS;
}

SEC("tc/ingress")
int veth_ingress(struct __sk_buff *skb)
{
	__u32 saddr = 0;
	int dport;

	if (skb->protocol == bpf_htons(ETH_P_IP) &&
	    skb->len < sizeof(struct ethhdr) + sizeof(struct iphdr))
		return bpf_redirect(wg_ifindex, BPF_F_INGRESS);

	dport = udp_dport(skb, &saddr);
	if (dport == WG_PK_PORT_VETH)
		record(skb, &res_veth, saddr);
	else if (dport == WG_PK_PORT_INJECT || dport == WG_PK_PORT_INJECT_B ||
		 dport == WG_PK_PORT_NOENT)
		return bpf_redirect(wg_ifindex, BPF_F_INGRESS);
	return TCX_PASS;
}

SEC("tc")
int wg_test_run(struct __sk_buff *skb)
{
	record(skb, &res_test_run, 0);
	return TCX_PASS;
}

char _license[] SEC("license") = "GPL";
