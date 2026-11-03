// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

extern int bpf_skb_wg_rx_peer_key(struct __sk_buff *skb, __u8 *key,
				  __u32 key__sz) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__uint(value_size, 32);
	__uint(map_flags, BPF_F_RDONLY_PROG);
} ro_map SEC(".maps");

SEC("tc")
__failure __msg("invalid read from stack")
int wg_key_buffer_too_small(struct __sk_buff *skb)
{
	__u8 key[16] = {};

	return bpf_skb_wg_rx_peer_key(skb, key, 32);
}

SEC("tc")
__failure __msg("write into map forbidden")
int wg_key_rdonly_map(struct __sk_buff *skb)
{
	__u32 idx = 0;
	__u8 *key;

	key = bpf_map_lookup_elem(&ro_map, &idx);
	if (!key)
		return 0;
	return bpf_skb_wg_rx_peer_key(skb, key, 32);
}

SEC("xdp")
__failure __msg("calling kernel function bpf_skb_wg_rx_peer_key is not allowed")
int wg_key_from_xdp(struct xdp_md *ctx)
{
	__u8 key[32] = {};

	return bpf_skb_wg_rx_peer_key((struct __sk_buff *)ctx, key,
				      sizeof(key));
}

char _license[] SEC("license") = "GPL";
