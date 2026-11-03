// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Avinash Duduskar. All Rights Reserved.
 */

#include "device.h"
#include "peer.h"
#include "allowedips.h"
#include "noise.h"

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <net/sch_generic.h>

/*
 * The lookup reads the source address without a length check. wg pulls the
 * header of packets it decrypts, but not of packets another program
 * redirects onto the device's ingress.
 */
static bool wg_inner_src_in_linear(const struct sk_buff *skb)
{
	int nhoff = skb_network_offset(skb);
	unsigned int len;

	if (skb->protocol == htons(ETH_P_IP))
		len = sizeof(struct iphdr);
	else if (skb->protocol == htons(ETH_P_IPV6))
		len = sizeof(struct ipv6hdr);
	else
		return false;

	return nhoff >= 0 && nhoff + len <= skb_headlen(skb);
}

__bpf_kfunc_start_defs();

/**
 * bpf_skb_wg_rx_peer_key - public key of the peer owning a packet's source
 * @skb_ctx: skb seen by a TC ingress program on a WireGuard interface
 * @key: buffer that receives the peer's static public key
 * @key__sz: size of @key, must be NOISE_PUBLIC_KEY_LEN (32)
 *
 * Look up the packet's source address in the device's allowed-ips table and
 * copy the static public key of the peer that owns it into @key.
 *
 * The result is the owner of the source address the packet carries when the
 * kfunc is called. For a packet WireGuard decrypted and delivered, that is
 * the peer that decrypted it, unless something changed the answer in
 * between: a packet redirected onto the device's ingress by another program
 * (bpf_redirect() with BPF_F_INGRESS, act_mirred) gets the owner of whatever
 * source it carries; a generic XDP program, or an earlier tc program or
 * action, that rewrites the source changes the result the same way; and if
 * allowed-ips change between decryption and the TC hook (while the packet
 * waits in GRO, a receive batch or an RPS backlog), the lookup uses the
 * table as it is at the time of the call and may return another peer or
 * fail.
 *
 * On error, @key is zeroed.
 *
 * Return:
 * * 0		- @key holds the owning peer's public key
 * * -EINVAL	- @key__sz is not NOISE_PUBLIC_KEY_LEN, or the IPv4/IPv6
 *		  header is not in the linear area
 * * -EOPNOTSUPP	- not called at TC ingress of a WireGuard interface
 * * -ENOENT	- no peer owns the source address
 */
__bpf_kfunc int bpf_skb_wg_rx_peer_key(struct __sk_buff *skb_ctx, u8 *key,
				       u32 key__sz)
{
	struct sk_buff *skb = (struct sk_buff *)skb_ctx;
	struct net_device *dev = skb->dev;
	struct wg_device *wg;
	struct wg_peer *peer;
	int ret;

	if (key__sz != NOISE_PUBLIC_KEY_LEN) {
		ret = -EINVAL;
		goto err;
	}
	if (!dev || !wg_is_wireguard_device(dev) || !skb_at_tc_ingress(skb)) {
		ret = -EOPNOTSUPP;
		goto err;
	}
	if (!wg_inner_src_in_linear(skb)) {
		ret = -EINVAL;
		goto err;
	}

	wg = netdev_priv(dev);
	peer = wg_allowedips_lookup_src(&wg->peer_allowedips, skb);
	if (!peer) {
		ret = -ENOENT;
		goto err;
	}

	/* remote_static never changes, so the peer reference is enough */
	memcpy(key, peer->handshake.remote_static, NOISE_PUBLIC_KEY_LEN);
	wg_peer_put(peer);
	return 0;

err:
	/* The verifier treats @key as written whatever the result */
	memset(key, 0, key__sz);
	return ret;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(wg_kfunc_ids)
BTF_ID_FLAGS(func, bpf_skb_wg_rx_peer_key)
BTF_KFUNCS_END(wg_kfunc_ids)

static const struct btf_kfunc_id_set wg_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &wg_kfunc_ids,
};

int __init wg_bpf_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					 &wg_kfunc_set);
}
