// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_misc.h"
#include "bpf_kfuncs.h"
#include "crypto_common.h"

unsigned char key[256] __attribute__((aligned(8))) = {};
char algo[128] __attribute__((aligned(8))) = "ecb(aes)";
static struct bpf_crypto_params params;
u16 udp_port = 7777;
int status = 1, hits;
u8 buf[16];

SEC("syscall")
int unclone_setup(void *ctx)
{
	struct bpf_crypto_ctx *cctx;
	int err;

	__builtin_memcpy(&params.type, "skcipher", sizeof("skcipher"));
	params.key_len = 16;
	__builtin_memcpy(&params.algo, algo, sizeof(algo));
	__builtin_memcpy(&params.key, key, sizeof(key));
	cctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!cctx) {
		status = err;
		return 0;
	}
	err = crypto_ctx_insert(cctx);
	status = err == -EEXIST ? 0 : err;
	return 0;
}

static __always_inline struct bpf_crypto_ctx *match(struct __sk_buff *skb)
{
	struct __crypto_ctx_value *v;
	struct udphdr udph;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return NULL;
	if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr), &udph, sizeof(udph)))
		return NULL;
	if (udph.dest != bpf_htons(udp_port))
		return NULL;
	v = crypto_ctx_value_lookup();
	return v ? v->ctx : NULL;
}

#define PAYLOAD_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))

/* ECB in place, the only write to the packet. */
SEC("tc")
int unclone_crypt(struct __sk_buff *skb)
{
	struct bpf_crypto_ctx *ctx = match(skb);
	struct bpf_dynptr pkt;

	if (!ctx)
		return TC_ACT_OK;
	bpf_dynptr_from_skb(skb, 0, &pkt);
	if (bpf_dynptr_adjust(&pkt, PAYLOAD_OFF, PAYLOAD_OFF + 16))
		return TC_ACT_OK;
	status = bpf_crypto_encrypt(ctx, &pkt, &pkt, NULL);
	hits++;
	return TC_ACT_OK;
}

/* Control: the same ciphertext, written back with bpf_dynptr_write(). */
SEC("tc")
int unclone_write(struct __sk_buff *skb)
{
	struct bpf_crypto_ctx *ctx = match(skb);
	struct bpf_dynptr pkt, src, dst;

	if (!ctx)
		return TC_ACT_OK;
	bpf_dynptr_from_skb(skb, 0, &pkt);
	bpf_dynptr_clone(&pkt, &src);
	if (bpf_dynptr_adjust(&src, PAYLOAD_OFF, PAYLOAD_OFF + 16))
		return TC_ACT_OK;
	bpf_dynptr_from_mem(buf, sizeof(buf), 0, &dst);
	status = bpf_crypto_encrypt(ctx, &src, &dst, NULL);
	if (!status)
		status = bpf_dynptr_write(&pkt, PAYLOAD_OFF, buf, sizeof(buf), 0);
	hits++;
	return TC_ACT_OK;
}

/* CBC in place with the IV in memory. */
SEC("tc")
int unclone_local_iv(struct __sk_buff *skb)
{
	struct bpf_crypto_ctx *ctx = match(skb);
	struct bpf_dynptr pkt, iv;

	if (!ctx)
		return TC_ACT_OK;
	bpf_dynptr_from_skb(skb, 0, &pkt);
	if (bpf_dynptr_adjust(&pkt, PAYLOAD_OFF, PAYLOAD_OFF + 16))
		return TC_ACT_OK;
	bpf_dynptr_from_mem(buf, sizeof(buf), 0, &iv);
	status = bpf_crypto_encrypt(ctx, &pkt, &pkt, &iv);
	hits++;
	return TC_ACT_OK;
}

/* CBC with the IV in the packet, output in memory: only the IV is written. */
SEC("tc")
int unclone_iv(struct __sk_buff *skb)
{
	struct bpf_crypto_ctx *ctx = match(skb);
	struct bpf_dynptr pkt, iv, dst;

	if (!ctx)
		return TC_ACT_OK;
	bpf_dynptr_from_skb(skb, 0, &pkt);
	bpf_dynptr_clone(&pkt, &iv);
	if (bpf_dynptr_adjust(&iv, PAYLOAD_OFF, PAYLOAD_OFF + 16))
		return TC_ACT_OK;
	bpf_dynptr_from_mem(buf, sizeof(buf), 0, &dst);
	status = bpf_crypto_encrypt(ctx, &iv, &dst, &iv);
	hits++;
	return TC_ACT_OK;
}

/* ECB in place, then read through a packet pointer taken before the call. */
SEC("tc")
int unclone_pkt_ptr(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct bpf_crypto_ctx *ctx = match(skb);
	struct ethhdr *eth = data;
	struct bpf_dynptr pkt;

	if (!ctx || (void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	bpf_dynptr_from_skb(skb, 0, &pkt);
	if (bpf_dynptr_adjust(&pkt, PAYLOAD_OFF, PAYLOAD_OFF + 16))
		return TC_ACT_OK;
	status = bpf_crypto_encrypt(ctx, &pkt, &pkt, NULL);
	if (!status && eth->h_proto != bpf_htons(ETH_P_IP))
		status = -EPROTO;
	hits++;
	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
