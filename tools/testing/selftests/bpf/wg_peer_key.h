/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __WG_PEER_KEY_H
#define __WG_PEER_KEY_H

#define WG_PK_KEY_LEN		32

#define WG_PK_PORT_A		7001
#define WG_PK_PORT_B		7002
#define WG_PK_PORT_EGRESS	7003
#define WG_PK_PORT_VETH		7004
#define WG_PK_PORT_INJECT	7005
#define WG_PK_PORT_NOENT	7006
#define WG_PK_PORT_A6		7007
#define WG_PK_PORT_B6		7008
#define WG_PK_PORT_INJECT_B	7009
#define WG_PK_PORT_MIRRED	7010
#define WG_PK_PORT_SPOOF	7011

struct wg_result {
	int ret;
	__u32 hits;
	__u32 saddr;
	__u8 key[WG_PK_KEY_LEN];
};

struct wg_short_result {
	int ret;
	__u32 hits;
	__u8 key[16];
};

#endif /* __WG_PEER_KEY_H */
