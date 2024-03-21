/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (c) 2019 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * Include file for sample Host Bandwidth Manager (HBM) BPF programs
 */
#define KBUILD_MODNAME "foo"
#define iphdr iphdr_unused
#define ipv6hdr ipv6hdr_unused
#define tcphdr tcphdr_unused
#include "vmlinux.h"
#undef tcphdr
#undef ipv6hdr
#undef iphdr
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tracing_net.h"

#define DROP		(0U)
#define ALLOW		(1U << 0)
#define CWR		(1U << 1)
#define DROP_CWR	(DROP | CWR)
#define ALLOW_CWR	(ALLOW | CWR)
#define TCP_ECN_OK	1

#ifndef HBM_DEBUG  // Define HBM_DEBUG to enable debugging
#undef bpf_printk
#define bpf_printk(fmt, ...)
#endif

#define INITIAL_CREDIT_PACKETS	100
#define MAX_BYTES_PER_PACKET	1500
#define MARK_THRESH		(40 * MAX_BYTES_PER_PACKET)
#define DROP_THRESH		(80 * 5 * MAX_BYTES_PER_PACKET)
#define LARGE_PKT_DROP_THRESH	(DROP_THRESH - (15 * MAX_BYTES_PER_PACKET))
#define MARK_REGION_SIZE	(LARGE_PKT_DROP_THRESH - MARK_THRESH)
#define LARGE_PKT_THRESH	120
#define MAX_CREDIT		(100 * MAX_BYTES_PER_PACKET)
#define INIT_CREDIT		(INITIAL_CREDIT_PACKETS * MAX_BYTES_PER_PACKET)

#define MSEC_PER_SEC  1000UL
#define NSEC_PER_USEC 1000UL
#define NSEC_PER_MSEC 1000000UL
#define NSEC_PER_SEC  1000000000UL

#define BYTES_TO_BITS(bytes) (((u64)bytes) << 3)
#define BYTES_TO_NS(bytes) (BYTES_TO_BITS(bytes) * NSEC_PER_SEC / rate_bps);

// Reserve 20us of queuing for small packets (less than 120 bytes)
#define LARGE_PKT_DROP_THRESH_NS (DROP_THRESH_NS - 20000)
#define MARK_REGION_SIZE_NS	(LARGE_PKT_DROP_THRESH_NS - MARK_THRESH_NS)

struct hbm_vqueue {
	struct bpf_spin_lock lock;
	/* 4 byte hole */
	__u64 lasttime;		/* In ns */
	__u64 now;
	int credit;		/* In bytes */
	__u32 rate;		/* In bytes per NS << 20 */
};

struct hbm_queue_stats {
	__u64 avg_Mbps;
	__u64 avg_pkt_sz;
	__u64 avg_delay_ns;
	__u64 avg_skb_delay_ns;
	__u64 burst_Mbps;
	__u64 max_burst_Mbps;
	__u64 max_pkt_sz;
	__u64 avg_cwnd;
	__u64 avg_rtt;

	__u64 delayed_pct;
	__u64 ecn_pct;
	__u64 ecn_err_pct;
	__u64 nodelay_pct;

	__u64 max_burst_port;
	__u64 max_pkt_sz_port;

	__u64 avg_tstamp;
	__u64 burst_tstamp;

	__u64 burst_bytes;
	__u64 burst_pkts;

	__s64 delta;

	__u64 bytes;
	__u64 pkts;

	__u64 delay_ns;
	__u64 pkts_delayed;
	__u64 skb_delay_ns;
	__u64 pkts_skb_delayed;
	__u64 pkts_nodelay;

	__u64 pkts_dropped;
	__u64 pkts_ecn;
	__u64 pkts_ecn_err;

	__u64 total_delay_ns;
	__u64 total_delay_pkts;
	__u64 total_skb_delay_pkts;
	__u64 total_pkts;
	__u64 total_ecn;

	__u64 cwnd;
	__u64 rtt;

	__u64 cg_ret[4];
};

static __always_inline __u64 div64_u64(__u64 dividend, __u64 divisor)
{
	return dividend / divisor;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct hbm_vqueue);
} queue_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct hbm_queue_stats);
} queue_stats SEC(".maps");

#define __struct_group(TAG, NAME, ATTRS, MEMBERS...) \
	union { \
		struct { MEMBERS } ATTRS; \
		struct TAG { MEMBERS } ATTRS NAME; \
	}

#define __LITTLE_ENDIAN_BITFIELD
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__struct_group(/* no tag */, addrs, /* no attrs */,
		__be32	saddr;
		__be32	daddr;
	);
	/*The options start here. */
};

struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8			priority:4,
				version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8			version:4,
				priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8			flow_lbl[3];

	__be16			payload_len;
	__u8			nexthdr;
	__u8			hop_limit;

	__struct_group(/* no tag */, addrs, /* no attrs */,
		struct	in6_addr	saddr;
		struct	in6_addr	daddr;
	);
};

struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};
#undef __LITTLE_ENDIAN_BITFIELD

struct hbm_pkt_info {
	int	cwnd;
	int	rtt;
	int	packets_out;
	union {
		struct iphdr iph;
		struct ipv6hdr ip6h;
	};
	short	ecn;
	u16	ip_protocol;
	bool	tcp_ack;
};
