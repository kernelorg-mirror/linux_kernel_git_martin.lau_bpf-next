// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */
#include <stddef.h>
#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/stddef.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ctx_ptr
# define ctx_ptr(field)		(void *)(long)(field)
#endif

__u32 veth_eth0_addr6[4] = {};
int veth0 = 0;
int eth0 = 0;

static bool v6_equal(__u32 *a, __u32 *b)
{
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

SEC("tc")
int veth0_ingress(struct __sk_buff *skb)
{
	void *data_end = ctx_ptr(skb->data_end);
	void *data = ctx_ptr(skb->data);
	struct ipv6hdr *ip6h;

	if (skb->protocol != __bpf_constant_htons(ETH_P_IPV6))
		return TC_ACT_OK;

	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;

	ip6h = (struct ipv6hdr *)(data + sizeof(struct ethhdr));
	if ((void *)(ip6h + 1) > data_end)
		return TC_ACT_SHOT;

	return bpf_redirect_neigh(eth0, NULL, 0, 0);
}

SEC("tc")
int eth0_ingress(struct __sk_buff *skb)
{
	void *data_end = ctx_ptr(skb->data_end);
	void *data = ctx_ptr(skb->data);
	struct ipv6hdr *ip6h;

	if (skb->protocol != __bpf_constant_htons(ETH_P_IPV6))
		return TC_ACT_UNSPEC;

	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_UNSPEC;

	ip6h = (struct ipv6hdr *)(data + sizeof(struct ethhdr));
	if ((void *)(ip6h + 1) > data_end)
		return TC_ACT_UNSPEC;

	if (!v6_equal(ip6h->daddr.s6_addr32, veth_eth0_addr6))
		return TC_ACT_UNSPEC;

	if (!veth0)
		return TC_ACT_UNSPEC;

	return bpf_redirect_peer(veth0, 0);
}
