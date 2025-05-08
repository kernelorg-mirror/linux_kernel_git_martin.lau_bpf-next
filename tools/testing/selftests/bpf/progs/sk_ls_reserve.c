// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct counters_x {
	u32 a;
	u32 b;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RESERVE_LOCAL_STORAGE);
	__type(key, int);
	__type(value, struct counters_x);
} reserve_x SEC(".maps");


int level;
int optname;

SEC("cgroup/getsockopt")
int getsockopt(struct bpf_sockopt *ctx)
{
	struct bpf_sock *sk;
	struct counters_x *x;

	if (ctx->level != level || ctx->optname != optname) {
		bpf_printk("%s:%d", __func__, __LINE__);
		return 1;
	}

	sk = ctx->sk;
	x = bpf_sk_storage_get(&reserve_x, sk, 0, 0);
	if (!x)
		return 0;

	x->a += 1;
	x->b += 1;

	ctx->retval = 0;
	return 1;
}

char _license[] SEC("license") = "GPL";
