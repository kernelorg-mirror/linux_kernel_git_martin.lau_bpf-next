// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include "sk_ls_reserve.skel.h"

int cgroup_fd;

/* FIXME: offload find_reserve to libbpf? */
static int find_reserve(const struct bpf_map *map)
{
	const char *name = bpf_map__name(map);
	struct bpf_map_info info = {};
	__u32 id = 0, len = sizeof(info);
	int fd, err;

	while (!bpf_map_get_next_id(id, &id)) {
		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0) {
			if (!ASSERT_EQ(errno, ENOENT, "errno"))
				return -1;
			continue;
		}

		err = bpf_map_get_info_by_fd(fd, &info, &len);
		if (!ASSERT_OK(err, "bpf_map_get_info_by_fd")) {
			close(fd);
			return -1;
		}

		if (!strcmp(info.name, name))
			return fd;
		close(fd);
	}

	return -1;
}

static void test_reserve(void)
{
	int err, val, reserve_x_fd, fd = -1;
	struct sk_ls_reserve *skel;
	int level, optname;
	__u32 len;

	skel = sk_ls_reserve__open();
	if (!ASSERT_OK_PTR(skel, "sk_ls_reserve__open"))
		return;

	skel->bss->level = level = 0xdeadbeef;
	skel->bss->optname = optname = 0xdeadbeef;

	reserve_x_fd = find_reserve(skel->maps.reserve_x);
	if (reserve_x_fd != -1) {
		err = bpf_map__reuse_fd(skel->maps.reserve_x, reserve_x_fd);
		close(reserve_x_fd);
		if (!ASSERT_OK(err, "bpf_map__reuse_fd"))
			goto done;
	}

	err = sk_ls_reserve__load(skel);
	if (!ASSERT_OK(err, "sk_ls_reserve__load"))
		goto done;

	skel->links.getsockopt = bpf_program__attach_cgroup(skel->progs.getsockopt,
							    cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.getsockopt, "attach_cgroup"))
		goto done;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(fd, "socket"))
		goto done;

	len = sizeof(val);
	err = getsockopt(fd, level, optname, &val, &len);
	if (!ASSERT_OK(err, "getsockopt"))
		goto done;

done:
	if (fd != -1)
		close(fd);
	sk_ls_reserve__destroy(skel);
}

void test_ns_sk_ls_reserve(void)
{
	cgroup_fd = test__join_cgroup("/sk_ls_reserve");
	if (!ASSERT_OK_FD(cgroup_fd, "test__join_cgroup"))
		return;

	test_reserve();

	close(cgroup_fd);
}
