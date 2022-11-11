// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */
#define _GNU_SOURCE
#include <sched.h>
#include <net/if.h>
#include "test_progs.h"
#include "network_helpers.h"
#include "veth_perf.skel.h"

static int eth0_ifindex;
static int veth0_ifindex;
static int veth_eth0_ifindex;

static const char *veth_eth0_addr6_str = "2803:6080:c124:5ab::3";
static const char *veth0_addr6_str = "2803:6080:c124:5ab::2";
static const char *veth_eth0_mac = "00:22:33:44:55:66";
static const char *veth0_mac = "00:11:22:33:44:55";
static __u32 veth_eth0_addr6[4];

#define SYS(fmt, ...)						\
	({							\
		char cmd[1024];					\
		snprintf(cmd, sizeof(cmd), fmt, ##__VA_ARGS__);	\
		if (!ASSERT_OK(system(cmd), cmd))		\
			goto fail;				\
	})

#define PIN_FNAME(__file) "/sys/fs/bpf/" #__file
#define PIN(__prog) ({							\
		int err = bpf_program__pin(skel->progs.__prog, PIN_FNAME(__prog)); \
		if (!ASSERT_OK(err, "pin " #__prog))		\
			goto fail;					\
		})
#define UNPIN(__prog) ({ bpf_program__unpin(skel->progs.__prog, PIN_FNAME(__prog)); })

static int saved_netns = -1;

static int switch_netns(const char *name)
{
	char nspath[PATH_MAX];
	int err, nsfd;

	if (!ASSERT_EQ(saved_netns, -1, "saved_netns"))
		return -1;

	saved_netns = open("/proc/self/ns/net", O_RDONLY);
	if (!ASSERT_NEQ(saved_netns, -1, "open /proc/self/ns/net"))
		return -1;

	snprintf(nspath, sizeof(nspath), "%s/%s", "/var/run/netns", name);
	nsfd = open(nspath, O_RDONLY | O_CLOEXEC);
	if (!ASSERT_GE(nsfd, 0, "open netns fd")) {
		saved_netns = -1;
		return -1;
	}

	err = setns(nsfd, CLONE_NEWNET);
	if (!ASSERT_OK(err, "setns")) {
		saved_netns = -1;
		return -1;
	}

	return 0;
}

static int restore_netns(void)
{
	int err;

	if (!ASSERT_NEQ(saved_netns, -1, "saved_netns"))
		return -1;

	err = setns(saved_netns, CLONE_NEWNET);
	if (!ASSERT_OK(err, "setns_by_fd"))
		return -1;

	saved_netns = -1;
	return 0;
}

static int setup_veth(void)
{
	SYS("ip link add veth0 type veth peer name veth_eth0");

	eth0_ifindex = if_nametoindex("eth0");
	if (!ASSERT_NEQ(eth0_ifindex, 0, "eth0_ifindex"))
		goto fail;

	veth0_ifindex = if_nametoindex("veth0");
	if (!ASSERT_NEQ(veth0_ifindex, 0, "veth0_ifindex"))
		goto fail;

	veth_eth0_ifindex = if_nametoindex("veth_eth0");
	if (!ASSERT_NEQ(veth_eth0_ifindex, 0, "veth_eth0_ifindex"))
		goto fail;

	SYS("ip link set veth0 address %s", veth0_mac);
	SYS("ip -6 addr add %s/64 dev veth0 nodad", veth0_addr6_str);
	SYS("ip link set dev veth0 up");

	SYS("ip netns add ns_test");
	SYS("ip link set dev veth_eth0 netns  ns_test");

	switch_netns("ns_test");
	SYS("ip link set veth_eth0 address %s", veth_eth0_mac);
	SYS("ip -6 addr add %s/64 dev veth_eth0 nodad", veth_eth0_addr6_str);
	SYS("ip -6 neigh add %s dev veth_eth0 lladdr %s", veth0_addr6_str,
	    veth0_mac);
	SYS("ip link set dev veth_eth0 up");
	SYS("ip -6 route add default via %s dev veth_eth0", veth0_addr6_str);
	restore_netns();

	system("tc qdisc add dev eth0 clsact >& /dev/null");
	SYS("tc filter add dev eth0 ingress prio 10 bpf da object-pinned "
	    PIN_FNAME(eth0_ingress));

	SYS("tc qdisc add dev veth0 clsact");
	SYS("tc filter add dev veth0 ingress prio 10 bpf da object-pinned "
	    PIN_FNAME(veth0_ingress));

	return 0;
fail:
	system("ip netns del ns_test >& /dev/null");
	system("ip link del veth0 >& /dev/null");
	system("tc filter del ingress dev eth0 prio 10 >& /dev/null");
	return -1;
}

void test_veth_perf(void)
{
	struct veth_perf *skel;
	const char *addr6_str;
	int err;
	char c;

	addr6_str = getenv("VETH_ETH0_ADDR6");
	if (addr6_str)
		veth_eth0_addr6_str = addr6_str;

	addr6_str = getenv("VETH0_ADDR6");
	if (addr6_str)
		veth0_addr6_str = addr6_str;

	err = inet_pton(AF_INET6, veth_eth0_addr6_str, veth_eth0_addr6);
	if (!ASSERT_EQ(err, 1, "inet_pton"))
		return;

	skel = veth_perf__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;
	PIN(eth0_ingress);
	PIN(veth0_ingress);

	if (!ASSERT_OK(setup_veth(), "setup_veth"))
		goto fail;

	memcpy(skel->bss->veth_eth0_addr6, veth_eth0_addr6,
	       sizeof(veth_eth0_addr6));
	skel->bss->eth0 = eth0_ifindex;
	skel->bss->veth0 = veth0_ifindex;

	printf("Press any key to cleanup: ");
	scanf("%c", &c);

	system("ip netns del ns_test");
	system("ip link del veth0");
	system("tc filter del ingress dev eth0 pref 10");

fail:
	UNPIN(eth0_ingress);
	UNPIN(veth0_ingress);
	veth_perf__destroy(skel);
}
