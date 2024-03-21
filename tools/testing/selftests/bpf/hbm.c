#include "test_progs.h"
#include "hbm_edt_kern.skel.h"

#define BPFFS "/sys/fs/bpf/kafai"
#define CGRPFS "/sys/fs/cgroup"

void test__fail()
{

}

static int pin_maps(struct hbm_edt_kern *skel, int taskid)
{
	char path[128];
	int err;

	snprintf(path, sizeof(path), BPFFS "/%d/queue_stats", taskid);
	unlink(path);
	err = bpf_map__pin(skel->maps.queue_stats, path);
	if (!ASSERT_OK(err, "bpf_map__pin(queue_stats)"))
		return -1;

	snprintf(path, sizeof(path), BPFFS "/%d/queue_state", taskid);
	unlink(path);
	err = bpf_map__pin(skel->maps.queue_state, path);
	if (!ASSERT_OK(err, "bpf_map__pin(queue_state)"))
		return -1;

	snprintf(path, sizeof(path), BPFFS "/%d/rodata", taskid);
	unlink(path);
	err = bpf_map__pin(skel->maps.rodata, path);
	if (!ASSERT_OK(err, "bpf_map__pin(rodata)"))
		return -1;

	return 0;
}

int main(int argc, char **argv)
{
	struct hbm_edt_kern *skel = NULL;
	int err, taskid, cgrp_fd = -1;
	struct bpf_link *link = NULL;
	const char *tw_cgrp_path;
	struct bpf_program *prog;
	uint64_t mark_tenth_pct;
	char cgrp_path[1024];
	char link_path[128];

	if (argc != 11) {
		printf("./hbm host_ip tw_cgrp_path svc_ip taskid prog rate_mbps burst_ns mark_ns mark_tenth_pct drop_ns\n");
		return -1;
	}

	skel = hbm_edt_kern__open();
	if (!ASSERT_OK_PTR(skel, "hbm_edt_kern__open"))
		goto done;

	err = inet_pton(AF_INET6, argv[1], &skel->rodata->host_addr);
	if (!ASSERT_EQ(err, 1, "inet_pton(host_addr)"))
		goto done;

	tw_cgrp_path = argv[2];

	err = inet_pton(AF_INET6, argv[3], &skel->rodata->svc_addr);
	if (!ASSERT_EQ(err, 1, "inet_pton(host_addr)"))
		goto done;

	err = inet_pton(AF_INET6, "::1", &skel->rodata->lo_addr);
	if (!ASSERT_EQ(err, 1, "inet_pton(host_addr)"))
		goto done;

	taskid = atoi(argv[4]);
	snprintf(link_path, sizeof(link_path), BPFFS "/%d/cgroup_link", taskid);

	skel->rodata->rate_bps = strtoull(argv[6], NULL, 10) * 1000 * 1000 ? : UINT64_MAX;
	skel->rodata->burst_ns = strtoull(argv[7], NULL, 10) ? : UINT64_MAX;
	skel->rodata->mark_ns = strtoull(argv[8], NULL, 10) ? : UINT64_MAX;
	mark_tenth_pct = strtoull(argv[9], NULL, 10);
	if (!ASSERT_LT(mark_tenth_pct, 1000, "mark_tenth_pct"))
		goto done;
	skel->rodata->mark_rand = (UINT_MAX / 1000) * (1000 - mark_tenth_pct);
	skel->rodata->drop_ns = strtoull(argv[10], NULL, 10) ? : UINT64_MAX;

	printf("rate_bps %lu burst_ns %lu mark_ns %lu drop_ns %lu\n",
	       skel->rodata->rate_bps, skel->rodata->burst_ns,
	       skel->rodata->mark_ns, skel->rodata->drop_ns);

	err = hbm_edt_kern__load(skel);
	if (!ASSERT_OK(err, "hbm_edt_kern__load"))
		goto done;

	if (!strcmp(argv[5], "edt"))
		prog = skel->progs.hbm_edt;
	else
		prog = skel->progs.tw_netbw_eg;

	link = bpf_link__open(link_path);
	if (link) {
		err = bpf_link__update_program(link, prog);
		ASSERT_OK(err, "bpf_link__update_program");
	} else {
		snprintf(cgrp_path, sizeof(cgrp_path), CGRPFS "%s", tw_cgrp_path);
		cgrp_fd = open(cgrp_path, O_RDONLY);
		if (!ASSERT_GE(cgrp_fd, 0, "open(cgroup)"))
			goto done;
		link = bpf_program__attach_cgroup(prog, cgrp_fd);
		if (!ASSERT_OK_PTR(link, "bpf_program__attach_cgroup"))
			goto done;
		err = bpf_link__pin(link, link_path);
		if (!ASSERT_OK(err, "bpf_link__pin"))
			goto done;
	}
	err = pin_maps(skel, taskid);
	if (err)
		goto done;
	bpf_link__disconnect(link);

done:
	bpf_link__destroy(link);
	hbm_edt_kern__destroy(skel);
	if (cgrp_fd != -1)
		close(cgrp_fd);
	return 0;
}
