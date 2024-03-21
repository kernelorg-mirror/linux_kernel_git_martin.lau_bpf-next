#include "hbm_kern.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define U32_MAX		4294967295U
#define U64_MAX		18446744073709551615ULL

volatile const struct in6_addr svc_addr;
volatile const struct in6_addr host_addr;
volatile const struct in6_addr lo_addr;

volatile const s64 burst_ns = 10 * NSEC_PER_MSEC;	/* 10ms  */
volatile const u64 mark_ns = 100 * NSEC_PER_MSEC;	/* 100ms */
volatile const u64 drop_ns = 2 * NSEC_PER_SEC;		/* 2s  */
volatile const u64 rate_bps = 12500UL * 1000 * 1000;
volatile const u32 mark_rand = (U32_MAX / 100) * 99;	/* 1% ECN */

#define v6_equal(a, b)		(a.s6_addr32[0] == b.s6_addr32[0] && \
				 a.s6_addr32[1] == b.s6_addr32[1] && \
				 a.s6_addr32[2] == b.s6_addr32[2] && \
				 a.s6_addr32[3] == b.s6_addr32[3])

static int get_tcp_info(struct __sk_buff *skb, struct hbm_pkt_info *pkti)
{
	struct bpf_sock *sk;
	struct bpf_tcp_sock *tp;

	sk = skb->sk;
	if (sk) {
		sk = bpf_sk_fullsock(sk);
		if (sk) {
			if (sk->protocol == IPPROTO_TCP) {
				tp = bpf_tcp_sock(sk);
				if (tp) {
					pkti->cwnd = tp->snd_cwnd;
					pkti->rtt = tp->srtt_us >> 3;
					pkti->packets_out = tp->packets_out;
					return 0;
				}
			}
		}
	}
	pkti->cwnd = 0;
	pkti->rtt = 0;
	pkti->packets_out = 0;
	return 1;
}

static void hbm_get_pkt_info(struct __sk_buff *skb,
			     struct hbm_pkt_info *pkti)
{
	struct iphdr *iph = &pkti->iph;
	struct ipv6hdr *ip6h = &pkti->ip6h;
	struct tcphdr th;
	__u32 ip_len;

	if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		bpf_skb_load_bytes(skb, 0, ip6h, sizeof(*ip6h));
		pkti->ip_protocol = ip6h->nexthdr;
		pkti->ecn = (ip6h->flow_lbl[0] >> 4) & INET_ECN_MASK;
		ip_len = sizeof(*ip6h);
	} else if (skb->protocol == bpf_htons(ETH_P_IP)) {
		bpf_skb_load_bytes(skb, 0, iph, sizeof(*iph));
		pkti->ip_protocol = iph->protocol;
		pkti->ecn = iph->tos & INET_ECN_MASK;
		ip_len = sizeof(*iph);
	}
	if (pkti->ip_protocol == IPPROTO_TCP) {
		bpf_skb_load_bytes(skb, ip_len, &th, sizeof(th));
		if (skb->len <= ip_len + th.doff * 4)
			pkti->tcp_ack = true;
		get_tcp_info(skb, pkti);
	}
}

static __always_inline void hbm_update_stats(struct hbm_queue_stats *qsp, struct __sk_buff *skb,
					     int local_port,
					     u64 now, u64 added_delay, u64 skb_delay,
					     int ret, struct hbm_pkt_info *pkti)
{
	qsp->burst_bytes += skb->len;
	qsp->bytes += skb->len;
	qsp->pkts += 1;
	qsp->total_pkts += 1;

	if (!qsp->avg_tstamp) {
		qsp->avg_tstamp = now;
	} else if (now > qsp->avg_tstamp && now - qsp->avg_tstamp > 10 * NSEC_PER_SEC) {
		qsp->avg_pkt_sz = qsp->bytes / qsp->pkts;
		/* devide by ns => Gbps. (* 1000) to get Mbps. */
		qsp->avg_Mbps = BYTES_TO_BITS(qsp->bytes) * 1000 / (now - qsp->avg_tstamp);
		qsp->avg_delay_ns = qsp->delay_ns / qsp->pkts_delayed;
		qsp->avg_skb_delay_ns = qsp->skb_delay_ns / qsp->pkts_skb_delayed;
		qsp->avg_cwnd = qsp->cwnd / qsp->pkts;
		qsp->avg_rtt = qsp->rtt / qsp->pkts;

		qsp->delayed_pct = qsp->pkts_delayed * 100 / qsp->pkts;
		qsp->ecn_pct = qsp->pkts_ecn * 100 / qsp->pkts;
		qsp->ecn_err_pct = qsp->pkts_ecn_err * 100 / qsp->pkts;

		qsp->pkts = 0;
		qsp->bytes = 0;

		qsp->max_burst_Mbps = 0;
		qsp->max_burst_port = 0;

		qsp->max_pkt_sz = 0;
		qsp->max_pkt_sz_port = 0;

		qsp->delay_ns = 0;
		qsp->skb_delay_ns = 0;
		qsp->pkts_delayed = 0;
		qsp->pkts_skb_delayed = 0;
		qsp->pkts_nodelay = 0;
		qsp->pkts_ecn = 0;
		qsp->pkts_ecn_err = 0;
		qsp->pkts_dropped = 0;

		qsp->cwnd = 0;
		qsp->rtt = 0;

		qsp->cg_ret[0] = qsp->cg_ret[1] = qsp->cg_ret[2] = qsp->cg_ret[3] = 0;

		qsp->avg_tstamp = now;
	}

	if (skb->len > qsp->max_pkt_sz) {
		qsp->max_pkt_sz = skb->len;
		qsp->max_pkt_sz_port = local_port;
	}

	if (now > qsp->burst_tstamp && now - qsp->burst_tstamp > NSEC_PER_MSEC) {
		qsp->burst_Mbps = BYTES_TO_BITS(qsp->burst_bytes) * 1000 / (now - qsp->burst_tstamp);
		qsp->burst_bytes = 0;
		qsp->burst_tstamp = now;
		if (qsp->burst_Mbps > qsp->max_burst_Mbps) {
			qsp->max_burst_Mbps = qsp->burst_Mbps;
			qsp->max_burst_port = local_port;
		}
	}

	if (added_delay) {
		qsp->total_delay_ns += added_delay;
		qsp->total_delay_pkts += 1;
		qsp->delay_ns += added_delay;
		qsp->pkts_delayed += 1;
	} else {
		qsp->pkts_nodelay += 1;
	}

	if (skb_delay) {
		qsp->skb_delay_ns += skb_delay;
		qsp->pkts_skb_delayed += 1;
		qsp->total_skb_delay_pkts += 1;
	}

	if (ret == DROP || ret == DROP_CWR)
		qsp->pkts_dropped += 1;

	qsp->cwnd += pkti->cwnd;
	qsp->rtt += pkti->rtt;

	if (ret <= 4)
		qsp->cg_ret[ret] += 1;
}


SEC("cgroup_skb/egress")
int hbm_edt(struct __sk_buff *skb)
{
	s64 added_delay = 0, delta = 0, delay_ns;
	u64 now, send_tstamp, skb_tstamp;
	struct hbm_queue_stats *qsp;
	unsigned int zero = 0;
	struct hbm_pkt_info pkti = {};
	struct hbm_vqueue *qdp;
	int len = skb->len;
	int ret = ALLOW;
	struct sock *sk = (void *)skb->sk;
	int local_port;

	if (!sk)
		return ALLOW;

	sk = bpf_rdonly_cast(sk, bpf_core_type_id_kernel(struct sock));
	local_port = sk->sk_num;

	if (skb->ifindex == 1)
		return ALLOW;

	hbm_get_pkt_info(skb, &pkti);
	if (pkti.ip_protocol != IPPROTO_TCP || pkti.tcp_ack ||
	    skb->protocol != bpf_htons(ETH_P_IPV6) ||
	    !v6_equal(pkti.ip6h.saddr, svc_addr) ||
	    v6_equal(pkti.ip6h.daddr, lo_addr) ||
	    v6_equal(pkti.ip6h.daddr, host_addr))
		return ALLOW;

	qdp = bpf_map_lookup_elem(&queue_state, &zero);
	if (!qdp)
		return ALLOW;

	now = bpf_ktime_get_ns();

	qsp = bpf_map_lookup_elem(&queue_stats, &zero);
	if (!qsp)
		return ALLOW;

	bpf_spin_lock(&qdp->lock);
	if (!qdp->lasttime)
		qdp->lasttime = now - burst_ns;

	delta = qdp->lasttime - now;
	qsp->delta = delta;
	if (delta <= -burst_ns) {
		qdp->lasttime = now - burst_ns;
		delta = -burst_ns;
	}
	send_tstamp = qdp->lasttime;
	delay_ns = BYTES_TO_NS(len);

	skb_tstamp = skb->tstamp;
	if (send_tstamp > now && send_tstamp > skb_tstamp) {
		added_delay = send_tstamp - skb_tstamp;
		skb->tstamp = send_tstamp;
	}

	if (delta > 0 && delta > drop_ns)
		ret = DROP;

	if (ret == ALLOW || ret == ALLOW_CWR)
		qdp->lasttime += delay_ns;

	hbm_update_stats(qsp, skb, local_port, now, added_delay, 0, ret, &pkti);

	bpf_spin_unlock(&qdp->lock);

	if (delta > 0 && delta > mark_ns && bpf_get_prandom_u32() > mark_rand) {
		if (bpf_skb_ecn_set_ce(skb)) {
			__sync_add_and_fetch(&qsp->pkts_ecn, 1);
			__sync_add_and_fetch(&qsp->total_ecn, 1);
		} else {
			__sync_add_and_fetch(&qsp->pkts_ecn_err, 1);
		}
	}

	return ret;
}

SEC("cgroup_skb/egress")
int tw_netbw_eg(struct __sk_buff* skb)
{
	u64 delay_ns, now, skb_tstamp, send_tstamp = 0;
	u64 added_delay = 0, skb_delay = 0;
	struct hbm_pkt_info pkti = {};
	struct hbm_queue_stats *qsp;
	struct hbm_vqueue *qdp;
	int len = skb->len;
	int ret = ALLOW;
	int zero = 0;
	struct sock *sk = (void *)skb->sk;
	int local_port;
	bool ecn = false;

	if (!sk)
		return ALLOW;

	sk = bpf_rdonly_cast(sk, bpf_core_type_id_kernel(struct sock));
	local_port = sk->sk_num;

	qdp = bpf_map_lookup_elem(&queue_state, &zero);
	if (!qdp)
		return ALLOW;

	qsp = bpf_map_lookup_elem(&queue_stats, &zero);
	if (!qsp)
		return ALLOW;

	hbm_get_pkt_info(skb, &pkti);
	if (pkti.ip_protocol != IPPROTO_TCP || pkti.tcp_ack ||
	    skb->protocol != bpf_htons(ETH_P_IPV6) ||
	    !v6_equal(pkti.ip6h.saddr, svc_addr) ||
	    v6_equal(pkti.ip6h.daddr, lo_addr) ||
	    v6_equal(pkti.ip6h.daddr, host_addr) ||
	    skb->ifindex == 1)
		return ALLOW;

	if (!qdp)
		return ALLOW;

	skb_tstamp = skb->tstamp;
	now = bpf_ktime_get_ns();
	if (skb_tstamp < now)
		skb_tstamp = now;

	bpf_spin_lock(&qdp->lock);

	delay_ns = BYTES_TO_NS(len);
	if (qdp->lasttime)
		send_tstamp = qdp->lasttime + delay_ns;
	else
		send_tstamp = now;

	if (send_tstamp <= skb_tstamp) {
		skb_delay = skb_tstamp - send_tstamp;
		/* Do take the per flow tcp pacing as
		 * an input to decide the qdp->lasttime.
		 */
		/* send_tstamp = skb_tstamp; */
		goto unlock;
	}

	added_delay = send_tstamp - skb_tstamp;
	skb->tstamp = send_tstamp;

	if (send_tstamp - now > mark_ns)
		ecn = true;

	if (send_tstamp - now > drop_ns)
		ret = DROP;

unlock:
	hbm_update_stats(qsp, skb, local_port, now, added_delay, skb_delay, ret, &pkti);
	if (ret == ALLOW || ret == ALLOW_CWR)
		qdp->lasttime = send_tstamp;

	bpf_spin_unlock(&qdp->lock);

	(void)ecn;
/*
	if (ecn) {
		if (bpf_skb_ecn_set_ce(skb))
			__sync_add_and_fetch(&qsp->pkts_ecn, 1);
		else
			__sync_add_and_fetch(&qsp->pkts_ecn_err, 1);
	}
*/
	return ALLOW;
}

char _license[] SEC("license") = "GPL";
