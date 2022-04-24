#ifndef simple_tcp_ipv4
#define simple_tcp_ipv4
#include "share.h"
static void __net_exit tcp_sk_exit(struct net *net)
{
   /* int cpu;*/

	/*for_each_possible_cpu(cpu)*/
		/*inet_ctl_sock_destroy(*per_cpu_ptr(net->ipv4.tcp_sk, cpu));*/
	/*free_percpu(net->ipv4.tcp_sk);*/
	return;
}

static int __net_init tcp_sk_init(struct net *net)
{
	int res, cpu, cnt;

	/*net->ipv4.tcp_sk = alloc_percpu(struct sock *);*/
	/*if (!net->ipv4.tcp_sk)*/
		/*return -ENOMEM;*/

	/*for_each_possible_cpu(cpu) {*/
		/*struct sock *sk;*/

		/*res = inet_ctl_sock_create(&sk, PF_INET, SOCK_RAW,*/
					   /*IPPROTO_TCP, net);*/
		/*if (res)*/
			/*goto fail;*/
		/*sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);*/
		/**per_cpu_ptr(net->ipv4.tcp_sk, cpu) = sk;*/
	/*}*/

	net->ipv4.sysctl_tcp_ecn = 2;
	net->ipv4.sysctl_tcp_ecn_fallback = 1;

	net->ipv4.sysctl_tcp_base_mss = TCP_BASE_MSS;
	net->ipv4.sysctl_tcp_probe_threshold = TCP_PROBE_THRESHOLD;
	net->ipv4.sysctl_tcp_probe_interval = TCP_PROBE_INTERVAL;

	net->ipv4.sysctl_tcp_keepalive_time = TCP_KEEPALIVE_TIME;
	net->ipv4.sysctl_tcp_keepalive_probes = TCP_KEEPALIVE_PROBES;
	net->ipv4.sysctl_tcp_keepalive_intvl = TCP_KEEPALIVE_INTVL;

	net->ipv4.sysctl_tcp_syn_retries = TCP_SYN_RETRIES;
	net->ipv4.sysctl_tcp_synack_retries = TCP_SYNACK_RETRIES;
	net->ipv4.sysctl_tcp_syncookies = 1;
	net->ipv4.sysctl_tcp_reordering = TCP_FASTRETRANS_THRESH;
	net->ipv4.sysctl_tcp_retries1 = TCP_RETR1;
	net->ipv4.sysctl_tcp_retries2 = TCP_RETR2;
	net->ipv4.sysctl_tcp_orphan_retries = 0;
	net->ipv4.sysctl_tcp_fin_timeout = TCP_FIN_TIMEOUT;
	net->ipv4.sysctl_tcp_notsent_lowat = UINT_MAX;
	net->ipv4.sysctl_tcp_tw_reuse = 0;

   /* cnt = tcp_hashinfo.ehash_mask + 1;*/
	/*net->ipv4.tcp_death_row.sysctl_max_tw_buckets = (cnt + 1) / 2;*/
	/*net->ipv4.tcp_death_row.hashinfo = &tcp_hashinfo;*/

	/*net->ipv4.sysctl_max_syn_backlog = max(128, cnt / 256);*/

	return 0;
fail:
	tcp_sk_exit(net);

	return res;
}

#endif /* ifndef simple_tcp_ipv4 */
