#ifndef simple_tcp_cong
#define simple_tcp_cong
#include "share.h"
//#include "smack.h"

//static int num_packets = 1;
//module_param(num_packets, int, 0644);
//MODULE_PARM_DESC(num_packets, "number of consecutive packets");

/* Simple linear search, don't expect many entries! */
static struct tcp_congestion_ops *tcp_ca_find(const char *name)
{
	return NULL;
}

/* Must be called with rcu lock held */
static const struct tcp_congestion_ops *__tcp_ca_find_autoload(const char *name)
{

	return NULL;
}

/* Simple linear search, not much in here. */
struct tcp_congestion_ops *tcp_ca_find_key(u32 key)
{

	return NULL;
}

/*
 * Attach new congestion control algorithm to the list
 * of available options.
 */
int tcp_register_congestion_control(struct tcp_congestion_ops *ca)
{
	return 0;
}
EXPORT_SYMBOL_GPL(tcp_register_congestion_control);

/*
 * Remove congestion control algorithm, called from
 * the module's remove function.  Module ref counts are used
 * to ensure that this can't be done till all sockets using
 * that method are closed.
 */
void tcp_unregister_congestion_control(struct tcp_congestion_ops *ca)
{
	return;
}
EXPORT_SYMBOL_GPL(tcp_unregister_congestion_control);

u32 tcp_ca_get_key_by_name(const char *name, bool *ecn_ca)
{
	return 0;
}
EXPORT_SYMBOL_GPL(tcp_ca_get_key_by_name);

char *tcp_ca_get_name_by_key(u32 key, char *buffer)
{
	return NULL;
}
EXPORT_SYMBOL_GPL(tcp_ca_get_name_by_key);

/* Assign choice of congestion control. */
void tcp_assign_congestion_control(struct sock *sk)
{
	return ;
}

void tcp_init_congestion_control(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	tcp_sk(sk)->prior_ssthresh = 0;
	if (icsk->icsk_ca_ops->init)
		icsk->icsk_ca_ops->init(sk);

	/*if (tcp_ca_needs_ecn(sk))*/
		/*INET_ECN_xmit(sk);*/
	/*else*/
		/*INET_ECN_dontxmit(sk);*/
}

/* Manage refcounts on socket close. */
void tcp_cleanup_congestion_control(struct sock *sk)
{
	return;
}

static void tcp_reinit_congestion_control(struct sock *sk,
					  const struct tcp_congestion_ops *ca)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	tcp_cleanup_congestion_control(sk);
	icsk->icsk_ca_ops = ca;
	icsk->icsk_ca_setsockopt = 1;
	memset(icsk->icsk_ca_priv, 0, sizeof(icsk->icsk_ca_priv));

	if (sk->sk_state != TCP_CLOSE)
		tcp_init_congestion_control(sk);

	return;
}


/* Used by sysctl to change default congestion control */
int tcp_set_default_congestion_control(const char *name)
{
	return 0;
}

/* Set default value from kernel configuration at bootup */
static int __init tcp_congestion_default(void)
{
	return 0;
}

/* Build string with list of available congestion control values */
void tcp_get_available_congestion_control(char *buf, size_t maxlen)
{
	return ;
}

/* Get current default congestion control */
void tcp_get_default_congestion_control(char *name)
{
	return;
}

/* Built list of non-restricted congestion control values */
void tcp_get_allowed_congestion_control(char *buf, size_t maxlen)
{
	return;
}

/* Change list of non-restricted congestion control */
int tcp_set_allowed_congestion_control(char *val)
{
	return 0;
}

/* Change congestion control for socket */
// revised by wsun, directly pass CA, to comment the code to lookup the name//
int tcp_set_congestion_control(struct sock *sk, const struct tcp_congestion_ops *ca)
{
	tcp_reinit_congestion_control(sk, ca);
	return 0;
}

// <M>
/* set number of consecutive packets for aggregation*/
//static void tcp_set_number_packets(int n)
//{
//	num_packets = n;
//	printf("Number of packets: %d", num_packets);
//}


/* Slow start is used when congestion window is no greater than the slow start
 * threshold. We base on RFC2581 and also handle stretch ACKs properly.
 * We do not implement RFC3465 Appropriate Byte Counting (ABC) per se but
 * something better;) a packet is only considered (s)acked in its entirety to
 * defend the ACK attacks described in the RFC. Slow start processes a stretch
 * ACK of degree N as if N acks of degree 1 are received back to back except
 * ABC caps N to 2. Slow start exits when cwnd grows over ssthresh and
 * returns the leftover acks to adjust cwnd in congestion avoidance mode.
 */
u32 tcp_slow_start(struct tcp_sock *tp, u32 acked)
{
	u32 cwnd = min(tp->snd_cwnd + acked, tp->snd_ssthresh);

	acked -= cwnd - tp->snd_cwnd;
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);

	if (tp->debug_info) {
		printf("[Func: tcp_slow_start] cwnd:%u, acked:%u, snd_cwnd:%u\n", 
				cwnd, acked, tp->snd_cwnd);
	}

	return acked;
}
EXPORT_SYMBOL_GPL(tcp_slow_start);
 
//u32 tcp_slow_start(struct tcp_sock *tp, u32 acked)
//{
////	if (!tp->packet_aggregation) {
//	if (true) { // we aggregate packets before calling tcp_slow_start so just use the original
//		u32 cwnd = min(tp->snd_cwnd + acked, tp->snd_ssthresh);
//
//		acked -= cwnd - tp->snd_cwnd;
//		tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
//
//		if (tp->debug_info) {
//			printf("[Func: tcp_slow_start] cwnd:%u, acked:%u, snd_cwnd:%u\n", 
//					cwnd, acked, tp->snd_cwnd);
//		}
//		//assert(tp->snd_cwnd < cwnd);
//		//assert(tp->snd_cwnd < tp->snd_cwnd_clamp);
//	} else { // packet aggregation
//		//while (tp->snd_cwnd < tp->snd_ssthresh && tp->num_packets > 0) {
//			//acked += tp->one_acked;
//			//u32 cwnd = min(tp->snd_cwnd + acked, tp->snd_ssthresh);
//			//if (tp->debug_info) {
//				//printf("[Func: tcp_slow_start PacketAggregation] cwnd:%u, acked:%u, ssthresh:%u, cwnd_clamp:%u\n", 
//						//cwnd, acked, tp->snd_ssthresh, tp->snd_cwnd_clamp);
//			//}		
//			//acked -= cwnd - tp->snd_cwnd;
//			//tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
//			
//			//tp->num_packets--;
//			//if (tp->debug_info) {
//				//printf("[Func: tcp_slow_start PacketAggregation] cwnd:%u, acked:%u, snd_cwnd:%u\n", 
//						//cwnd, acked, tp->snd_cwnd);
//			//}
//		//}
//		u32 total_acked = acked * tp->num_packets;
//		u32 cwnd = min(tp->snd_cwnd + total_acked, tp->snd_ssthresh);
//		
//		if (tp->debug_info) {
//			printf("[Func: tcp_slow_start PacketAggregation] cwnd:%u, acked:%u, ssthresh:%u, cwnd_clamp:%u\n", 
//					cwnd, acked, tp->snd_ssthresh, tp->snd_cwnd_clamp);
//		}	
//		
//		total_acked -= cwnd - tp->snd_cwnd;
//		tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
//		// calculate the number of packets left when slow start finishes
//		if (total_acked > 0) {
//			tp->num_packets = total_acked / tp->one_acked;
//			acked = total_acked - tp->one_acked * tp->num_packets;
//			// integer division rounds down
//			// add one packet here after calculating acked left
//			tp->num_packets++;
//		}
//		else { // no packets left
//			tp->num_packets = 0;
//			acked = total_acked;
//		}
//		
//		if (tp->debug_info) {
//			printf("[Func: tcp_slow_start PacketAggregation] cwnd:%u, acked:%u, snd_cwnd:%u\n", 
//					cwnd, acked, tp->snd_cwnd);
//		}
//	}
//
//	return acked;
//}
//EXPORT_SYMBOL_GPL(tcp_slow_start);

/* calculate the square root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 */
//static u32 square_root(u64 a)
//{
//	STUB (1, "debug.\n");
//	u32 x, b, shift;
//	/*
//	 * cbrt(x) MSB values for x MSB values in [0..63].
//	 * Precomputed then refined by hand - Willy Tarreau
//	 *
//	 * For x in [0..63],
//	 *   v = cbrt(x << 18) - 1
//	 *   cbrt(x) = (v[x] + 10) >> 6
//	 */
//	static const u8 v[] = {
//		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
//		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
//		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
//		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
//		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
//		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
//		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
//		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
//	};
//
//	b = fls64(a);
//	if (b < 7) {
//		/* a in [0..63] */
//		return ((u32)v[(u32)a] + 35) >> 6;
//	}
//
//	b = ((b * 84) >> 8) - 1;
//	shift = (a >> (b * 3));
//
//	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;
//
//	/*
//	 * Newton-Raphson iteration
//	 *                         
//	 * x    = ( x  +  a / x  ) / 2
//	 *  k+1      k         k
//	 */
//	x = (x + (u32)div64_u64(a, (u64)x));
//	x = x >> 1;
//	return x;
//}

/* In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w),
 * for every packet that was ACKed.
 */
void tcp_cong_avoid_ai(struct tcp_sock *tp, u32 w, u32 acked)
{
	if (tp->debug_info) {
		printf("[Func: tcp_cong_avoid_ai] w:%u, acked:%u, snd_cwnd_cnt:%u\n", 
				w, acked, tp->snd_cwnd_cnt);
	}

	//u32 prior_cwnd = tp->snd_cwnd;

	if (!tp->packet_aggregation) { // orginal
		// If credits accumulated at a higher w, apply them gently now.
		if (tp->snd_cwnd_cnt >= w) {
			tp->snd_cwnd_cnt = 0;
			tp->snd_cwnd++;
		}

		tp->snd_cwnd_cnt += acked;
		if (tp->snd_cwnd_cnt >= w) {
			u32 delta = tp->snd_cwnd_cnt / w;

			tp->snd_cwnd_cnt -= delta * w;
			tp->snd_cwnd += delta;
			if (tp->debug_info) {
				printf("[Func: tcp_cong_avoid_ai] snd_cwnd:%u, snd_cwnd_cnt:%u, delta:%u\n", 
						tp->snd_cwnd, tp->snd_cwnd_cnt, delta);
			}
		}
		tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
	} else { // packet aggregation
		//while (tp->num_packets > 0) {
			//if (tp->snd_cwnd_cnt >= w) {
				//tp->snd_cwnd_cnt = 0;
				//tp->snd_cwnd++;
			//}
			
			//tp->snd_cwnd_cnt += acked;

			//if (tp->snd_cwnd_cnt >= w) {
				//u32 delta = tp->snd_cwnd_cnt / w;

				//tp->snd_cwnd_cnt -= delta * w;
				//tp->snd_cwnd += delta;
				//if (tp->debug_info) {
					//printf("[Func: tcp_cong_avoid_ai PacketAggregation] snd_cwnd:%u, snd_cwnd_cnt:%u, delta:%u\n", 
							//tp->snd_cwnd, tp->snd_cwnd_cnt, delta);
				//}
			//}
			//tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
			//w = tp->snd_cwnd;
			//tp->num_packets--;
		//}
		// Using floating point numbers
//		if (tp->snd_cwnd_cnt >= tp->snd_cwnd)
//			tp->snd_cwnd_cnt = tp->snd_cwnd;
//		double delta = tp->snd_cwnd * tp->snd_cwnd - tp->snd_cwnd + 1.0/4.0 +
//						2 * tp->num_packets * acked + 2 * tp->snd_cwnd_cnt;
//		tp->snd_cwnd = sqrt(delta) + 1.0/2.0;
//		tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
		
		// Using square root estimation
//		if (tp->snd_cwnd_cnt >= tp->snd_cwnd)
//			tp->snd_cwnd_cnt = tp->snd_cwnd;
//		u64 delta = tp->snd_cwnd * tp->snd_cwnd - tp->snd_cwnd +
//						2 * tp->num_packets * acked + 2 * tp->snd_cwnd_cnt;
//		tp->snd_cwnd = square_root(delta);
//		tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
//		
//		STUB (1, "debug - after returning from square_root.\n");
		
		// Up to one RTT only
		if (tp->snd_cwnd_cnt >= w) {
			tp->snd_cwnd_cnt = 0;
			tp->snd_cwnd++;
		}
		tp->snd_cwnd_cnt += acked;
		if (tp->snd_cwnd_cnt >= w) {
			tp->snd_cwnd_cnt -= w;
			tp->snd_cwnd++;
		}
		tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
		
		if (tp->debug_info) {
//			printf("[Func: tcp_cong_avoid_ai PacketAggregation] snd_cwnd:%u, snd_cwnd_cnt:%u, delta:%u, sqrt(delta):%lf\n", 
//							tp->snd_cwnd, tp->snd_cwnd_cnt, delta, sqrt(delta));
		}
	}
	
	//assert(tp->snd_cwnd >= prior_cwnd);
}
EXPORT_SYMBOL_GPL(tcp_cong_avoid_ai);


/* 
 * Original linux tcp reno already increases snd_cwnd only after a RTT
 * snd_cwnd only increases at the end of a RTT
 */
/*void tcp_cong_avoid_ai(struct tcp_sock *tp, u32 w, u32 acked)
{
	if (tp->debug_info) {
		printf("[Func: tcp_cong_avoid_ai] w:%u, acked:%u, snd_cwnd_cnt:%u\n", 
				w, acked, tp->snd_cwnd_cnt);
	}

	u32 prior_cwnd = tp->snd_cwnd;

	if (!tp->packet_aggregation) { // orginal
		tp->acked_counter += acked;
		// If credits accumulated at a higher w, apply them gently now.
		if (tp->snd_cwnd_cnt >= w) {
			tp->snd_cwnd_cnt = 0;
			tp->cwnd_counter++;
		}
		tp->snd_cwnd_cnt += acked;
		if (tp->snd_cwnd_cnt >= w) {
			u32 delta = tp->snd_cwnd_cnt / w;
			tp->snd_cwnd_cnt -= delta * w;
			tp->cwnd_counter += delta;
		}
		// Reach the end of a RTT, increase snd_cwnd
		if (tp->acked_counter >= tp->snd_cwnd) {
			tp->snd_cwnd += tp->cwnd_counter;
			tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
			tp->acked_counter = 0;
			tp->cwnd_counter = 0;
			w = tp->snd_cwnd;
		}
		if (tp->debug_info) {
			printf("[Func: tcp_cong_avoid_ai] snd_cwnd:%u, snd_cwnd_cnt:%u, cwnd_counter:%u, acked_counter:%u\n", 
							tp->snd_cwnd, tp->snd_cwnd_cnt, tp->cwnd_counter, tp->acked_counter);
		}
	} else { // packet aggregation
		// Follow RFC snd_cwnd += mss*mss/snd_cwnd
		//u32 delta = tp->snd_cwnd * tp->snd_cwnd + (2*acked - tp->snd_cwnd) * tp->one_acked
		//						+ (1/4 + 2 * tp->num_packets) * tp->one_acked * tp->one_acked;
		//tp->snd_cwnd += (sqrt(delta) - (tp->snd_cwnd + tp->one_acked / 2)) / tp->one_acked;

		// Follow Linux kernel implementation
		// Linux seems to be less aggresive than the RFC, only increase snd_cwnd by 1/snd_cwnd each packet acked
		//u32 delta = tp->snd_cwnd * tp->snd_cwnd - (tp->snd_cwnd + 2 * acked) / tp->one_acked
		//						+ 1/(4 * tp->one_acked * tp->one_acked) + 2 * tp->num_packets;
		//u32 tmp_cwnd = tp->snd_cwnd;
		//tp->snd_cwnd += sqrt(delta) - tmp_cwnd - 1/(2*tp->one_acked);
		
		// But based on the code, it seems that snd_cwnd is increased by 1 each RTT
		u32 delta = tp->snd_cwnd * tp->snd_cwnd - tp->snd_cwnd + 1/4 + 2 * tp->num_packets * tp->one_acked + 2 * acked;
		tp->snd_cwnd += sqrt(delta) - tp->snd_cwnd - 1/2;
		
		tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
		if (tp->debug_info) {
					printf("[Func: tcp_cong_avoid_ai PacketAggregation] snd_cwnd:%u, snd_cwnd_cnt:%u, delta:%u, sqrt(delta):%lf\n", 
							tp->snd_cwnd, tp->snd_cwnd_cnt, delta, sqrt(delta));
		}
	}
}
EXPORT_SYMBOL_GPL(tcp_cong_avoid_ai);
*/

/*
 * TCP Reno congestion control
 * This is special case used for fallback as well.
 */
/* This is Jacobson's slow start and congestion avoidance.
 * SIGCOMM '88, p. 328.
 */
void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	
	STUB (tp->debug_info, "debug.\n");
	
	if (tp->debug_info) {
		printf("[Func: tcp_reno_cong_avoid] number of packets:%d, ack:%u, acked:%u, snd_ssthresh:%u\n", 
				tp->num_packets, ack, acked, tp->snd_ssthresh);
		printf("[Func: tcp_reno_cong_avoid] snd_cwnd:%u, snd_cwnd_cnt:%u, max_packets_out:%u, snd_cwnd_clamp:%u\n", 
				tp->snd_cwnd, tp->snd_cwnd_cnt, tp->max_packets_out, tp->snd_cwnd_clamp);
	}

	if (!tcp_is_cwnd_limited(sk)) {
		if (tp->debug_info) {
			printf("[Func: tcp_reno_cong_avoid] tcp is cwmd limited !!!\n");
		}
		return;
	}

	/* In "safe" area, increase. */
	if (tcp_in_slow_start(tp)) {
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}
	if (tp->debug_info) {
		printf("Exit slow start\n");
	}
	/* In dangerous area, increase slowly. */
	tcp_cong_avoid_ai(tp, tp->snd_cwnd, acked);
}
EXPORT_SYMBOL_GPL(tcp_reno_cong_avoid);

/* Slow start threshold is half the congestion window (min 2) */
u32 tcp_reno_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	
	STUB (tp->debug_info, "debug.\n");
	
	return max(tp->snd_cwnd >> 1U, 2U);
}
EXPORT_SYMBOL_GPL(tcp_reno_ssthresh);

u32 tcp_reno_undo_cwnd(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	
	STUB (tp->debug_info, "debug.\n");
	
	return max(tp->snd_cwnd, tp->snd_ssthresh << 1);
}
EXPORT_SYMBOL_GPL(tcp_reno_undo_cwnd);

struct tcp_congestion_ops tcp_reno = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "reno",
	.owner		= THIS_MODULE,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
};

#endif /* ifndef simple_tcp_cong */
