#ifndef script_tcp_ack_function
#define script_tcp_ack_function
#include "share.h"
#include "klee.h"

    struct sk_buff *skb;
	skb = malloc (sizeof (*skb));
    struct tcp_sock tcp_sock_struct;
	struct tcp_sock *sk = &tcp_sock_struct;
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	u8 ca_state;
    u32 num_special_events = 1;

	u32 special_indexes [num_special_events]; // indexes of special events
	u32 undoing [num_special_events]; // for each loss, explore both undoing and not undoing
	u32 timeout [num_special_events];
	
	u32 sym_cwnd = __VERIFIER_nondet_u32("snd_cwnd");
	u32 sym_ssthresh = __VERIFIER_nondet_u32("snd_ssthresh");
	klee_assume (sym_cwnd >= 1 && sym_cwnd <= 100);
	klee_assume (sym_ssthresh >= 1);
	tp->snd_cwnd = sym_cwnd;
	tp->snd_ssthresh = sym_ssthresh;

	u32 agg_update_packets_sent [num_special_events+1];
	u32 agg_update_packets_acked [num_special_events+1];
	u32 one_ack = 1;
	
	
	tp->packet_aggregation = 1; // 0: original, 1: aggregation
	tp->num_packets = 1; // all aggregated packets are counted as 1
	tp->is_cwnd_limited = 1; // cwnd will not be limited
	int return_status = 0;
	u32 prior_cwnd = 0; // cwnd before an event
	u32 prior_loss_cwnd = 0; // cwnd before loss
	u32 prior_timeout_cwnd = 0; // cwnd before a timeout
	u32 prior_ssthresh = 0; // ssthresh before timeout
	bool enable_verifier = true; // enable assertion statements
	bool three_dup_acks = false;
	bool is_timeout = false;
	int flag = 0;
	TCP_SKB_CB(skb)->seq = 0;
	TCP_SKB_CB(skb)->ack_seq = 0;

extern struct tcp_congestion_ops tcp_reno;
extern unsigned int __VERIFIER_nondet_uint(char *name);
extern u32 __VERIFIER_nondet_u32(char *name);
extern void __VERIFIER_error();
u32 fast_recovery();
u32 three_dup_acks();
u32 u32 three_dup_acks_not();

void __VERIFIER_error() 
{
	klee_assert(0);
}

unsigned int __VERIFIER_nondet_uint(char *name) 
{
	unsigned int __sym__VERIFIER_nondet_uint;
	klee_make_symbolic (&__sym__VERIFIER_nondet_uint, sizeof(__sym__VERIFIER_nondet_uint),
	name);
	return __sym__VERIFIER_nondet_uint;
}

u32 __VERIFIER_nondet_u32(char *name) 
{
	u32 __sym__VERIFIER_nondet_u32;
	klee_make_symbolic (&__sym__VERIFIER_nondet_u32, sizeof(__sym__VERIFIER_nondet_u32),
	name);
	return __sym__VERIFIER_nondet_u32;
}

void __VERIFIER_assert(int cond)
{
	if (!(cond))
	{
		__VERIFIER_error();
	}
	return;
}



static int tcp_ack_new(struct sock *sk, const struct sk_buff *skb, int flag)
{

	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_sacktag_state sack_state;
	struct rate_sample rs = { .prior_delivered = 0 };
	u32 prior_snd_una = tp->snd_una;
	bool is_sack_reneg = tp->is_sack_reneg;
	u32 ack_seq = TCP_SKB_CB(skb)->seq;
	u32 ack = TCP_SKB_CB(skb)->ack_seq;
	int num_dupack = 0;
	int prior_packets = tp->packets_out;
	u32 delivered = tp->delivered;
	u32 lost = tp->lost;
	int rexmit = REXMIT_NONE; 
	u32 prior_fack;

	sack_state.first_sackt = 0;
	sack_state.rate = &rs;
	

	if (before(ack, prior_snd_una)) {
		
		if (before(ack, prior_snd_una - tp->max_window)) {

			printf ("First if tcp_ack, old ack.\n");
			return -1;
		}
		goto old_ack;
	}

	if (after(ack, tp->snd_nxt)) {

		printf("Second if tcp_ack, invalid ack.\n");
		return -1;
	}

	if (after(ack, prior_snd_una)) {
		flag |= FLAG_SND_UNA_ADVANCED;
		icsk->icsk_retransmits = 0;


	}

	prior_fack = tcp_is_sack(tp) ? tcp_highest_sack_seq(tp) : tp->snd_una;
	rs.prior_in_flight = tcp_packets_in_flight(tp);


	if ((flag & (FLAG_SLOWPATH | FLAG_SND_UNA_ADVANCED)) ==
	    FLAG_SND_UNA_ADVANCED) {
	
		tcp_update_wl(tp, ack_seq);
		tcp_snd_una_update(tp, ack);
		flag |= FLAG_WIN_UPDATE;

		tcp_in_ack_event(sk, CA_ACK_WIN_UPDATE);


	} else {
		u32 ack_ev_flags = CA_ACK_SLOWPATH;

		if (ack_seq != TCP_SKB_CB(skb)->end_seq)
			flag |= FLAG_DATA;

		if (tp->ecn_flags & TCP_ECN_OK) {
			flag |= FLAG_ECE;
			ack_ev_flags |= CA_ACK_ECE;
		}

		if (flag & FLAG_WIN_UPDATE)
			ack_ev_flags |= CA_ACK_WIN_UPDATE;

		tcp_in_ack_event(sk, ack_ev_flags);
	}

	
	sk->sk_err_soft = 0;
	icsk->icsk_probes_out = 0;
	tp->rcv_tstamp = tcp_jiffies32;
	if (!prior_packets)
		goto no_queue;


	if (tcp_ack_is_dubious(sk, flag)) {
		if (!(flag & (FLAG_SND_UNA_ADVANCED | FLAG_NOT_DUP))) {
			num_dupack = 1;
			
			if (!(flag & FLAG_DATA))
				num_dupack = max_t(u16, 1, skb_shinfo(skb)->gso_segs);
		}
		tcp_fastretrans_alert(sk, prior_snd_una, num_dupack, &flag,
				      &rexmit);
	}

	if ((flag & FLAG_FORWARD_PROGRESS) || !(flag & FLAG_NOT_DUP))
		sk_dst_confirm(sk);


	tp->delivered += ack - ack_seq;



	delivered = tcp_newly_delivered(sk, delivered, flag);
	lost = tp->lost - lost;			/* freshly marked lost */
	rs.is_ack_delayed = !!(flag & FLAG_ACK_MAYBE_DELAYED);
	tcp_rate_gen(sk, delivered, lost, is_sack_reneg, sack_state.rate);
	tcp_cong_control(sk, ack, delivered, flag, sack_state.rate);

	return 1;

no_queue:
	
	if (flag & FLAG_DSACKING_ACK) {
		tcp_fastretrans_alert(sk, prior_snd_una, num_dupack, &flag,
				      &rexmit);
		tcp_newly_delivered(sk, delivered, flag);
	}


	if (tp->tlp_high_seq)
		tcp_process_tlp_ack(sk, ack, flag);
		
	printf ("no_queue branch.\n");	
	return 1;

old_ack:

	if (TCP_SKB_CB(skb)->sacked) {
		
		tcp_fastretrans_alert(sk, prior_snd_una, num_dupack, &flag,
				      &rexmit);
		tcp_newly_delivered(sk, delivered, flag);

	}

	printf ("old_ack branch.\n");
	return 0;
}


static void update_newly_received_packet_variables (struct sock *sk, struct sk_buff *skb, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	
	tp->rcv_nxt = TCP_SKB_CB(skb)->seq + 1;
	tp->rcv_wup = TCP_SKB_CB(skb)->seq + 1;
	TCP_SKB_CB(skb)->ack_seq += acked;
	tp->snd_nxt	= TCP_SKB_CB(skb)->ack_seq;
}


static int aggregate_normal_events (struct sock *sk, struct sk_buff *skb) {
	struct tcp_sock *tp = tcp_sk(sk);
	

	tp->max_packets_out = tp->snd_cwnd * 2;
	int flag = FLAG_DATA;
	flag |= FLAG_DATA_ACKED;

	int return_status = tcp_ack_new(sk, skb, flag);
	
	return return_status;
}



    u32 three_dup_acks()
	{
		
				tp->packets_out = 0;
				
				tp->undo_retrans = 0;
				flag = FLAG_DSACKING_ACK;
				return_status = tcp_ack_new(sk, skb, flag);
				tp->packets_out = __VERIFIER_nondet_u32("packets out after undoing three dup acks");
				klee_assume (tp->packets_out < prior_packets_out);
				tp->lost_out--;
				tp->retrans_out--;
				three_dup_acks = false;
				tcp_set_ca_state(sk, TCP_CA_Open);
				if (enable_verifier) {
					klee_assert(tp->snd_cwnd <= prior_loss_cwnd);
				}
	}
	
	
	
	
	u32 three_dup_acks_not()
	{
		update_newly_received_packet_variables (sk, skb, agg_update_packets_acked[i]);
			prior_cwnd = tp->snd_cwnd;
			return_status = aggregate_normal_events (sk, skb);
			
			TCP_SKB_CB(skb)->seq += agg_update_packets_acked[i];
			tp->packets_out -= agg_update_packets_acked[i];
			if (enable_verifier) {
				klee_assert(tp->snd_cwnd >= prior_cwnd);
			}
	}

	


u32 fast_recovery()
{
	// Fast recovery
//				printf ("Aggregate last group in fast recovery------\n");
//				tp->sacked_out += agg_update_packets_sent[num_special_events]
//													+ agg_update_packets_sent[num_special_events]/2;
				tp->sacked_out += agg_update_packets_sent[num_special_events]; //+ agg_update_packets_sent[i]/2;
				tp->snd_nxt	+= agg_update_packets_sent[num_special_events];
//				tp->prr_out += agg_update_packets_sent[num_special_events];
//				tp->prr_delivered += agg_update_packets_acked[num_special_events];
				tp->high_seq = tp->snd_nxt;
//				update_newly_received_packet_variables_fast_recovery (sk, skb, agg_update_packets_acked[num_special_events]);
				// To skip state D case TCP_CA_Recovery in tcp_fastretrans_alert()
				prior_cwnd = tp->snd_cwnd;
				return_status = aggregate_normal_events (sk, skb);
				TCP_SKB_CB(skb)->seq += agg_update_packets_acked[num_special_events];
				tp->packets_out -= agg_update_packets_acked[num_special_events];
				if (enable_verifier) {
					klee_assert(tp->snd_cwnd <= prior_loss_cwnd);
				}
}



int main() 
{
	
	if (skb == NULL) {
		fprintf(stderr, "skb allocation failed.\n");
		return -1;
	}
	

	memset(&tcp_sock_struct, 0, sizeof(struct tcp_sock));
	tcp_set_congestion_control(sk, &tcp_reno);
	struct net net_namespace;
	memset(&net_namespace, 0, sizeof(struct net));
	sk->inet_conn.icsk_inet.sk.sk_net.net = &net_namespace;
	tcp_sk_init(&net_namespace);

	tp->debug_info = 0;
	if (tp->debug_info) {
		printf("[Before initialization] tp->snd_cwnd:%u, tp->snd_ssthresh:%u\n",
						tp->snd_cwnd, tp->snd_ssthresh);
	}

	tcp_init_sock(sk);

	if (icsk->icsk_ca_ops->init)
		icsk->icsk_ca_ops->init(sk);
	tcp_ca_event(sk, CA_EVENT_TX_START);

	if (tp->debug_info) {
		printf("[After initialization] tp->snd_cwnd:%u, tp->snd_ssthresh:%u\n",
						tp->snd_cwnd, tp->snd_ssthresh);
	}
	

	
	
	tcp_set_ca_state(sk, TCP_CA_Open);
	
	for (u32 i=0; i<num_special_events; i++) {
		printf ("ITERATION %u --------\n", (i+1));
		
		agg_update_packets_sent[i] = __VERIFIER_nondet_u32("agg update packets sent");
		klee_assume (agg_update_packets_sent[i] <= tp->snd_cwnd);
	
		agg_update_packets_acked[i] = __VERIFIER_nondet_u32("agg update packets acked");
		klee_assume (agg_update_packets_acked[i] <= agg_update_packets_sent[i]);
		
		tp->packets_out += agg_update_packets_sent[i];
		if (three_dup_acks == false) { // Normal case

			three_dup_acks_not();
		}
		else { 
			tp->sacked_out += agg_update_packets_sent[i]; //+ agg_update_packets_sent[i]/2;
			tp->snd_nxt += agg_update_packets_sent[i];


			tp->high_seq = tp->snd_nxt;

			prior_cwnd = tp->snd_cwnd;
			return_status = aggregate_normal_events (sk, skb);
			TCP_SKB_CB(skb)->seq += agg_update_packets_acked[i];
			tp->packets_out -= agg_update_packets_acked[i];
			if (enable_verifier) {
				klee_assert(tp->snd_cwnd <= prior_cwnd);
			}
		}
		
		undoing[i] = __VERIFIER_nondet_u32("undoing");
		timeout[i] = __VERIFIER_nondet_u32("timeout");
		if (undoing[i] != 0 && (three_dup_acks || is_timeout)) { 
			
			u32 prior_packets_out = tp->packets_out;
			if (three_dup_acks) {
			three_dup_acks();
			}
			else if (is_timeout) {
				tp->frto = 1;
				flag = FLAG_ORIG_SACK_ACKED;
				return_status = tcp_ack_new(sk, skb, flag);
				tp->packets_out = __VERIFIER_nondet_u32("packets out after undoing timeout");
				klee_assume (tp->packets_out < prior_packets_out);
				is_timeout = false;
				if (enable_verifier) {
					klee_assert(tp->snd_cwnd >= prior_timeout_cwnd);
				}
			}
			
		}
		else if (timeout[i] != 0) { // Timeout
//			printf ("Timeout------\n");
			update_newly_received_packet_variables (sk, skb, one_ack);
			tcp_set_ca_state(sk, TCP_CA_Disorder);
			flag = FLAG_SET_XMIT_TIMER;
			prior_timeout_cwnd = tp->snd_cwnd;
			tcp_enter_loss(sk);
			tp->undo_marker = tp->snd_una;
			// undo the most recent cwnd reduction
			is_timeout = true;
			three_dup_acks = false;
			if (enable_verifier) {
				klee_assert(tp->snd_cwnd <= prior_timeout_cwnd);
			}
		}
		else if (three_dup_acks == false){ // Three dup acks
//			printf ("Three dup acks------\n");
			tcp_set_ca_state(sk, TCP_CA_Disorder);
			// If tp->lost_out = 0, the conditional "if (!tcp_time_to_recover(sk, flag))" passes
			// tp->lost_out must be greater than 0 for tcp_fastretrans_alert() to call tcp_enter_recovery()
			tp->lost_out += one_ack;
			// retransmit missing packets
			tp->retrans_out += one_ack;
			// Increase ack_seq so delivered > 0. Thus, in tcp_cwnd_reduction(), first if is false,
			// the functions won't return, and we can reach the end where tp->snd_cwnd is modified.
			// The 3rd argument below is passed to tcp_packet_in_flight() later, and affects the
			// cwnd after loss.
			tp->rcv_nxt = TCP_SKB_CB(skb)->seq + one_ack;
			tp->rcv_wup = TCP_SKB_CB(skb)->seq + one_ack;
			TCP_SKB_CB(skb)->ack_seq += one_ack;
			tp->snd_nxt	= TCP_SKB_CB(skb)->ack_seq;
			tp->packets_out += one_ack;
			flag = FLAG_LOST_RETRANS;
			prior_loss_cwnd = tp->snd_cwnd;
			return_status = tcp_ack_new(sk, skb, flag);
			three_dup_acks = true;
			is_timeout = false;
			if (enable_verifier) {
				klee_assert(tp->snd_cwnd <= prior_loss_cwnd);
				klee_assert(tp->snd_cwnd >= tp->snd_ssthresh);
			}
		}
		
		// This is the last loss events, aggregate all normal packets left
		if (i == num_special_events-1) {
			// number of aggregated update packets
			agg_update_packets_sent[num_special_events] = __VERIFIER_nondet_u32("last agg update packets sent");
			klee_assume (agg_update_packets_sent[num_special_events] <= tp->snd_cwnd);
			// number of aggregated update packets received
			agg_update_packets_acked[num_special_events] = __VERIFIER_nondet_u32("last agg update packets acked");
			klee_assume (agg_update_packets_acked[num_special_events] <= agg_update_packets_sent[num_special_events]);
			// Aggregate packets up to one RTT maximum
			tp->packets_out += agg_update_packets_sent[num_special_events];
			if (three_dup_acks == false) {
//				printf ("Aggregate last group of update normal packets------\n");
				update_newly_received_packet_variables (sk, skb, agg_update_packets_acked[num_special_events]);
				prior_cwnd = tp->snd_cwnd;
				return_status = aggregate_normal_events (sk, skb);
				TCP_SKB_CB(skb)->seq += agg_update_packets_acked[num_special_events];
				tp->packets_out -= agg_update_packets_acked[num_special_events];
				if (enable_verifier) {
					klee_assert(tp->snd_cwnd >= prior_cwnd);
				}
			}
			else { 
			
			fast_recovery();
			}
		}
	}
	
	free (skb);
//	printf ("Finish--------\n");
	return 0;
}
#endif

