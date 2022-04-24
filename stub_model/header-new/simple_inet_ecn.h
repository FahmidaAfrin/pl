#ifndef __SIMPLE_INET_ECN_H__
#define __SIMPLE_INET_ECN_H__

static inline void INET_ECN_xmit(struct sock *sk)
{
	STUB(1, "the stub function is called !\n");
}

static inline void INET_ECN_dontxmit(struct sock *sk)
{
	STUB(1, "the stub function is called !\n");
}

#endif
