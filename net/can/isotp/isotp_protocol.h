// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright and detailed license information see isotp.c

#ifndef _ISOTP_PROTOCOL_H_
#define _ISOTP_PROTOCOL_H_

#include <linux/socket.h>
#include <net/sock.h>
#include <linux/can.h>
#include <linux/can/isotp.h>

int isotp_sendmsg(struct socket *sock, struct msghdr *msg, size_t size);
void isotp_send_cframe(struct isotp_sock *so);
void isotp_send_fc(struct sock *sk, int ae, u8 flowstatus);
void isotp_rcv_echo(struct sk_buff *skb, void *data);
void isotp_rcv(struct sk_buff *skb, void *skdata);
bool isotp_register_rxid(struct isotp_sock *so);
u8 padlen(u8 datalen);

static inline struct isotp_sock *isotp_sk(const struct sock *sk)
{
	return (struct isotp_sock *)sk;
}

static inline u32 isotp_bc_flags(struct isotp_sock *so)
{
	return so->opt.flags & ISOTP_ALL_BC_FLAGS;
}

/* CAN XL link layer mode is enabled when this flag is set */
static inline bool xlmode(struct isotp_sock *so)
{
	return (so->xl.tx_flags & CANXL_XLF);
}

#endif /* _ISOTP_PROTOCOL_H_ */
