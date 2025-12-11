// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright and detailed license information see isotp.c

/* ISO 15765-2 CAN transport protocol for protocol family CAN
 *
 * This implementation does not provide ISO-TP specific return values to the
 * userspace.
 *
 * - RX path timeout of data reception leads to -ETIMEDOUT
 * - RX path SN mismatch leads to -EILSEQ
 * - RX path data reception with wrong padding leads to -EBADMSG
 * - TX path flowcontrol reception timeout leads to -ECOMM
 * - TX path flowcontrol reception overflow leads to -EMSGSIZE
 * - TX path flowcontrol reception with wrong layout/padding leads to -EBADMSG
 * - when a transfer (tx) is on the run the next write() blocks until it's done
 * - use CAN_ISOTP_WAIT_TX_DONE flag to block the caller until the PDU is sent
 * - as we have static buffers the check whether the PDU fits into the buffer
 *   is done at FF reception time (no support for sending 'wait frames')
 */

#include <linux/spinlock.h>
#include <linux/hrtimer.h>
#include <linux/wait.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/can.h>
#include <linux/can/core.h>
#include <linux/can/skb.h>
#include <linux/can/isotp.h>
#include <linux/slab.h>
#include <net/sock.h>
#include "isotp_defines.h"
#include "isotp_protocol.h"

/* can-isotp module parameter, see isotp.c */
extern unsigned int max_pdu_size;

/* calculate CAN protocol specific length for CAN sk_buffs */
static int isotp_tx_skb_len(struct isotp_sock *so, unsigned int datalen)
{
	if (xlmode(so))
		return CANXL_HDR_SIZE + datalen;
	else
		return so->ll.mtu;
}

/* fill CC/FD/XL frame and return the pointer to the frame data section */
static u8 *isotp_fill_frame_head(struct isotp_sock *so, struct sk_buff *skb,
				 unsigned int datalen)
{
	/* all types of CAN frames start at skb->data */
	cu_t *cu = (cu_t *)skb->data;

	/* fill CAN XL frame */
	if (xlmode(so)) {
		cu->xl.prio = so->txid;
		cu->xl.flags = so->xl.tx_flags; /* incl. SEC/RRS */
		cu->xl.af = so->xl.tx_addr;
		cu->xl.len = datalen;
		cu->xl.sdt = CAN_CIA_ISO15765_2_SDT;
		if (so->xl.tx_vcid)
			cu->xl.prio |= (so->xl.tx_vcid << CANXL_VCID_OFFSET);

		return (u8 *)&cu->xl.data;
	}

	/* fill CAN CC/FD frame */
	cu->fd.can_id = so->txid;
	cu->fd.flags = so->ll.tx_flags;
	cu->fd.len = datalen;

	return (u8 *)&cu->fd.data;
}

int isotp_send_fc(struct sock *sk, int ae, u8 flowstatus)
{
	struct net_device *dev;
	struct sk_buff *nskb;
	struct isotp_sock *so = isotp_sk(sk);
	unsigned int datalen = ae + FC_CONTENT_SZ;
	int skblen;
	u8 *data;
	int can_send_ret;

	/* increase skb->len for CAN XL padding with TX_DL=8 only */
	if (xlmode(so) && (so->opt.flags & CAN_ISOTP_TX_PADDING))
		skblen = isotp_tx_skb_len(so, CAN_ISOTP_MIN_TX_DL);
	else
		skblen = isotp_tx_skb_len(so, datalen);

	/* create & send flow control reply */
	nskb = alloc_skb(skblen + sizeof(struct can_skb_priv), gfp_any());
	if (!nskb)
		return 1;

	dev = dev_get_by_index(sock_net(sk), so->ifindex);
	if (!dev) {
		kfree_skb(nskb);
		return 1;
	}

	can_skb_reserve(nskb);
	can_skb_prv(nskb)->ifindex = dev->ifindex;
	can_skb_prv(nskb)->skbcnt = 0;

	nskb->dev = dev;
	can_skb_set_owner(nskb, sk);
	skb_put_zero(nskb, skblen);

	if (so->opt.flags & CAN_ISOTP_TX_PADDING)
		datalen = CAN_ISOTP_MIN_TX_DL;

	/* fill CAN frame and return pointer to CAN frame data */
	data = isotp_fill_frame_head(so, nskb, datalen);

	if (so->opt.flags & CAN_ISOTP_TX_PADDING)
		memset(data, so->opt.txpad_content, CAN_ISOTP_MIN_TX_DL);

	*(data + ae) = N_PCI_FC | flowstatus;
	*(data + ae + 1) = so->rxfc.bs;
	*(data + ae + 2) = so->rxfc.stmin;

	if (ae)
		*(data) = so->opt.ext_address;

	can_send_ret = can_send(nskb, 1);
	if (can_send_ret)
		pr_notice_once("can-isotp: %s: can_send_ret %pe\n",
			       __func__, ERR_PTR(can_send_ret));

	dev_put(dev);

	/* reset blocksize counter */
	so->rx.bs = 0;

	/* reset last CF frame rx timestamp for rx stmin enforcement */
	so->lastrxcf_tstamp = ktime_set(0, 0);

	/* start rx timeout watchdog */
	hrtimer_start(&so->rxtimer, ktime_set(ISOTP_FC_TIMEOUT, 0),
		      HRTIMER_MODE_REL_SOFT);
	return 0;
}

void isotp_send_cframe(struct isotp_sock *so)
{
	struct sock *sk = &so->sk;
	struct sk_buff *skb;
	struct net_device *dev;
	int ae = (so->opt.flags & CAN_ISOTP_EXTEND_ADDR) ? 1 : 0;
	int pcilen = N_PCI_SZ + ae;
	int space = so->tx.ll_dl - pcilen;
	int num = min_t(int, so->tx.len - so->tx.idx, space);
	unsigned int datalen = num + pcilen;
	int skblen;
	int padlength = 0;
	u8 padval;
	u8 *data;
	int can_send_ret;

	/* increase skb->len for CAN XL padding with TX_DL=8 only */
	if ((num < space) && xlmode(so) &&
	    (so->opt.flags & CAN_ISOTP_TX_PADDING))
		skblen = isotp_tx_skb_len(so, CAN_ISOTP_MIN_TX_DL);
	else
		skblen = isotp_tx_skb_len(so, datalen);

	dev = dev_get_by_index(sock_net(sk), so->ifindex);
	if (!dev)
		return;

	skb = alloc_skb(skblen + sizeof(struct can_skb_priv), GFP_ATOMIC);
	if (!skb) {
		dev_put(dev);
		return;
	}

	can_skb_reserve(skb);
	can_skb_prv(skb)->ifindex = dev->ifindex;
	can_skb_prv(skb)->skbcnt = 0;

	/* set uid in tx skb to identify CF echo frames */
	can_set_skb_uid(skb);

	skb_put_zero(skb, skblen);

	/* increase length for padding of CAN CC/FD frames */
	if (num < space) {
		if (so->opt.flags & CAN_ISOTP_TX_PADDING) {
			/* user requested CC/FD padding (or XL with TX_DL=8) */
			padlength = padlen(datalen);
			datalen = padlength;
			padval = so->opt.txpad_content;
		} else if ((datalen > CAN_ISOTP_MIN_TX_DL) && !xlmode(so)) {
			/* mandatory padding for CAN FD frames */
			padlength = padlen(datalen);
			datalen = padlength;
			padval = CAN_ISOTP_DEFAULT_PAD_CONTENT;
		}
	}

	/* fill CAN frame and return pointer to CAN frame data */
	data = isotp_fill_frame_head(so, skb, datalen);

	if (padlength)
		memset(data, padval, datalen);

	/* copy data behind the PCI */
	memcpy(data + pcilen, so->tx.buf + so->tx.idx, num);
	so->tx.idx += num;

	/* add extended address */
	if (ae)
		*(data) = so->opt.ext_address;

	/* place consecutive frame N_PCI in appropriate index */
	*(data + ae) = N_PCI_CF | so->tx.sn++;

	/* update protocol counters */
	so->tx.sn %= 16;
	so->tx.bs++;

	skb->dev = dev;
	can_skb_set_owner(skb, sk);

	/* cfecho should have been zero'ed by init/isotp_rcv_echo() */
	if (so->cfecho)
		pr_notice_once("can-isotp: cfecho is %08X != 0\n", so->cfecho);

	/* set consecutive frame echo tag */
	so->cfecho = can_skb_prv(skb)->skbcnt;

	/* send frame with local echo enabled */
	can_send_ret = can_send(skb, 1);
	if (can_send_ret) {
		pr_notice_once("can-isotp: %s: can_send_ret %pe\n",
			       __func__, ERR_PTR(can_send_ret));
		if (can_send_ret == -ENOBUFS)
			pr_notice_once("can-isotp: tx queue is full\n");
	}
	dev_put(dev);
}

void isotp_rcv_echo(struct sk_buff *skb, void *data)
{
	struct sock *sk = (struct sock *)data;
	struct isotp_sock *so = isotp_sk(sk);

	/* only handle my own local echo CF/SF skb's (no FF!) */
	if (skb->sk != sk || so->cfecho != can_skb_prv(skb)->skbcnt)
		return;

	/* cancel local echo timeout */
	hrtimer_cancel(&so->txtimer);

	/* local echo skb with consecutive frame has been consumed */
	so->cfecho = 0;

	if (so->tx.idx >= so->tx.len) {
		/* we are done */
		so->tx.state = ISOTP_IDLE;
		wake_up_interruptible(&so->wait);
		return;
	}

	if (so->txfc.bs && so->tx.bs >= so->txfc.bs) {
		/* stop and wait for FC with timeout */
		so->tx.state = ISOTP_WAIT_FC;
		hrtimer_start(&so->txtimer, ktime_set(ISOTP_FC_TIMEOUT, 0),
			      HRTIMER_MODE_REL_SOFT);
		return;
	}

	/* no gap between data frames needed => use burst mode */
	if (!so->tx_gap) {
		/* enable echo timeout handling */
		hrtimer_start(&so->txtimer, ktime_set(ISOTP_ECHO_TIMEOUT, 0),
			      HRTIMER_MODE_REL_SOFT);
		isotp_send_cframe(so);
		return;
	}

	/* start timer to send next consecutive frame with correct delay */
	hrtimer_start(&so->txfrtimer, so->tx_gap, HRTIMER_MODE_REL_SOFT);
}

/* create full FF PCI with optional AE and return the required PCI size */
static int isotp_ff_pci(struct isotp_sock *so, u8 *aepci)
{
	int ae = (so->opt.flags & CAN_ISOTP_EXTEND_ADDR) ? 1 : 0;
	int ff_pci_sz;

	if (ae)
		*(aepci) = so->opt.ext_address;

	/* create N_PCI bytes with 12/32 bit FF_DL data length */
	if (so->tx.len > MAX_12BIT_PDU_SIZE) {
		/* use 32 bit FF_DL notation */
		*(aepci + ae) = N_PCI_FF;
		*(aepci + ae + 1) = 0;
		*(aepci + ae + 2) = (u8)(so->tx.len >> 24) & 0xFFU;
		*(aepci + ae + 3) = (u8)(so->tx.len >> 16) & 0xFFU;
		*(aepci + ae + 4) = (u8)(so->tx.len >> 8) & 0xFFU;
		*(aepci + ae + 5) = (u8)so->tx.len & 0xFFU;
		ff_pci_sz = FF_PCI_SZ32;
	} else {
		/* use 12 bit FF_DL notation */
		*(aepci + ae) = (u8)(so->tx.len >> 8) | N_PCI_FF;
		*(aepci + ae + 1) = (u8)so->tx.len & 0xFFU;
		ff_pci_sz = FF_PCI_SZ12;
	}

	return ff_pci_sz + ae;
}

/* create full SF/FF PCI with optional AE and return the required PCI size */
static unsigned int isotp_sf_ff_pci(struct isotp_sock *so, u8 *aepci)
{
	int ae = (so->opt.flags & CAN_ISOTP_EXTEND_ADDR) ? 1 : 0;
	int aepcilen;

	/* check for shortest SF PCI with 4 bit data length 1 .. 7 */
	if (so->tx.ll_dl == CAN_ISOTP_MIN_TX_DL) {

		if (so->tx.len > so->tx.ll_dl - SF_PCI_SZ4 - ae) {
			/* FF */
			aepcilen = isotp_ff_pci(so, aepci);
		} else {
			if (ae)
				*(aepci) = so->opt.ext_address;

			*(aepci + ae) = (u8)(so->tx.len) | N_PCI_SF;
			aepcilen = SF_PCI_SZ4 + ae;
		}

		return aepcilen;
	}

	/* TX_DL > 8 => CAN CC and CAN XL have the same kind of SF PCI length
	 * extension. So we can check for FF segmentation with SF_PCI_SZ8
	 */
	if (so->tx.len > so->tx.ll_dl - SF_PCI_SZ8 - ae) {
		/* FF */
		aepcilen = isotp_ff_pci(so, aepci);
	} else if (so->tx.len <= CAN_MAX_DLEN - SF_PCI_SZ4 - ae) {
		/* short PDU with CAN CC length information 1 .. 6/7 byte */
		if (ae)
			*(aepci) = so->opt.ext_address;

		*(aepci + ae) = (u8)(so->tx.len) | N_PCI_SF;
		aepcilen = SF_PCI_SZ4 + ae;
	} else {
		if (ae)
			*(aepci) = so->opt.ext_address;

		/* follow 12 bit FF_DL notation for 8/11 bit FD/XL SF DL */
		*(aepci + ae) = (u8)(so->tx.len >> 8) | N_PCI_SF;
		*(aepci + ae + 1) = (u8)so->tx.len & 0xFFU;
		aepcilen = SF_PCI_SZ8 + ae;

		/* set SF length CAN XL flag in XL mode */
		if (xlmode(so))
			*(aepci + ae) |= N_PCI_SF_XL;
	}

	return aepcilen;
}

int isotp_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	struct isotp_sock *so = isotp_sk(sk);
	struct sk_buff *skb;
	struct net_device *dev;
	int ae = (so->opt.flags & CAN_ISOTP_EXTEND_ADDR) ? 1 : 0;
	int wait_tx_done = (so->opt.flags & CAN_ISOTP_WAIT_TX_DONE) ? 1 : 0;
	s64 hrtimer_sec = ISOTP_ECHO_TIMEOUT;
	u8 aepci[1 + FF_PCI_SZ32];
	int aepcilen;
	int space;
	int num;
	int datalen;
	int skblen;
	int padlength = 0;
	u8 padval;
	u8 *data;
	int err;

	if (!so->bound || so->tx.state == ISOTP_SHUTDOWN)
		return -EADDRNOTAVAIL;

	while (cmpxchg(&so->tx.state, ISOTP_IDLE, ISOTP_SENDING) != ISOTP_IDLE) {
		/* we do not support multiple buffers - for now */
		if (msg->msg_flags & MSG_DONTWAIT)
			return -EAGAIN;

		if (so->tx.state == ISOTP_SHUTDOWN)
			return -EADDRNOTAVAIL;

		/* wait for complete transmission of current pdu */
		err = wait_event_interruptible(so->wait, so->tx.state == ISOTP_IDLE);
		if (err)
			goto err_event_drop;
	}

	/* PDU size > default => try max_pdu_size */
	if (size > so->tx.buflen && so->tx.buflen < max_pdu_size) {
		u8 *newbuf = kmalloc(max_pdu_size, GFP_KERNEL);

		if (newbuf) {
			so->tx.buf = newbuf;
			so->tx.buflen = max_pdu_size;
		}
	}

	if (!size || size > so->tx.buflen) {
		err = -EINVAL;
		goto err_out_drop;
	}

	err = memcpy_from_msg(so->tx.buf, msg, size);
	if (err < 0)
		goto err_out_drop;

	so->tx.len = size;
	so->tx.idx = 0;

	aepcilen = isotp_sf_ff_pci(so, aepci);
	space = so->tx.ll_dl - aepcilen;
	num = min_t(int, size, space);
	datalen = num + aepcilen;

	/* increase skb->len for CAN XL padding with TX_DL=8 only */
	if ((num < space) && xlmode(so) &&
	    (so->opt.flags & CAN_ISOTP_TX_PADDING))
		skblen = isotp_tx_skb_len(so, CAN_ISOTP_MIN_TX_DL);
	else
		skblen = isotp_tx_skb_len(so, datalen);

	dev = dev_get_by_index(sock_net(sk), so->ifindex);
	if (!dev) {
		err = -ENXIO;
		goto err_out_drop;
	}

	skb = sock_alloc_send_skb(sk, skblen + sizeof(struct can_skb_priv),
				  msg->msg_flags & MSG_DONTWAIT, &err);
	if (!skb) {
		dev_put(dev);
		goto err_out_drop;
	}

	can_skb_reserve(skb);
	can_skb_prv(skb)->ifindex = dev->ifindex;
	can_skb_prv(skb)->skbcnt = 0;

	/* set uid in tx skb to identify CF echo frames */
	can_set_skb_uid(skb);

	skb_put_zero(skb, skblen);

	/* check for single frame padding (N_PCI_SF = 0) */
	if (!(aepci[ae] & N_PCI_MASK) && (num < space)) {
		if (so->opt.flags & CAN_ISOTP_TX_PADDING) {
			/* user requested CC/FD padding (or XL with TX_DL=8) */
			padlength = padlen(datalen);
			datalen = padlength;
			padval = so->opt.txpad_content;
		} else if ((datalen > CAN_ISOTP_MIN_TX_DL) && !xlmode(so)) {
			/* mandatory padding for CAN FD frames */
			padlength = padlen(datalen);
			datalen = padlength;
			padval = CAN_ISOTP_DEFAULT_PAD_CONTENT;
		}
	}

	/* fill CAN frame and return pointer to CAN frame data */
	data = isotp_fill_frame_head(so, skb, datalen);

	/* cfecho should have been zero'ed by init / former isotp_rcv_echo() */
	if (so->cfecho)
		pr_notice_once("can-isotp: uninit cfecho %08X\n", so->cfecho);

	/* check for single frame (N_PCI_SF = 0) */
	if (!(aepci[ae] & N_PCI_MASK)) {
		if (padlength)
			memset(data, padval, datalen);

		/* copy AE and PCI information */
		memcpy(data, aepci, aepcilen);

		/* copy data behind AE and PCI information */
		memcpy(data + aepcilen, so->tx.buf, size);
		so->tx.idx += size;

		/* set CF echo tag for isotp_rcv_echo() (SF-mode) */
		so->cfecho = can_skb_prv(skb)->skbcnt;
	} else {
		/* first frame of this sequence */
		so->tx.sn = 1;

		/* copy AE and PCI information */
		memcpy(data, aepci, aepcilen);

		/* copy data behind AE and PCI information */
		memcpy(data + aepcilen, so->tx.buf, so->tx.ll_dl - aepcilen);

		so->tx.idx += so->tx.ll_dl - aepcilen;

		if (isotp_bc_flags(so) == CAN_ISOTP_CF_BROADCAST) {
			/* set timer for FC-less operation (STmin = 0) */
			if (so->opt.flags & CAN_ISOTP_FORCE_TXSTMIN)
				so->tx_gap = ktime_set(0, so->force_tx_stmin);
			else
				so->tx_gap = ktime_set(0, so->frame_txtime);

			/* disable wait for FCs due to activated block size */
			so->txfc.bs = 0;

			/* set CF echo tag for isotp_rcv_echo() (CF-mode) */
			so->cfecho = can_skb_prv(skb)->skbcnt;
		} else {
			/* standard flow control check */
			so->tx.state = ISOTP_WAIT_FIRST_FC;

			/* start timeout for FC */
			hrtimer_sec = ISOTP_FC_TIMEOUT;

			/* no CF echo tag for isotp_rcv_echo() (FF-mode) */
			so->cfecho = 0;
		}
	}

	hrtimer_start(&so->txtimer, ktime_set(hrtimer_sec, 0),
		      HRTIMER_MODE_REL_SOFT);

	/* send the first or only CAN frame */
	skb->dev = dev;
	skb->sk = sk;
	err = can_send(skb, 1);
	dev_put(dev);
	if (err) {
		pr_notice_once("can-isotp: %s: can_send_ret %pe\n",
			       __func__, ERR_PTR(err));

		/* no transmission -> no timeout monitoring */
		hrtimer_cancel(&so->txtimer);

		/* reset consecutive frame echo tag */
		so->cfecho = 0;

		goto err_out_drop;
	}

	if (wait_tx_done) {
		/* wait for complete transmission of current pdu */
		err = wait_event_interruptible(so->wait, so->tx.state == ISOTP_IDLE);
		if (err)
			goto err_event_drop;

		err = sock_error(sk);
		if (err)
			return err;
	}

	return size;

err_event_drop:
	/* got signal: force tx state machine to be idle */
	so->tx.state = ISOTP_IDLE;
	hrtimer_cancel(&so->txfrtimer);
	hrtimer_cancel(&so->txtimer);
err_out_drop:
	/* drop this PDU and unlock a potential wait queue */
	so->tx.state = ISOTP_IDLE;
	wake_up_interruptible(&so->wait);

	return err;
}
