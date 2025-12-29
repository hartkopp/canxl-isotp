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

bool isotp_register_rxid(struct isotp_sock *so)
{
	/* no broadcast modes => register rx_id for FC frame reception */
	return (isotp_bc_flags(so) == 0);
}

static void isotp_rcv_skb(struct sk_buff *skb, struct sock *sk)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)skb->cb;
	enum skb_drop_reason reason;

	BUILD_BUG_ON(sizeof(skb->cb) < sizeof(struct sockaddr_can));

	memset(addr, 0, sizeof(*addr));
	addr->can_family = AF_CAN;
	addr->can_ifindex = skb->dev->ifindex;

	if (sock_queue_rcv_skb_reason(sk, skb, &reason) < 0)
		sk_skb_reason_drop(sk, skb, reason);
}

u8 padlen(u8 datalen)
{
	static const u8 plen[] = {
		8, 8, 8, 8, 8, 8, 8, 8, 8,	/* 0 - 8 */
		12, 12, 12, 12,			/* 9 - 12 */
		16, 16, 16, 16,			/* 13 - 16 */
		20, 20, 20, 20,			/* 17 - 20 */
		24, 24, 24, 24,			/* 21 - 24 */
		32, 32, 32, 32, 32, 32, 32, 32,	/* 25 - 32 */
		48, 48, 48, 48, 48, 48, 48, 48,	/* 33 - 40 */
		48, 48, 48, 48, 48, 48, 48, 48	/* 41 - 48 */
	};

	if (datalen > 48)
		return 64;

	return plen[datalen];
}

/* check for length optimization and return true when the check fails */
static bool chk_optimized_fail(unsigned int datalen, int start_index)
{
	/* for CAN_DL <= 8 the start_index is equal to the CAN_DL as the
	 * padding would start at this point. E.g. if the padding would
	 * start at cf.data[7] datalen has to be 7 to be optimal.
	 * Note: The data[] index starts with zero.
	 */
	if (datalen <= CAN_ISOTP_MIN_TX_DL)
		return (datalen != start_index);

	/* This relation is also valid in the non-linear DLC range, where
	 * we need to take care of the minimal next possible CAN_DL.
	 * The correct check would be (padlen(datalen) != padlen(start_index)).
	 * But as datalen can only take discrete values from 12, .., 64 at this
	 * point the padlen(datalen) is always equal to datalen.
	 */
	return (datalen != padlen(start_index));
}

/* check padding and return true when the check fails */
static bool chk_pad_fail(struct isotp_sock *so, u8 *data, unsigned int datalen,
			 int start_index, u8 content)
{
	int i;

	/* no RX_PADDING value => check length of optimized frame length */
	if (!(so->opt.flags & CAN_ISOTP_RX_PADDING)) {
		if (so->opt.flags & CAN_ISOTP_CHK_PAD_LEN)
			return chk_optimized_fail(datalen, start_index);

		/* no valid test against empty value => ignore frame */
		return true;
	}

	/* check datalength of correctly padded CAN frame */
	if ((so->opt.flags & CAN_ISOTP_CHK_PAD_LEN) &&
	    datalen != padlen(datalen))
		return true;

	/* check padding content */
	if (so->opt.flags & CAN_ISOTP_CHK_PAD_DATA) {
		for (i = start_index; i < datalen; i++)
			if (*(data + i) != content)
				return true;
	}

	return false;
}

static void isotp_rcv_fc(struct isotp_sock *so, u8 *data, unsigned int datalen)
{
	struct sock *sk = &so->sk;
	int ae = (so->opt.flags & CAN_ISOTP_EXTEND_ADDR) ? 1 : 0;

	if (so->tx.state != ISOTP_WAIT_FC &&
	    so->tx.state != ISOTP_WAIT_FIRST_FC)
		return;

	hrtimer_cancel(&so->txtimer);

	if ((datalen < ae + FC_CONTENT_SZ) ||
	    ((so->opt.flags & ISOTP_CHECK_PADDING) &&
	     chk_pad_fail(so, data, datalen, ae + FC_CONTENT_SZ,
			  so->opt.rxpad_content))) {
		/* malformed PDU - report 'not a data message' */
		sk->sk_err = EBADMSG;
		if (!sock_flag(sk, SOCK_DEAD))
			sk_error_report(sk);

		so->tx.state = ISOTP_IDLE;
		wake_up_interruptible(&so->wait);
		return;
	}

	/* get static/dynamic communication params from first/every FC frame */
	if (so->tx.state == ISOTP_WAIT_FIRST_FC ||
	    so->opt.flags & CAN_ISOTP_DYN_FC_PARMS) {
		so->txfc.bs = *(data + ae + 1);
		so->txfc.stmin = *(data + ae + 2);

		/* fix wrong STmin values according spec */
		if (so->txfc.stmin > 0x7F &&
		    (so->txfc.stmin < 0xF1 || so->txfc.stmin > 0xF9))
			so->txfc.stmin = 0x7F;

		so->tx_gap = ktime_set(0, 0);
		/* add transmission time for CAN frame N_As */
		so->tx_gap = ktime_add_ns(so->tx_gap, so->frame_txtime);
		/* add waiting time for consecutive frames N_Cs */
		if (so->opt.flags & CAN_ISOTP_FORCE_TXSTMIN)
			so->tx_gap = ktime_add_ns(so->tx_gap,
						  so->force_tx_stmin);
		else if (so->txfc.stmin < 0x80)
			so->tx_gap = ktime_add_ns(so->tx_gap,
						  so->txfc.stmin * 1000000);
		else
			so->tx_gap = ktime_add_ns(so->tx_gap,
						  (so->txfc.stmin - 0xF0)
						  * 100000);
		so->tx.state = ISOTP_WAIT_FC;
	}

	switch (*(data + ae) & 0x0F) {
	case ISOTP_FC_CTS:
		so->tx.bs = 0;
		so->tx.state = ISOTP_SENDING;
		/* send CF frame and enable echo timeout handling */
		hrtimer_start(&so->txtimer, ktime_set(ISOTP_ECHO_TIMEOUT, 0),
			      HRTIMER_MODE_REL_SOFT);
		isotp_send_cframe(so);
		break;

	case ISOTP_FC_WT:
		/* start timer to wait for next FC frame */
		hrtimer_start(&so->txtimer, ktime_set(ISOTP_FC_TIMEOUT, 0),
			      HRTIMER_MODE_REL_SOFT);
		break;

	case ISOTP_FC_OVFLW:
		/* overflow on receiver side - report 'message too long' */
		sk->sk_err = EMSGSIZE;
		if (!sock_flag(sk, SOCK_DEAD))
			sk_error_report(sk);
		fallthrough;

	default:
		/* stop this tx job */
		so->tx.state = ISOTP_IDLE;
		wake_up_interruptible(&so->wait);
	}
}

static void isotp_rcv_sf(struct sock *sk, u8 *data, unsigned int datalen,
			 int pcilen, struct sk_buff *skb, unsigned int sf_dl)
{
	struct isotp_sock *so = isotp_sk(sk);
	struct sk_buff *nskb;

	hrtimer_cancel(&so->rxtimer);
	so->rx.state = ISOTP_IDLE;

	if (!sf_dl || sf_dl > datalen - pcilen)
		return;

	if ((so->opt.flags & ISOTP_CHECK_PADDING) &&
	    chk_pad_fail(so, data, datalen, pcilen + sf_dl, so->opt.rxpad_content)) {
		/* malformed PDU - report 'not a data message' */
		sk->sk_err = EBADMSG;
		if (!sock_flag(sk, SOCK_DEAD))
			sk_error_report(sk);
		return;
	}

	nskb = alloc_skb(sf_dl, gfp_any());
	if (!nskb)
		return;

	memcpy(skb_put(nskb, sf_dl), data + pcilen, sf_dl);

	nskb->tstamp = skb->tstamp;
	nskb->dev = skb->dev;
	isotp_rcv_skb(nskb, sk);
}

static void isotp_rcv_ff(struct sock *sk, u8 *data, unsigned int datalen)
{
	struct isotp_sock *so = isotp_sk(sk);
	int ae = (so->opt.flags & CAN_ISOTP_EXTEND_ADDR) ? 1 : 0;
	int i;
	int ff_pci_sz;

	hrtimer_cancel(&so->rxtimer);
	so->rx.state = ISOTP_IDLE;

	if (datalen < CAN_ISOTP_MIN_TX_DL)
		return;

	/* get the used sender LL_DL from the (first) CAN frame data length */
	if (xlmode(so))
		so->rx.ll_dl = datalen;
	else
		so->rx.ll_dl = padlen(datalen);

	/* CAN FD: the first frame uses the entire LL_DL length (no padding) */
	if (datalen != so->rx.ll_dl)
		return;

	/* get the FF_DL */
	so->rx.len = (*(data + ae) & 0x0F) << 8;
	so->rx.len += *(data + ae + 1);

	/* Check for FF_DL escape sequence supporting 32 bit PDU length */
	if (so->rx.len) {
		ff_pci_sz = FF_PCI_SZ12;
	} else {
		/* FF_DL = 0 => get real length from next 4 bytes */
		so->rx.len = *(data + ae + 2) << 24;
		so->rx.len += *(data + ae + 3) << 16;
		so->rx.len += *(data + ae + 4) << 8;
		so->rx.len += *(data + ae + 5);
		ff_pci_sz = FF_PCI_SZ32;

		/* unneeded escape sequence => ignore PDU according to spec */
		if (so->rx.len <= MAX_12BIT_PDU_SIZE)
			return;
	}

	/* single FF's are not allowed. rx.len has to require a CF */
	if (so->rx.len + ae + ff_pci_sz <= so->rx.ll_dl)
		return;

	/* PDU size > default => try max_pdu_size */
	if (so->rx.len > so->rx.buflen && so->rx.buflen < max_pdu_size) {
		u8 *newbuf = kmalloc(max_pdu_size, GFP_ATOMIC);

		if (newbuf) {
			so->rx.buf = newbuf;
			so->rx.buflen = max_pdu_size;
		}
	}

	if (so->rx.len > so->rx.buflen) {
		/* send FC frame with overflow status */
		isotp_send_fc(sk, ae, ISOTP_FC_OVFLW);
		return;
	}

	/* copy the first received data bytes */
	so->rx.idx = 0;
	for (i = ae + ff_pci_sz; i < so->rx.ll_dl; i++)
		so->rx.buf[so->rx.idx++] = *(data + i);

	/* initial setup for this pdu reception */
	so->rx.sn = 1;
	so->rx.state = ISOTP_WAIT_DATA;

	/* no creation of flow control frames */
	if (so->opt.flags & CAN_ISOTP_LISTEN_MODE)
		return;

	/* send our first FC frame */
	isotp_send_fc(sk, ae, ISOTP_FC_CTS);
}

static void isotp_rcv_cf(struct sock *sk, u8 *data, unsigned int datalen,
			 struct sk_buff *skb)
{
	struct isotp_sock *so = isotp_sk(sk);
	int ae = (so->opt.flags & CAN_ISOTP_EXTEND_ADDR) ? 1 : 0;
	struct sk_buff *nskb;
	int i;

	if (so->rx.state != ISOTP_WAIT_DATA)
		return;

	/* drop if timestamp gap is less than force_rx_stmin nano secs */
	if (so->opt.flags & CAN_ISOTP_FORCE_RXSTMIN) {
		if (ktime_to_ns(ktime_sub(skb->tstamp, so->lastrxcf_tstamp)) <
		    so->force_rx_stmin)
			return;

		so->lastrxcf_tstamp = skb->tstamp;
	}

	hrtimer_cancel(&so->rxtimer);

	/* CFs are never longer than the FF */
	if (datalen > so->rx.ll_dl)
		return;

	/* CFs have usually the LL_DL length */
	if (datalen < so->rx.ll_dl) {
		/* this is only allowed for the last CF */
		if (so->rx.len - so->rx.idx > so->rx.ll_dl - ae - N_PCI_SZ)
			return;
	}

	if ((*(data + ae) & 0x0F) != so->rx.sn) {
		/* wrong sn detected - report 'illegal byte sequence' */
		sk->sk_err = EILSEQ;
		if (!sock_flag(sk, SOCK_DEAD))
			sk_error_report(sk);

		/* reset rx state */
		so->rx.state = ISOTP_IDLE;
		return;
	}
	so->rx.sn++;
	so->rx.sn %= 16;

	for (i = ae + N_PCI_SZ; i < datalen; i++) {
		so->rx.buf[so->rx.idx++] = *(data + i);
		if (so->rx.idx >= so->rx.len)
			break;
	}

	if (so->rx.idx >= so->rx.len) {
		/* we are done */
		so->rx.state = ISOTP_IDLE;

		if ((so->opt.flags & ISOTP_CHECK_PADDING) &&
		    chk_pad_fail(so, data, datalen, i + 1, so->opt.rxpad_content)) {
			/* malformed PDU - report 'not a data message' */
			sk->sk_err = EBADMSG;
			if (!sock_flag(sk, SOCK_DEAD))
				sk_error_report(sk);
			return;
		}

		nskb = alloc_skb(so->rx.len, gfp_any());
		if (!nskb)
			return;

		memcpy(skb_put(nskb, so->rx.len), so->rx.buf,
		       so->rx.len);

		nskb->tstamp = skb->tstamp;
		nskb->dev = skb->dev;
		isotp_rcv_skb(nskb, sk);
		return;
	}

	/* perform blocksize handling, if enabled */
	if (!so->rxfc.bs || ++so->rx.bs < so->rxfc.bs) {
		/* start rx timeout watchdog */
		hrtimer_start(&so->rxtimer, ktime_set(ISOTP_FC_TIMEOUT, 0),
			      HRTIMER_MODE_REL_SOFT);
		return;
	}

	/* no creation of flow control frames */
	if (so->opt.flags & CAN_ISOTP_LISTEN_MODE)
		return;

	/* we reached the specified blocksize so->rxfc.bs */
	isotp_send_fc(sk, ae, ISOTP_FC_CTS);
}

/* check CC/FD/XL frame and return the pointer to the frame data section */
static u8 *isotp_check_frame_head(struct isotp_sock *so, struct sk_buff *skb,
				  unsigned int *datalen)
{
	/* all types of CAN frames start at skb->data */
	union cfu *cu = (union cfu *)skb->data;

	/* check CAN XL frame */
	if (xlmode(so)) {
		canid_t vcid = cu->xl.prio >> CANXL_VCID_OFFSET;

		if (!can_is_canxl_skb(skb))
			return NULL;

		if ((cu->xl.prio & CANXL_PRIO_MASK) != so->rxid ||
		    cu->xl.flags != so->xl.rx_flags ||
		    cu->xl.af != so->xl.rx_addr ||
		    cu->xl.sdt != CAN_CIA_ISO15765_2_SDT)
			return NULL;

		if ((vcid & CANXL_VCID_VAL_MASK) != so->xl.rx_vcid)
			return NULL;

		*datalen = cu->xl.len;

		return (u8 *)&cu->xl.data;
	}

	/* check CAN CC/FD frame:
	 * Strictly receive only frames with the configured MTU size
	 * => clear separation of CAN2.0 / CAN FD transport channels
	 */
	if (cu->fd.can_id != so->rxid || skb->len != so->ll.mtu)
		return NULL;

	*datalen = cu->fd.len;

	return (u8 *)&cu->fd.data;
}

void isotp_rcv(struct sk_buff *skb, void *skdata)
{
	struct sock *sk = (struct sock *)skdata;
	struct isotp_sock *so = isotp_sk(sk);
	int ae = (so->opt.flags & CAN_ISOTP_EXTEND_ADDR) ? 1 : 0;
	u8 *data;
	unsigned int datalen, sf_dl;
	u8 n_pci_type;

	data = isotp_check_frame_head(so, skb, &datalen);
	if (!data)
		return;

	/* if enabled: check reception of my configured extended address */
	if (ae && *(data) != so->opt.rx_ext_address)
		return;

	n_pci_type = *(data + ae) & N_PCI_MASK;

	/* Make sure the state changes and data structures stay consistent at
	 * CAN frame reception time. This locking is not needed in real world
	 * use cases but the inconsistency can be triggered with syzkaller.
	 */
	spin_lock(&so->rx_lock);

	if (so->opt.flags & CAN_ISOTP_HALF_DUPLEX) {
		/* check rx/tx path half duplex expectations */
		if ((so->tx.state != ISOTP_IDLE && n_pci_type != N_PCI_FC) ||
		    (so->rx.state != ISOTP_IDLE && n_pci_type == N_PCI_FC))
			goto out_unlock;
	}

	switch (n_pci_type) {
	case N_PCI_FC:
		/* tx path: flow control frame containing the FC parameters */
		isotp_rcv_fc(so, data, datalen);
		break;

	case N_PCI_SF:
		/* rx path: single frame
		 *
		 * As we do not have a rx.ll_dl configuration, we can only test
		 * if the CAN frames payload length matches the LL_DL == 8
		 * requirements - no matter if it's CAN 2.0 or CAN FD or CAN XL
		 */

		/* get the SF_DL from the N_PCI byte */
		sf_dl = *(data + ae) & 0x0F;

		if (datalen <= CAN_MAX_DLEN) {
			isotp_rcv_sf(sk, data, datalen,
				     SF_PCI_SZ4 + ae, skb, sf_dl);
		} else {
			if (xlmode(so)) {
				/* isotp_check_frame_head() checked the rest */
				if (sf_dl & N_PCI_SF_XL) {
					/* use the low nibble content of N_PCI byte */
					sf_dl &= 7;
					sf_dl <<= 8;
					/* add low byte of SF data length */
					sf_dl |= *(data + SF_PCI_SZ4 + ae);
					isotp_rcv_sf(sk, data, datalen,
						     SF_PCI_SZ8 + ae, skb, sf_dl);
				}
			} else if (can_is_canfd_skb(skb)) {
				/* We have a CAN FD frame and CAN_DL is greater than 8:
				 * Only frames with the SF_DL == 0 ESC value are valid.
				 *
				 * If so take care of the increased SF PCI size
				 * (SF_PCI_SZ8) to point to the message content behind
				 * the extended SF PCI info and get the real SF_DL
				 * length value from the formerly first data byte.
				 */
				if (sf_dl == 0) {
					sf_dl = *(data + SF_PCI_SZ4 + ae);
					isotp_rcv_sf(sk, data, datalen,
						     SF_PCI_SZ8 + ae, skb, sf_dl);
				}
			}
		}
		break;

	case N_PCI_FF:
		/* rx path: first frame */
		isotp_rcv_ff(sk, data, datalen);
		break;

	case N_PCI_CF:
		/* rx path: consecutive frame */
		isotp_rcv_cf(sk, data, datalen, skb);
		break;
	}

out_unlock:
	spin_unlock(&so->rx_lock);
}
