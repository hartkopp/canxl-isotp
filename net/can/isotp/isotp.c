// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/* isotp.c - ISO 15765-2 CAN transport protocol for protocol family CAN
 *
 * Copyright (c) 2020 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * The provided data structures and external interfaces from this code
 * are not restricted to be used by modules with a GPL compatible license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/hrtimer.h>
#include <linux/wait.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/can.h>
#include <linux/can/core.h>
#include <linux/can/isotp.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include "isotp_defines.h"
#include "isotp_protocol.h"
#include "isotp_hrtimer.h"

MODULE_DESCRIPTION("PF_CAN ISO 15765-2 transport protocol");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Oliver Hartkopp <socketcan@hartkopp.net>");
MODULE_ALIAS("can-proto-6");

unsigned int max_pdu_size __read_mostly = DEFAULT_MAX_PDU_SIZE;
module_param(max_pdu_size, uint, 0444);
MODULE_PARM_DESC(max_pdu_size, "maximum isotp pdu size (default "
		 __stringify(DEFAULT_MAX_PDU_SIZE) ")");

static LIST_HEAD(isotp_notifier_list);
static DEFINE_SPINLOCK(isotp_notifier_lock);
static struct isotp_sock *isotp_busy_notifier;

static int isotp_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
			 int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	struct isotp_sock *so = isotp_sk(sk);
	int ret = 0;

	if (flags & ~(MSG_DONTWAIT | MSG_TRUNC | MSG_PEEK | MSG_CMSG_COMPAT))
		return -EINVAL;

	if (!so->bound)
		return -EADDRNOTAVAIL;

	skb = skb_recv_datagram(sk, flags, &ret);
	if (!skb)
		return ret;

	if (size < skb->len)
		msg->msg_flags |= MSG_TRUNC;
	else
		size = skb->len;

	ret = memcpy_to_msg(msg, skb->data, size);
	if (ret < 0)
		goto out_err;

	sock_recv_cmsgs(msg, sk, skb);

	if (msg->msg_name) {
		__sockaddr_check_size(ISOTP_MIN_NAMELEN);
		msg->msg_namelen = ISOTP_MIN_NAMELEN;
		memcpy(msg->msg_name, skb->cb, msg->msg_namelen);
	}

	/* set length of return value */
	ret = (flags & MSG_TRUNC) ? skb->len : size;

out_err:
	skb_free_datagram(sk, skb);

	return ret;
}

static int isotp_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct isotp_sock *so;
	struct net *net;

	if (!sk)
		return 0;

	so = isotp_sk(sk);
	net = sock_net(sk);

	/* wait for complete transmission of current pdu */
	while (wait_event_interruptible(so->wait, so->tx.state == ISOTP_IDLE) == 0 &&
	       cmpxchg(&so->tx.state, ISOTP_IDLE, ISOTP_SHUTDOWN) != ISOTP_IDLE)
		;

	/* force state machines to be idle also when a signal occurred */
	so->tx.state = ISOTP_SHUTDOWN;
	so->rx.state = ISOTP_IDLE;

	spin_lock(&isotp_notifier_lock);
	while (isotp_busy_notifier == so) {
		spin_unlock(&isotp_notifier_lock);
		schedule_timeout_uninterruptible(1);
		spin_lock(&isotp_notifier_lock);
	}
	list_del(&so->notifier);
	spin_unlock(&isotp_notifier_lock);

	lock_sock(sk);

	/* remove current filters & unregister */
	if (so->bound) {
		if (so->ifindex) {
			struct net_device *dev;

			dev = dev_get_by_index(net, so->ifindex);
			if (dev) {
				if (isotp_register_rxid(so))
					can_rx_unregister(net, dev, so->rxid,
							  SINGLE_MASK(so->rxid),
							  isotp_rcv, sk);

				can_rx_unregister(net, dev, so->txid,
						  SINGLE_MASK(so->txid),
						  isotp_rcv_echo, sk);
				dev_put(dev);
				synchronize_rcu();
			}
		}
	}

	hrtimer_cancel(&so->txfrtimer);
	hrtimer_cancel(&so->txtimer);
	hrtimer_cancel(&so->rxtimer);

	so->ifindex = 0;
	so->bound = 0;

	if (so->rx.buf != so->rx.sbuf)
		kfree(so->rx.buf);

	if (so->tx.buf != so->tx.sbuf)
		kfree(so->tx.buf);

	sock_orphan(sk);
	sock->sk = NULL;

	release_sock(sk);
	sock_prot_inuse_add(net, sk->sk_prot, -1);
	sock_put(sk);

	return 0;
}

static bool isotp_invalid_canid(canid_t canid)
{
	canid_t sanitized_id = canid;

	/* sanitize CAN identifier */
	if (sanitized_id & CAN_EFF_FLAG)
		sanitized_id &= (CAN_EFF_FLAG | CAN_EFF_MASK);
	else
		sanitized_id &= CAN_SFF_MASK;

	/* give feedback on wrong CAN-ID value */
	if (sanitized_id != canid)
		return true;

	return false;
}

static int isotp_bind(struct socket *sock, struct sockaddr_unsized *uaddr, int len)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct sock *sk = sock->sk;
	struct isotp_sock *so = isotp_sk(sk);
	struct net *net = sock_net(sk);
	int ifindex;
	struct net_device *dev;
	canid_t tx_id = addr->can_addr.tp.tx_id;
	canid_t rx_id = addr->can_addr.tp.rx_id;
	int err = 0;
	int notify_enetdown = 0;

	if (len < ISOTP_MIN_NAMELEN)
		return -EINVAL;

	if (addr->can_family != AF_CAN)
		return -EINVAL;

	/* check for correct tx CAN identifier */
	if (isotp_invalid_canid(tx_id))
		return -EINVAL;

	/* check for correct rx CAN identifier (if needed) */
	if (isotp_register_rxid(so) && isotp_invalid_canid(rx_id))
		return -EINVAL;


	if (so->xl.tx_flags & CANXL_XLF) {
		/* don't enable padding options for CAN XL link layer */
		if (so->opt.flags & CAN_ISOTP_PADDING_MASK)
			return -EINVAL;

		/* CAN XL priority field is only 11 bit */
		if ((tx_id | rx_id) & CAN_EFF_FLAG)
			return -EINVAL;
	}

	if (!addr->can_ifindex)
		return -ENODEV;

	lock_sock(sk);

	if (so->bound) {
		err = -EINVAL;
		goto out;
	}

	/* ensure different CAN IDs when the rx_id is to be registered */
	if (isotp_register_rxid(so) && rx_id == tx_id) {
		err = -EADDRNOTAVAIL;
		goto out;
	}

	dev = dev_get_by_index(net, addr->can_ifindex);
	if (!dev) {
		err = -ENODEV;
		goto out;
	}
	if (dev->type != ARPHRD_CAN) {
		dev_put(dev);
		err = -ENODEV;
		goto out;
	}
	if (READ_ONCE(dev->mtu) < so->ll.mtu) {
		dev_put(dev);
		err = -EINVAL;
		goto out;
	}
	if (!(dev->flags & IFF_UP))
		notify_enetdown = 1;

	ifindex = dev->ifindex;

	if (isotp_register_rxid(so))
		can_rx_register(net, dev, rx_id, SINGLE_MASK(rx_id),
				isotp_rcv, sk, "isotp", sk);

	/* no consecutive frame echo skb in flight */
	so->cfecho = 0;

	/* register for echo skb's */
	can_rx_register(net, dev, tx_id, SINGLE_MASK(tx_id),
			isotp_rcv_echo, sk, "isotpe", sk);

	dev_put(dev);

	/* switch to new settings */
	so->ifindex = ifindex;
	so->rxid = rx_id;
	so->txid = tx_id;
	so->bound = 1;

out:
	release_sock(sk);

	if (notify_enetdown) {
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk_error_report(sk);
	}

	return err;
}

static int isotp_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct sock *sk = sock->sk;
	struct isotp_sock *so = isotp_sk(sk);

	if (peer)
		return -EOPNOTSUPP;

	memset(addr, 0, ISOTP_MIN_NAMELEN);
	addr->can_family = AF_CAN;
	addr->can_ifindex = so->ifindex;
	addr->can_addr.tp.rx_id = so->rxid;
	addr->can_addr.tp.tx_id = so->txid;

	return ISOTP_MIN_NAMELEN;
}

static int isotp_setsockopt_locked(struct socket *sock, int level, int optname,
			    sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct isotp_sock *so = isotp_sk(sk);
	int ret = 0;

	if (so->bound)
		return -EISCONN;

	switch (optname) {
	case CAN_ISOTP_OPTS:
		if (optlen != sizeof(struct can_isotp_options))
			return -EINVAL;

		if (copy_from_sockptr(&so->opt, optval, optlen))
			return -EFAULT;

		/* no separate rx_ext_address is given => use ext_address */
		if (!(so->opt.flags & CAN_ISOTP_RX_EXT_ADDR))
			so->opt.rx_ext_address = so->opt.ext_address;

		/* these broadcast flags are not allowed together */
		if (isotp_bc_flags(so) == ISOTP_ALL_BC_FLAGS) {
			/* CAN_ISOTP_SF_BROADCAST is prioritized */
			so->opt.flags &= ~CAN_ISOTP_CF_BROADCAST;

			/* give user feedback on wrong config attempt */
			ret = -EINVAL;
		}

		/* check for frame_txtime changes (0 => no changes) */
		if (so->opt.frame_txtime) {
			if (so->opt.frame_txtime == CAN_ISOTP_FRAME_TXTIME_ZERO)
				so->frame_txtime = 0;
			else
				so->frame_txtime = so->opt.frame_txtime;
		}
		break;

	case CAN_ISOTP_RECV_FC:
		if (optlen != sizeof(struct can_isotp_fc_options))
			return -EINVAL;

		if (copy_from_sockptr(&so->rxfc, optval, optlen))
			return -EFAULT;
		break;

	case CAN_ISOTP_TX_STMIN:
		if (optlen != sizeof(u32))
			return -EINVAL;

		if (copy_from_sockptr(&so->force_tx_stmin, optval, optlen))
			return -EFAULT;
		break;

	case CAN_ISOTP_RX_STMIN:
		if (optlen != sizeof(u32))
			return -EINVAL;

		if (copy_from_sockptr(&so->force_rx_stmin, optval, optlen))
			return -EFAULT;
		break;

	case CAN_ISOTP_LL_OPTS:
		if (optlen == sizeof(struct can_isotp_ll_options)) {
			struct can_isotp_ll_options ll;

			if (copy_from_sockptr(&ll, optval, optlen))
				return -EFAULT;

			/* check for correct ISO 11898-1 DLC data length */
			if (ll.tx_dl != padlen(ll.tx_dl))
				return -EINVAL;

			if (ll.mtu != CAN_MTU && ll.mtu != CANFD_MTU)
				return -EINVAL;

			if (ll.mtu == CAN_MTU &&
			    (ll.tx_dl > CAN_MAX_DLEN || ll.tx_flags != 0))
				return -EINVAL;

			memcpy(&so->ll, &ll, sizeof(ll));

			/* configured CC/FD LL opts -> disable XL LL opts */
			so->xl.tx_flags = 0;

			/* set ll_dl for tx path to similar place as for rx */
			so->tx.ll_dl = ll.tx_dl;
		} else {
			return -EINVAL;
		}
		break;

	case CAN_ISOTP_XL_OPTS:
		if (optlen == sizeof(struct can_isotp_xl_options)) {
			struct can_isotp_xl_options xl;

			if (copy_from_sockptr(&xl, optval, optlen))
				return -EFAULT;

			/* check for correct/required CAN XL flags */
			if (!(xl.tx_flags & CANXL_XLF) ||
			    (xl.tx_flags & ~CANXL_FLAGS_MASK))
				return -EINVAL;

			if (!(xl.rx_flags & CANXL_XLF) ||
			    (xl.rx_flags & ~CANXL_FLAGS_MASK))
				return -EINVAL;

			/* check valid tx_dl range for CAN XL link layer */
			if (xl.tx_dl < CAN_MAX_DLEN || xl.tx_dl > CANXL_MAX_DLEN)
				return -EINVAL;

			/* check for correct CAN identifier */
			if (isotp_invalid_canid(xl.tx_addr))
				return -EINVAL;

			if (isotp_invalid_canid(xl.rx_addr))
				return -EINVAL;

			memcpy(&so->xl, &xl, sizeof(xl));

			/* set ll_dl for tx path to similar place as for rx */
			so->tx.ll_dl = xl.tx_dl;
		} else {
			return -EINVAL;
		}
		break;

	default:
		ret = -ENOPROTOOPT;
	}

	return ret;
}

static int isotp_setsockopt(struct socket *sock, int level, int optname,
			    sockptr_t optval, unsigned int optlen)

{
	struct sock *sk = sock->sk;
	int ret;

	if (level != SOL_CAN_ISOTP)
		return -EINVAL;

	lock_sock(sk);
	ret = isotp_setsockopt_locked(sock, level, optname, optval, optlen);
	release_sock(sk);
	return ret;
}

static int isotp_getsockopt(struct socket *sock, int level, int optname,
			    char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct isotp_sock *so = isotp_sk(sk);
	int len;
	void *val;

	if (level != SOL_CAN_ISOTP)
		return -EINVAL;
	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case CAN_ISOTP_OPTS:
		len = min_t(int, len, sizeof(struct can_isotp_options));
		val = &so->opt;
		break;

	case CAN_ISOTP_RECV_FC:
		len = min_t(int, len, sizeof(struct can_isotp_fc_options));
		val = &so->rxfc;
		break;

	case CAN_ISOTP_TX_STMIN:
		len = min_t(int, len, sizeof(u32));
		val = &so->force_tx_stmin;
		break;

	case CAN_ISOTP_RX_STMIN:
		len = min_t(int, len, sizeof(u32));
		val = &so->force_rx_stmin;
		break;

	case CAN_ISOTP_LL_OPTS:
		len = min_t(int, len, sizeof(struct can_isotp_ll_options));
		val = &so->ll;
		break;

	case CAN_ISOTP_XL_OPTS:
		len = min_t(int, len, sizeof(struct can_isotp_xl_options));
		val = &so->xl;
		break;

	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, val, len))
		return -EFAULT;
	return 0;
}

static void isotp_notify(struct isotp_sock *so, unsigned long msg,
			 struct net_device *dev)
{
	struct sock *sk = &so->sk;

	if (!net_eq(dev_net(dev), sock_net(sk)))
		return;

	if (so->ifindex != dev->ifindex)
		return;

	switch (msg) {
	case NETDEV_UNREGISTER:
		lock_sock(sk);
		/* remove current filters & unregister */
		if (so->bound) {
			if (isotp_register_rxid(so))
				can_rx_unregister(dev_net(dev), dev, so->rxid,
						  SINGLE_MASK(so->rxid),
						  isotp_rcv, sk);

			can_rx_unregister(dev_net(dev), dev, so->txid,
					  SINGLE_MASK(so->txid),
					  isotp_rcv_echo, sk);
		}

		so->ifindex = 0;
		so->bound  = 0;
		release_sock(sk);

		sk->sk_err = ENODEV;
		if (!sock_flag(sk, SOCK_DEAD))
			sk_error_report(sk);
		break;

	case NETDEV_DOWN:
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk_error_report(sk);
		break;
	}
}

static int isotp_notifier(struct notifier_block *nb, unsigned long msg,
			  void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (dev->type != ARPHRD_CAN)
		return NOTIFY_DONE;
	if (msg != NETDEV_UNREGISTER && msg != NETDEV_DOWN)
		return NOTIFY_DONE;
	if (unlikely(isotp_busy_notifier)) /* Check for reentrant bug. */
		return NOTIFY_DONE;

	spin_lock(&isotp_notifier_lock);
	list_for_each_entry(isotp_busy_notifier, &isotp_notifier_list, notifier) {
		spin_unlock(&isotp_notifier_lock);
		isotp_notify(isotp_busy_notifier, msg, dev);
		spin_lock(&isotp_notifier_lock);
	}
	isotp_busy_notifier = NULL;
	spin_unlock(&isotp_notifier_lock);
	return NOTIFY_DONE;
}

static int isotp_init(struct sock *sk)
{
	struct isotp_sock *so = isotp_sk(sk);

	so->ifindex = 0;
	so->bound = 0;

	so->opt.flags = CAN_ISOTP_DEFAULT_FLAGS;
	so->opt.ext_address = CAN_ISOTP_DEFAULT_EXT_ADDRESS;
	so->opt.rx_ext_address = CAN_ISOTP_DEFAULT_EXT_ADDRESS;
	so->opt.rxpad_content = CAN_ISOTP_DEFAULT_PAD_CONTENT;
	so->opt.txpad_content = CAN_ISOTP_DEFAULT_PAD_CONTENT;
	so->opt.frame_txtime = CAN_ISOTP_DEFAULT_FRAME_TXTIME;
	so->frame_txtime = CAN_ISOTP_DEFAULT_FRAME_TXTIME;
	so->rxfc.bs = CAN_ISOTP_DEFAULT_RECV_BS;
	so->rxfc.stmin = CAN_ISOTP_DEFAULT_RECV_STMIN;
	so->rxfc.wftmax = CAN_ISOTP_DEFAULT_RECV_WFTMAX;
	so->ll.mtu = CAN_ISOTP_DEFAULT_LL_MTU;
	so->ll.tx_dl = CAN_ISOTP_DEFAULT_LL_TX_DL;
	so->ll.tx_flags = CAN_ISOTP_DEFAULT_LL_TX_FLAGS;

	/* set ll_dl for tx path to similar place as for rx */
	so->tx.ll_dl = so->ll.tx_dl;

	/* CAN XL link layer options disabled by default */
	so->xl.tx_flags = 0;

	so->rx.state = ISOTP_IDLE;
	so->tx.state = ISOTP_IDLE;

	so->rx.buf = so->rx.sbuf;
	so->tx.buf = so->tx.sbuf;
	so->rx.buflen = ARRAY_SIZE(so->rx.sbuf);
	so->tx.buflen = ARRAY_SIZE(so->tx.sbuf);

	hrtimer_setup(&so->rxtimer, isotp_rx_timer_handler, CLOCK_MONOTONIC, HRTIMER_MODE_REL_SOFT);
	hrtimer_setup(&so->txtimer, isotp_tx_timer_handler, CLOCK_MONOTONIC, HRTIMER_MODE_REL_SOFT);
	hrtimer_setup(&so->txfrtimer, isotp_txfr_timer_handler, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL_SOFT);

	init_waitqueue_head(&so->wait);
	spin_lock_init(&so->rx_lock);

	spin_lock(&isotp_notifier_lock);
	list_add_tail(&so->notifier, &isotp_notifier_list);
	spin_unlock(&isotp_notifier_lock);

	return 0;
}

static __poll_t isotp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct isotp_sock *so = isotp_sk(sk);

	__poll_t mask = datagram_poll(file, sock, wait);
	poll_wait(file, &so->wait, wait);

	/* Check for false positives due to TX state */
	if ((mask & EPOLLWRNORM) && (so->tx.state != ISOTP_IDLE))
		mask &= ~(EPOLLOUT | EPOLLWRNORM);

	return mask;
}

static int isotp_sock_no_ioctlcmd(struct socket *sock, unsigned int cmd,
				  unsigned long arg)
{
	/* no ioctls for socket layer -> hand it down to NIC layer */
	return -ENOIOCTLCMD;
}

static const struct proto_ops isotp_ops = {
	.family = PF_CAN,
	.release = isotp_release,
	.bind = isotp_bind,
	.connect = sock_no_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = isotp_getname,
	.poll = isotp_poll,
	.ioctl = isotp_sock_no_ioctlcmd,
	.gettstamp = sock_gettstamp,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = isotp_setsockopt,
	.getsockopt = isotp_getsockopt,
	.sendmsg = isotp_sendmsg,
	.recvmsg = isotp_recvmsg,
	.mmap = sock_no_mmap,
};

static struct proto isotp_proto __read_mostly = {
	.name = "CAN_ISOTP",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct isotp_sock),
	.init = isotp_init,
};

static const struct can_proto isotp_can_proto = {
	.type = SOCK_DGRAM,
	.protocol = CAN_ISOTP,
	.ops = &isotp_ops,
	.prot = &isotp_proto,
};

static struct notifier_block canisotp_notifier = {
	.notifier_call = isotp_notifier
};

static __init int isotp_module_init(void)
{
	int err;

	max_pdu_size = max_t(unsigned int, max_pdu_size, MAX_12BIT_PDU_SIZE);
	max_pdu_size = min_t(unsigned int, max_pdu_size, MAX_PDU_SIZE);

	pr_info("can: isotp protocol (max_pdu_size %d)\n", max_pdu_size);

	err = can_proto_register(&isotp_can_proto);
	if (err < 0)
		pr_err("can: registration of isotp protocol failed %pe\n", ERR_PTR(err));
	else
		register_netdevice_notifier(&canisotp_notifier);

	return err;
}

static __exit void isotp_module_exit(void)
{
	can_proto_unregister(&isotp_can_proto);
	unregister_netdevice_notifier(&canisotp_notifier);
}

module_init(isotp_module_init);
module_exit(isotp_module_exit);
