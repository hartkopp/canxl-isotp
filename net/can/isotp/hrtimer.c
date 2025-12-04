// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright and detailed license information see isotp.c

#include <linux/hrtimer.h>
#include <linux/wait.h>
#include <net/sock.h>
#include "isotp_defines.h"
#include "isotp_protocol.h"
#include "isotp_hrtimer.h"

enum hrtimer_restart isotp_rx_timer_handler(struct hrtimer *hrtimer)
{
	struct isotp_sock *so = container_of(hrtimer, struct isotp_sock,
					     rxtimer);
	struct sock *sk = &so->sk;

	if (so->rx.state == ISOTP_WAIT_DATA) {
		/* we did not get new data frames in time */

		/* report 'connection timed out' */
		sk->sk_err = ETIMEDOUT;
		if (!sock_flag(sk, SOCK_DEAD))
			sk_error_report(sk);

		/* reset rx state */
		so->rx.state = ISOTP_IDLE;
	}

	return HRTIMER_NORESTART;
}

enum hrtimer_restart isotp_tx_timer_handler(struct hrtimer *hrtimer)
{
	struct isotp_sock *so = container_of(hrtimer, struct isotp_sock,
					     txtimer);
	struct sock *sk = &so->sk;

	/* don't handle timeouts in IDLE or SHUTDOWN state */
	if (so->tx.state == ISOTP_IDLE || so->tx.state == ISOTP_SHUTDOWN)
		return HRTIMER_NORESTART;

	/* we did not get any flow control or echo frame in time */

	/* report 'communication error on send' */
	sk->sk_err = ECOMM;
	if (!sock_flag(sk, SOCK_DEAD))
		sk_error_report(sk);

	/* reset tx state */
	so->tx.state = ISOTP_IDLE;
	wake_up_interruptible(&so->wait);

	return HRTIMER_NORESTART;
}

enum hrtimer_restart isotp_txfr_timer_handler(struct hrtimer *hrtimer)
{
	struct isotp_sock *so = container_of(hrtimer, struct isotp_sock,
					     txfrtimer);

	/* start echo timeout handling and cover below protocol error */
	hrtimer_start(&so->txtimer, ktime_set(ISOTP_ECHO_TIMEOUT, 0),
		      HRTIMER_MODE_REL_SOFT);

	/* cfecho should be consumed by isotp_rcv_echo() here */
	if (so->tx.state == ISOTP_SENDING && !so->cfecho)
		isotp_send_cframe(so);

	return HRTIMER_NORESTART;
}
