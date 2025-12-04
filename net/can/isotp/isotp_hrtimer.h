// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright and detailed license information see isotp.c

#ifndef _ISOTP_HRTIMER_H_
#define _ISOTP_HRTIMER_H_

#include <linux/hrtimer.h>

enum hrtimer_restart isotp_rx_timer_handler(struct hrtimer *hrtimer);
enum hrtimer_restart isotp_tx_timer_handler(struct hrtimer *hrtimer);
enum hrtimer_restart isotp_txfr_timer_handler(struct hrtimer *hrtimer);

#endif /* _ISOTP_HRTIMER_H_ */
