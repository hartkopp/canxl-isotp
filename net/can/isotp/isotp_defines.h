// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright and detailed license information see isotp.c

#ifndef _ISOTP_DEFINES_H_
#define _ISOTP_DEFINES_H_

#include <linux/spinlock.h>
#include <linux/hrtimer.h>
#include <linux/wait.h>
#include <linux/can.h>
#include <linux/can/isotp.h>

#define ISOTP_MIN_NAMELEN CAN_REQUIRED_SIZE(struct sockaddr_can, can_addr.tp)

#define SINGLE_MASK(id) (((id) & CAN_EFF_FLAG) ? \
			 (CAN_EFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG) : \
			 (CAN_SFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG))

/* Since ISO 15765-2:2016 the CAN isotp protocol supports more than 4095
 * byte per ISO PDU as the FF_DL can take full 32 bit values (4 Gbyte).
 * We would need some good concept to handle this between user space and
 * kernel space. For now set the static buffer to something about 8 kbyte
 * to be able to test this new functionality.
 */
#define DEFAULT_MAX_PDU_SIZE 8300

/* maximum PDU size before ISO 15765-2:2016 extension was 4095 */
#define MAX_12BIT_PDU_SIZE 4095

/* limit the isotp pdu size from the optional module parameter to 1MByte */
#define MAX_PDU_SIZE (1025 * 1024U)

/* valid bits that can/must be set in struct canxl_frame.flags */
#define CANXL_FLAGS_MASK (CANXL_XLF | CANXL_RRS | CANXL_SEC)

/* to check for disabled padding options for the CAN XL link layer */
#define CAN_ISOTP_PADDING_MASK (CAN_ISOTP_TX_PADDING | CAN_ISOTP_RX_PADDING | \
				CAN_ISOTP_CHK_PAD_LEN | CAN_ISOTP_CHK_PAD_DATA)

/* CAN CiA 611-1 Service Data Unit Type for ISO 15765-2 */
#define CAN_CIA_ISO15765_2_SDT 0x09

/* N_PCI type values in bits 7-4 of N_PCI bytes */
#define N_PCI_SF 0x00	/* single frame */
#define N_PCI_FF 0x10	/* first frame */
#define N_PCI_CF 0x20	/* consecutive frame */
#define N_PCI_FC 0x30	/* flow control */
#define N_PCI_MASK 0xF0	/* to mask the N_PCI type value */

#define N_PCI_SF_XL 8	/* SF length CAN XL flag (bit 3 of N_PCI low nibble) */

#define N_PCI_SZ 1	/* size of the PCI byte #1 */
#define SF_PCI_SZ4 1	/* size of SingleFrame PCI including 4 bit SF_DL */
#define SF_PCI_SZ8 2	/* size of SingleFrame PCI including 8 bit SF_DL */
#define SF_PCI_SZ11 2	/* size of SingleFrame PCI including 11 bit SF_DL */
#define FF_PCI_SZ12 2	/* size of FirstFrame PCI including 12 bit FF_DL */
#define FF_PCI_SZ32 6	/* size of FirstFrame PCI including 32 bit FF_DL */
#define FC_CONTENT_SZ 3	/* flow control content size in byte (FS/BS/STmin) */

#define ISOTP_CHECK_PADDING (CAN_ISOTP_CHK_PAD_LEN | CAN_ISOTP_CHK_PAD_DATA)
#define ISOTP_ALL_BC_FLAGS (CAN_ISOTP_SF_BROADCAST | CAN_ISOTP_CF_BROADCAST)

/* Flow Status given in FC frame */
#define ISOTP_FC_CTS 0		/* clear to send */
#define ISOTP_FC_WT 1		/* wait */
#define ISOTP_FC_OVFLW 2	/* overflow */

#define ISOTP_FC_TIMEOUT 1	/* 1 sec */
#define ISOTP_ECHO_TIMEOUT 2	/* 2 secs */

enum {
	ISOTP_IDLE = 0,
	ISOTP_WAIT_FIRST_FC,
	ISOTP_WAIT_FC,
	ISOTP_WAIT_DATA,
	ISOTP_SENDING,
	ISOTP_SHUTDOWN,
};

struct tpcon {
	u8 *buf;
	unsigned int buflen;
	unsigned int len;
	unsigned int idx;
	u32 state;
	u32 ll_dl;
	u8 bs;
	u8 sn;
	u8 sbuf[DEFAULT_MAX_PDU_SIZE];
};

struct isotp_sock {
	struct sock sk;
	int bound;
	int ifindex;
	canid_t txid;
	canid_t rxid;
	ktime_t tx_gap;
	ktime_t lastrxcf_tstamp;
	struct hrtimer rxtimer, txtimer, txfrtimer;
	struct can_isotp_options opt;
	struct can_isotp_fc_options rxfc, txfc;
	struct can_isotp_ll_options ll;
	struct can_isotp_xl_options xl;
	u32 frame_txtime;
	u32 force_tx_stmin;
	u32 force_rx_stmin;
	int cfecho; /* consecutive frame echo tag */
	struct tpcon rx, tx;
	struct list_head notifier;
	wait_queue_head_t wait;
	spinlock_t rx_lock; /* protect single thread state machine */
};

/* CAN CC/FD/XL frame union */
typedef union {
	struct can_frame cc;
	struct canfd_frame fd;
	struct canxl_frame xl;
} cu_t;

#endif /* _ISOTP_DEFINES_H_ */
