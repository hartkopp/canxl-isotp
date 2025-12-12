This repository contains the proof-of-concept implementation for the next ISO 15765-2:2026(?) standard.

Based on the Linux CAN ISO-TP implementation for CAN CC and CAN FD this development repository aims for the CAN XL support of the protocol.
The code of the latest commit represents the final version which can be potentially applied to the Linux mainline kernel.

But the commits and patches in this repository contain a mixed development history of features, clean-ups, refactoring and fixes.
Therefore the final version code will need some rework to create a new sequence of easy-to-review code changes applicable for Linux upstream development.

The former implementation for CAN CC/FD relied on the struct can\[fd\]_frame which was referenced via pointer in many function calls.
The CAN XL frame structure canxl_frame has the length information and payload data at different postitions/offsets which has a big impact on the function calls.

The development consists of

- move isotp.c into a separate directory to be able to split the already extensive code
- split isotp.c in several code pieces to increase readability and maintainability
- introduce a better skb reference check for echo skbs
- introduce new helpers (e.g. for PCI creation) and defines
- rename variables
- refactor functions to return bool or void
- remove referencing struct canfd_frames and provide a data pointer and a datalen instead
- create helpers to fill and check CAN frame head content
- rework the padding for TX_DL == 8 including CAN XL support
- introduce CAN XL link layer sockopt to pass addresses, VCID, flags, TX_DL

Features of the new CAN XL support:
- configurable TX_DL from 8 to 2048 (linear values)
- Padding (RX/TX) for TX_DL = 8 (legacy feature, routing capability)
- known ISO-TP addressing (RX/TX) in AF field (11/29 bit CAN ID as known in SocketCAN)
- sending and checking (RX/TX) of VCID, CAN XL flags (enables filtering for SEC & RRS bits)
- 11 bit CAN XL priority in sockaddr_can.tp.\[rx\|tx\]_id (former CAN ID addresses)
- SF length encoding in only two PCI bytes (analogue to FF length encoding)

But beware: This implementation only reflects the current state of discussion to evaluate the impact of the CAN XL extension to existing ISO-TP protocol code.
There is not even a draft ISO15765-2:2026 standard document out there.

The CAN XL enabled can-utils tools (isotprecv, isotpsend, isotpserver, isotptun) can be found here:

https://github.com/hartkopp/can-utils/tree/canxl-isotp

Happy testing! Feedback is welcome!

(c)2025 Oliver Hartkopp <socketcan@hartkopp.net>
