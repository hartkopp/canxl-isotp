# SPDX-License-Identifier: GPL-2.0
KERNEL_VER := $(shell uname -r)
KERNEL_SRC ?= /lib/modules/$(KERNEL_VER)/build
MOD_DIR ?= net/can
THIS_DIR := $(shell pwd)
SRC_DIR := $(THIS_DIR)/$(MOD_DIR)
DEST_DIR := /lib/modules/$(KERNEL_VER)/$(MOD_DIR)

ifneq ($(EXTRA_CFLAGS),)
MAKE_CMDLINE_OPTS += EXTRA_CFLAGS="$(EXTRA_CFLAGS)"
endif

.PHONY: all clean install uninstall

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC_DIR) $(MAKE_CMDLINE_OPTS) modules

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC_DIR) $(MAKE_CMDLINE_OPTS) clean

install:
	$(MAKE) -C "$(KERNEL_SRC)" M=$(SRC_DIR) $(MAKE_CMDLINE_OPTS) modules_install
ifneq ($(MODPROBE_DIR),)
endif
	depmod -a

uninstall:
	-rmmod $(mod-name)
ifneq ($(MODPROBE_DIR),)
endif
	-rm -f $(dir $(KERNEL_SRC))updates/$(mod-name).*
	depmod -a

