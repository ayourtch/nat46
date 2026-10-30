obj-m += nat46.o
nat46-objs := nat46-netdev.o nat46-module.o nat46-core.o nat46-glue.o
CFLAGS_nat46.o := -DDEBUG

ccflags-y += -Wno-date-time

ifneq ($(KERNELRELEASE),)
# Detect net_device::netns_immutable (renamed from netns_local, backported to some 6.12.y)
NAT46_PROBE_NETNS = printf '\#include <linux/netdevice.h>\nvoid f(struct net_device *d) { d->netns_immutable = 1; }\n'

ccflags-y += $(call try-run,\
	$(NAT46_PROBE_NETNS) | $(CC) $(KBUILD_CPPFLAGS) $(KBUILD_CFLAGS) $(LINUXINCLUDE) -x c -c -o "$$TMP" -,\
	-DNAT46_HAVE_NETNS_IMMUTABLE,)
endif

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
