obj-m += nat46.o
nat46-objs := nat46-netdev.o nat46-module.o nat46-core.o nat46-glue.o
CFLAGS_nat46.o := -DDEBUG

NAT46_VERSION ?= 0.1.0
ccflags-y += -DNAT46_VERSION=\"$(NAT46_VERSION)\"

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
