obj-m += mapmint.o
mapmint-objs := mapmint_core.o mapmint_netdev.o
CFLAGS_mapmint.o := -DDEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
