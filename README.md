nat46
=====

This is an OpenWRT feed with a Linux kernel module implementing flexible NAT46.

Compiling
=========

The module by default uses procfs for communication between the user and kernel space.
To use Netlink sockets instead, add the following to nat46/nat46/modules/Makefile
when compiling:
```
EXTRA_CFLAGS += -DPROTO_NETLINK
```

With Barrier Breaker (trunk), add the following line to *feeds.conf.default*:
```
src-git nat46 https://github.com/ayourtch/nat46.git
```

then issue:

```
./scripts/feeds update -a
./scripts/feeds install -a -p nat46
```

This will cause the following to appear in the "make menuconfig":

 * Kernel modules -> Network Support -> kmod-nat46

Managing
========

The management of the NAT46 interfaces is done via the /proc/net/nat46/control file.

For more information about the module, take a look at the nat46/modules/README file.


