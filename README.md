nat46
======

Compiling
=========

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


