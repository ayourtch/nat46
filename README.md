nat46
=====

This is an OpenWRT feed with a Linux kernel module implementing flexible NAT46.

Compiling
=========

Since [4856fa3](https://github.com/openwrt/openwrt/commit/4856fa30a6c6b6fca5e036a226e3e4658105d9c7)
was merged, nat46 can be built by selecting the corresponding option under:

 * Kernel modules -> Network Support -> kmod-nat46

Managing
========

The management of the NAT46 interfaces is done via the /proc/net/nat46/control file.

For more information about the module, take a look at the nat46/modules/README file.


