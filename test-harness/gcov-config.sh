#!/bin/sh
# gcov-config.sh — GCOV kernel configuration for nat46 coverage testing
# Sourced by both the local run-gcov-ci script and the GitHub Actions workflow.
# Usage: . ./gcov-config.sh  (from the kernel source tree root, after defconfig)

set -e

make defconfig
make kvm_guest.config

# GCOV for coverage profiling of the nat46 module
# CONFIG_GCOV_KERNEL enables the gcov infrastructure (debugfs entries at /sys/kernel/debug/gcov/)
# We do NOT enable CONFIG_GCOV_PROFILE_ALL — that would profile all kernel built-in code (expensive).
# Instead, we compile only the nat46 module with GCOV flags (via KCFLAGS).
scripts/config --enable CONFIG_DEBUG_FS
scripts/config --enable CONFIG_GCOV_KERNEL

# Networking and IPv6
scripts/config --enable CONFIG_NET
scripts/config --enable CONFIG_INET
scripts/config --enable CONFIG_IPV6
scripts/config --module CONFIG_NF_DEFRAG_IPV6
scripts/config --enable CONFIG_PACKET

# TUN/TAP for packet injection
scripts/config --enable CONFIG_TUN

# 9P filesystem for host filesystem access (built-in, so insmod not needed)
scripts/config --enable CONFIG_NETFS_SUPPORT
scripts/config --enable CONFIG_9P_FS
scripts/config --enable CONFIG_9P_FS_POSIX_ACL
scripts/config --enable CONFIG_NET_9P
scripts/config --enable CONFIG_NET_9P_VIRTIO

# Virtio for QEMU
scripts/config --enable CONFIG_VIRTIO
scripts/config --enable CONFIG_VIRTIO_PCI
scripts/config --enable CONFIG_VIRTIO_BLK
scripts/config --enable CONFIG_VIRTIO_NET
scripts/config --enable CONFIG_VIRTIO_CONSOLE

# Filesystem support
scripts/config --enable CONFIG_EXT4_FS
scripts/config --enable CONFIG_PROC_FS
scripts/config --enable CONFIG_SYSFS
scripts/config --enable CONFIG_TMPFS
scripts/config --enable CONFIG_DEVTMPFS
scripts/config --enable CONFIG_DEVTMPFS_MOUNT

# Module loading (for nat46.ko)
scripts/config --enable CONFIG_MODULES
scripts/config --enable CONFIG_MODULE_UNLOAD

# Disable module compression
scripts/config --disable CONFIG_MODULE_COMPRESS_GZIP
scripts/config --disable CONFIG_MODULE_COMPRESS_XZ
scripts/config --disable CONFIG_MODULE_COMPRESS_ZSTD

# Disable things that cause issues
scripts/config --disable CONFIG_RANDOMIZE_BASE
scripts/config --disable CONFIG_SYSTEM_TRUSTED_KEYRING
scripts/config --disable CONFIG_MODULE_SIG_ALL

# Disable -Werror
scripts/config --disable CONFIG_WERROR

make olddefconfig
