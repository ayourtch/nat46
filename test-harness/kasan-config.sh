#!/bin/sh
# kasan-config.sh — KASAN kernel configuration options for nat46 test harness
# Sourced by both the local run-kasan-ci script and the GitHub Actions workflow.
# Usage: . ./kasan-config.sh  (from the kernel source tree root, after defconfig)

set -e

make defconfig
make kvm_guest.config

# KASAN for out-of-bounds/use-after-free detection
scripts/config --enable CONFIG_KASAN
scripts/config --enable CONFIG_KASAN_GENERIC
scripts/config --enable CONFIG_KASAN_INLINE
# Keep stack instrumentation explicit even where KASAN_GENERIC selects it by
# default, so the checked-in configuration states the intended coverage.
scripts/config --enable CONFIG_KASAN_STACK

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

# Disable module compression (test harness expects .ko files)
scripts/config --disable CONFIG_MODULE_COMPRESS_GZIP
scripts/config --disable CONFIG_MODULE_COMPRESS_XZ
scripts/config --disable CONFIG_MODULE_COMPRESS_ZSTD

# Disable things that cause issues
scripts/config --disable CONFIG_RANDOMIZE_BASE
scripts/config --disable CONFIG_SYSTEM_TRUSTED_KEYRING
scripts/config --disable CONFIG_MODULE_SIG_ALL

# Disable -Werror (CONFIG_WERROR forces -Werror, which fails on
# missing-prototype warnings in newer kernels)
scripts/config --disable CONFIG_WERROR

make olddefconfig
