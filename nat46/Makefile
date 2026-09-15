#
# Copyright (C) 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=nat46
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/nat46
  DEPENDS:=+kmod-nf-conntrack
  TITLE:=Stateless NAT46 translation kernel module
  SECTION:=kernel
  SUBMENU:=Network Support
  FILES:=$(PKG_BUILD_DIR)/modules/nat46.ko 
endef


define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) -r ./* $(PKG_BUILD_DIR)/
endef


MAKE_KMOD := $(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		PATH="$(TARGET_PATH)" \
		NAT46_VERSION="$(PKG_VERSION)-r$(PKG_RELEASE)" \
		M="$(PKG_BUILD_DIR)/modules"

define Build/Compile
	# Compile the kernel part
	+$(MAKE_KMOD) modules
endef

define KernelPackage/nat46/install
	$(CP) -r ./files/* $(1)/
endef

$(eval $(call KernelPackage,nat46))
