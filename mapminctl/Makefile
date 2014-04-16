#
# Copyright (C) 2013 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=mapminctl
PKG_VERSION:=00001
PKG_RELEASE:=00001

# PKG_SOURCE_URL:=https://github.com/ayourtch/mdpc.git
# PKG_SOURCE_PROTO:=git
# PKG_SOURCE_VERSION:=eef3fc50c380ec165c3ad31be690760887de9d60
# PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz
# PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION)
# PKG_BUILD_DIR:=$(BUILD_DIR)/map-mdpc/$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/mapminctl
  SECTION:=net
  DEPENDS:=+odhcp6c +map-mdpc +kmod-mapmint +iptables-mod-conntrack-extra
  CATEGORY:=Network
  TITLE:=MAPMIN control utility
  MAINTAINER:=Andrew Yourtchenko <ayourtch@gmail.com>
  PKGARCH:=all
endef

define Package/mapminctl/description
  Provides the mapminctl utility to generate the CLI for setting up 
  the mapmin parameters.
endef

define Build/Compile
	$(TARGET_CC) -o $(PKG_BUILD_DIR)/mapminctl \
                ./mapminctl.c 
endef

define Build/Configure
endef

define Package/mapminctl/install
	$(INSTALL_DIR) $(1)/sbin
	mkdir $(1)/mapmin-stuff/
	$(CP) -r ./files/* $(1)/mapmin-stuff/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mapminctl $(1)/sbin/
endef

$(eval $(call BuildPackage,mapminctl))
