# SPDX-License-Identifier: GPL-2.0-only
include $(TOPDIR)/rules.mk

PKG_NAME:=mtk-tops-accounting
PKG_VERSION:=0.1
PKG_RELEASE:=9
PKG_LICENSE:=GPL-2.0-only
PKGARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/mtk-tops-accounting
  SECTION:=net
  CATEGORY:=Network
  TITLE:=MediaTek TOPS accounting coverage status
  PKGARCH:=all
  DEPENDS:=+jshn +coreutils-timeout
endef

define Package/mtk-tops-accounting/description
  Read bounded software status for the MT7988 TOPS/PPE conntrack accounting
  path. Supplies coverage metadata to traffic applications without adding
  TOPS event counters to WAN or connection byte totals.
endef

define Build/Compile
endef

define Package/mtk-tops-accounting/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/mtk-tops-status $(1)/usr/bin/mtk-tops-status
	$(INSTALL_BIN) ./files/mtk-npu-usage $(1)/usr/bin/mtk-npu-usage
endef

$(eval $(call BuildPackage,mtk-tops-accounting))
