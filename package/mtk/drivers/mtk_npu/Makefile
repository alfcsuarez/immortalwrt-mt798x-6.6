# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2025 MediaTek Inc. All Rights Reserved.
# Author: Ren-Ting Wang <ren-ting.wang@mediatek.com>
#
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=mtk_npu
PKG_RELEASE:=8
PKG_BUILD_DEPENDS:=pce
PKG_FILE_DEPENDS:=$(CURDIR)/src/
SCAN_DEPS = *.mk Config*.in

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/package-defaults.mk

NPU_KERNEL_PKGS:=
NPU_PKGS:=

include npu.mk
include $(filter-out npu.mk,$(wildcard *.mk))

PKG_CONFIG_DEPENDS += $(sort \
	$(foreach option,$(EXTRA_KCONFIG),$(firstword $(subst =, ,$(option)))) \
	$(foreach package,$(NPU_KERNEL_PKGS),CONFIG_PACKAGE_kmod-$(package)) \
	CONFIG_MTK_NPU_24_10_TUNNEL_BACKEND CONFIG_MTK_NPU_24_10_MCAST_BACKEND \
	CONFIG_MTK_NPU_24_10_FLOW_BACKEND CONFIG_MTK_NPU_24_10_DPDK_BACKEND \
	CONFIG_MTK_NPU_REBB_SUPPORT CONFIG_MTK_NPU_PPP_SOCKET \
	CONFIG_MTK_NPU_DPDK_MAC_FILTER_NUM \
	CONFIG_NPU_TNL_NUM CONFIG_NPU_TNL_MAP_BIT CONFIG_NPU_TNL_TYPE_NUM)

EXTRA_CFLAGS+= \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=m,%,$(filter %=m,$(EXTRA_KCONFIG)))) \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=y,%,$(filter %=y,$(EXTRA_KCONFIG))))

EXTRA_CFLAGS+= \
	-Wall -Werror

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/usr/include/npu
	$(CP) $(PKG_BUILD_DIR)/inc/* $(STAGING_DIR)/usr/include/npu/
	$(CP) $(PKG_BUILD_DIR)/protocol/inc/* $(STAGING_DIR)/usr/include/npu/
	$(CP) $(PKG_BUILD_DIR)/npu-dpdk/inc/* $(STAGING_DIR)/usr/include/npu/
	$(CP) $(PKG_BUILD_DIR)/npu-flow/inc/* $(STAGING_DIR)/usr/include/npu/
	$(CP) $(PKG_BUILD_DIR)/npu-nf_hnat/inc/* $(STAGING_DIR)/usr/include/npu/
	$(CP) $(PKG_BUILD_DIR)/npu-mcast/inc/* $(STAGING_DIR)/usr/include/npu/
endef

define Build/Compile
	$(if $(filter y,$(CONFIG_MTK_NPU_24_10_TUNNEL_BACKEND)),\
		$(if $(filter y,$(CONFIG_MTK_NPU_HNAT)),true,\
			$(error NPU HNAT mode requires kmod-npu-nf_hnat)))
	$(if $(filter y,$(CONFIG_MTK_NPU_24_10_MCAST_BACKEND)),\
		$(if $(filter y,$(CONFIG_MTK_NPU_MCAST)),true,\
			$(error NPU multicast mode requires kmod-npu-mcast)))
	$(if $(filter y,$(CONFIG_MTK_NPU_24_10_DPDK_BACKEND)),\
		$(if $(filter y,$(CONFIG_MTK_NPU_DPDK)),true,\
			$(error NPU DPDK mode requires kmod-npu-dpdk)))
	$(if $(filter y,$(CONFIG_MTK_NPU_24_10_FLOW_BACKEND)),\
		$(if $(filter y,$(CONFIG_MTK_NPU_FLOW)),true,\
			$(error Native NPU FLOW requires kmod-npu-flow with vendor HNAT disabled)))
	$(if $(filter y,$(CONFIG_MTK_NPU_FLOW)),\
		grep -q '^CONFIG_NET_MEDIATEK_NPU_FLOW=y' "$(LINUX_DIR)/.config" && \
		! grep -q '^CONFIG_NET_MEDIATEK_HNAT=[ym]' "$(LINUX_DIR)/.config")
	$(MAKE) -C "$(LINUX_DIR)" \
		$(KERNEL_MAKE_FLAGS) \
		M="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		$(EXTRA_KCONFIG) \
		modules
endef

$(foreach KERNEL_PKG,$(NPU_KERNEL_PKGS),$(eval $(call KernelPackage,$(KERNEL_PKG))))
$(foreach PKG,$(NPU_PKGS),$(eval $(call BuildPackage,$(PKG))))
