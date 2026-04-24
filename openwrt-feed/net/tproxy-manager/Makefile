include $(TOPDIR)/rules.mk

PKG_NAME:=tproxy-manager
PKG_VERSION:=0.0.0~git
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=Rico-X <ricox.sp@gmail.com>
PKG_BUILD_PARALLEL:=1
PKGARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/tproxy-manager
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=TPROXY Manager for OpenWrt
  URL:=https://github.com/rico-x/tproxy-manager
  DEPENDS:= \
	+busybox \
	+ca-bundle \
	+curl \
	+ip-full \
	+kmod-nft-socket \
	+kmod-nft-tproxy \
	+kmod-tcp-bbr \
	+lua \
	+luci-base \
	+luci-compat \
	+luci-lib-ip \
	+luci-lib-jsonc \
	+uci
endef

define Package/tproxy-manager/description
 TPROXY Manager provides a LuCI UI and runtime scripts for nftables-based
 transparent proxying, Xray and Mihomo management, GEO database updates,
 and VLESS watchdog failover on OpenWrt.
endef

define Build/Compile
endef

define Package/tproxy-manager/install
	$(INSTALL_DIR) $(1)
	$(CP) ./files/. $(1)/
endef

define Package/tproxy-manager/postinst
#!/bin/sh
# postinst for tproxy-manager
# - выполняет uci-defaults (создание /etc/tproxy-manager/* и UCI-значений, только если отсутствуют)
# - безопасно запускает /usr/bin/optimize-sysctl.sh и /usr/bin/setup-bbr.sh (ошибки игнорируются)
# - включает и стартует сервис /etc/init.d/tproxy-manager, если есть

[ -n "$$IPKG_INSTROOT" ] && exit 0

LOGTAG="tproxy-manager-postinst"

if [ -d /etc/uci-defaults ]; then
  for f in /etc/uci-defaults/*tproxy_manager*; do
    [ -f "$$f" ] || continue
    ( . "$$f" ) >"/tmp/$$(basename "$$f").log" 2>&1 \
      || logger -t "$$LOGTAG" "uci-defaults $$(basename "$$f") exited non-zero (ignored)"
    rm -f "$$f"
  done
fi

run_safe() {
  _s="$$1"
  if [ -x "$$_s" ]; then
    /bin/sh "$$_s" >"/tmp/$$(basename "$$_s").postinst.log" 2>&1 \
      || logger -t "$$LOGTAG" "$$(basename "$$_s") exited non-zero (ignored)"
  fi
}
run_safe /usr/bin/optimize-sysctl.sh
run_safe /usr/bin/setup-bbr.sh

chmod +x /etc/init.d/tproxy-manager 2>/dev/null || true
chmod +x /etc/init.d/tproxy-manager-watchdog 2>/dev/null || true
chmod +x /usr/bin/vless2json.sh 2>/dev/null || true

if [ -x /etc/init.d/tproxy-manager ]; then
  /etc/init.d/tproxy-manager enable >/dev/null 2>&1 \
    || logger -t "$$LOGTAG" "enable failed (ignored)"
  /etc/init.d/tproxy-manager start >/dev/null 2>&1 \
    || logger -t "$$LOGTAG" "start failed (ignored)"
fi

exit 0
endef

define Package/tproxy-manager/prerm
#!/bin/sh
[ "$$PKG_UPGRADE" = "1" ] && exit 0
if [ -x /etc/init.d/tproxy-manager ]; then
  /etc/init.d/tproxy-manager stop
  /etc/init.d/tproxy-manager disable
fi
if [ -x /etc/init.d/tproxy-manager-watchdog ]; then
  /etc/init.d/tproxy-manager-watchdog stop
  /etc/init.d/tproxy-manager-watchdog disable
fi
exit 0
endef

$(eval $(call BuildPackage,tproxy-manager))
