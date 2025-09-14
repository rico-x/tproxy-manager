#!/bin/sh

SYSCTL_FILE="/etc/sysctl.conf"
TMP_SYSCTL="/tmp/sysctl_owrt_validated.conf"

# Резервная копия
cp "$SYSCTL_FILE" "$SYSCTL_FILE.bak.$(date +%Y%m%d-%H%M%S)"

# Очистим временный файл
echo "# Cleaned sysctl.conf for OpenWrt" > "$TMP_SYSCTL"

# Список параметров с рекомендуемыми значениями
PARAMS="
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.wmem_default=2097152
net.core.netdev_max_backlog=10240
net.core.somaxconn=8192
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=1200
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_max_syn_backlog=10240
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.ip_local_port_range='1024 45000'
"

# Пробуем применить каждый параметр вручную, и только если успех — добавляем в конфиг
echo "$PARAMS" | while IFS= read -r line; do
  param=$(echo "$line" | cut -d= -f1)
  value=$(echo "$line" | cut -d= -f2-)
  if sysctl -w "$param=$value" >/dev/null 2>&1; then
    echo "$param=$value" >> "$TMP_SYSCTL"
  else
    echo "# SKIPPED: $param (not supported)" >> "$TMP_SYSCTL"
  fi
done

# Перезаписываем конфиг безопасным набором
cp "$TMP_SYSCTL" "$SYSCTL_FILE"

# Применяем
sysctl -p

echo "[+] Применено. Все неподдерживаемые параметры исключены."
