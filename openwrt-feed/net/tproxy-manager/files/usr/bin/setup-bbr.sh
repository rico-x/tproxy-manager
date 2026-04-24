#!/bin/sh
# Включение TCP BBR на OpenWrt (24.10.x+)
# - ставит kmod-tcp-bbr (если доступен)
# - загружает модуль tcp_bbr
# - включает BBR как алгоритм congestion control (перманентно через /etc/sysctl.d)
# - опционально пытается включить net.core.default_qdisc=fq (если ядро умеет fq)
# - безопасно перезапускает параметры и показывает статус

set -eu

msg() { echo "[BBR] $*"; }

# 1) Установка модуля (если ещё не установлен)
### Перенесен в зависимости, чтоб не ломался при первом запуске
#if ! lsmod | grep -q '^tcp_bbr'; then
#  if opkg list-installed | grep -q '^kmod-tcp-bbr'; then
#    msg "kmod-tcp-bbr уже установлен."
#  else
#    msg "Устанавливаю kmod-tcp-bbr…"
#    opkg update >/dev/null 2>&1 || true
#    opkg install kmod-tcp-bbr
#  fi
#fi

# 2) Загрузка модуля
if ! lsmod | grep -q '^tcp_bbr'; then
  msg "Загружаю модуль tcp_bbr…"
  modprobe tcp_bbr || {
    msg "ОШИБКА: не удалось загрузить tcp_bbr (ядро без поддержки?)."
    exit 1
  }
fi

# 3) Проверка наличия BBR среди доступных алгоритмов
avail_cc="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")"
if echo "$avail_cc" | grep -qw bbr; then
  msg "BBR доступен (available: $avail_cc)."
else
  msg "ВНИМАНИЕ: BBR не отображается в tcp_available_congestion_control: $avail_cc"
  msg "Продолжаю, так как модуль загружен; ядро OpenWrt может не заполнять этот список."
fi

# 4) Включаем BBR сейчас (runtime)
sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null
msg "Установлено net.ipv4.tcp_congestion_control=bbr (runtime)."

# 5) Попытка включить fq как qdisc (опционально; не критично)
set_qdisc_fq() {
  if sysctl -a 2>/dev/null | grep -q '^net.core.default_qdisc'; then
    if sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1; then
      msg "Установлено net.core.default_qdisc=fq (runtime)."
      return 0
    else
      msg "fq недоступен в ядре — оставляю текущий qdisc (обычно fq_codel)."
      return 1
    fi
  else
    msg "Параметр net.core.default_qdisc отсутствует — пропускаю."
    return 1
  fi
}
set_qdisc_fq || true

# 6) Сохраняем настройки перманентно
CONF_DIR="/etc/sysctl.d"
CONF_FILE="$CONF_DIR/99-bbr.conf"
mkdir -p "$CONF_DIR"

# Строим файл заново (идемпотентно)
{
  echo "# Создано $(date -u +'%Y-%m-%dT%H:%M:%SZ') — включение TCP BBR"
  echo "net.ipv4.tcp_congestion_control=bbr"
  # fq — только как пожелание; если ядро не умеет, sysctl -p его проигнорирует
  echo "net.core.default_qdisc=fq"
} > "$CONF_FILE"

# Применяем
if sysctl -p "$CONF_FILE" >/dev/null 2>&1; then
  msg "Перманентные параметры применены из $CONF_FILE."
else
  msg "Предупреждение: часть параметров из $CONF_FILE могла не примениться (например, fq). Это некритично."
fi

# 7) Итоговый статус
msg "Текущий алгоритм TCP: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')"
if sysctl -a 2>/dev/null | grep -q '^net.core.default_qdisc'; then
  msg "Текущий default_qdisc: $(sysctl -n net.core.default_qdisc 2>/dev/null || echo '?')"
fi

# Покажем активные TCP-сессии (если есть) и их congestion control
if command -v ss >/dev/null 2>&1; then
  msg "Первые активные TCP-сессии (колонка cong):"
  ss -t -i | awk 'NR<=20{print}'
fi

msg "Готово."