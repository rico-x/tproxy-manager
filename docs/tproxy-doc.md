# TPROXY engine: low-level reference

Этот документ описывает низкоуровневый TPROXY-движок проекта:

- `/usr/bin/tproxy-manager.sh`
- `/etc/init.d/tproxy-manager`

Пользовательская LuCI-документация, описание вкладок `XRAY`, `MIHOMO`, `Обновление геобаз` и `WATCHDOG` находятся в [README.md](../README.md).

## Назначение

`tproxy-manager.sh` настраивает прозрачный перехват трафика через `nftables` и policy routing на OpenWrt. Скрипт:

- управляет таблицей `nftables`;
- создаёт и удаляет `ip rule` и `ip route`;
- использует UCI-пакет `tproxy-manager`;
- работает с файлами списков из `/etc/tproxy-manager`.

Поддерживаются:

- IPv4 и IPv6;
- режимы портов `bypass` и `only`;
- фильтрация по исходным адресам `off`, `only`, `bypass`;
- отдельные `fwmark` и routing table для TCP и UDP.

## Основные файлы

UCI:

- `/etc/config/tproxy-manager`

Исполняемые файлы:

- `/usr/bin/tproxy-manager.sh`
- `/etc/init.d/tproxy-manager`

Списки:

- `/etc/tproxy-manager/tproxy-manager.ports`
- `/etc/tproxy-manager/tproxy-manager.v4`
- `/etc/tproxy-manager/tproxy-manager.v6`
- `/etc/tproxy-manager/tproxy-manager.src4.only`
- `/etc/tproxy-manager/tproxy-manager.src6.only`
- `/etc/tproxy-manager/tproxy-manager.src4.bypass`
- `/etc/tproxy-manager/tproxy-manager.src6.bypass`

## Требования

- OpenWrt с `nftables`
- `ip-full`
- `kmod-nft-tproxy`
- `kmod-nft-socket`
- root-доступ

Пакетные зависимости задаются в [pkg/tproxy-manager/CONTROL/control](../pkg/tproxy-manager/CONTROL/control).

## Быстрый старт

Запуск через init.d:

```sh
/etc/init.d/tproxy-manager start
```

Остановка:

```sh
/etc/init.d/tproxy-manager stop
```

Проверка состояния:

```sh
/etc/init.d/tproxy-manager status
```

Диагностика:

```sh
/etc/init.d/tproxy-manager diag
```

Прямой вызов backend-скрипта:

```sh
/usr/bin/tproxy-manager.sh start
/usr/bin/tproxy-manager.sh restart only
/usr/bin/tproxy-manager.sh stop
/usr/bin/tproxy-manager.sh status
/usr/bin/tproxy-manager.sh diag
```

## Команды

Поддерживаются:

```txt
tproxy-manager.sh start [-q] [bypass|only]
tproxy-manager.sh restart [-q] [bypass|only]
tproxy-manager.sh stop
tproxy-manager.sh status
tproxy-manager.sh diag
```

Аргумент `[bypass|only]` переопределяет `port_mode` только для текущего запуска.

## UCI-конфигурация

Базовая секция:

```uci
config main 'main'
  option log_enabled '1'
  option nft_table 'tp_mgr'
  option ifaces 'br-lan'
  option ipv6_enabled '1'

  option tproxy_port '61219'
  option fwmark_tcp '0x1'
  option fwmark_udp '0x2'
  option rttab_tcp '100'
  option rttab_udp '101'

  option port_mode 'bypass'
  option ports_file '/etc/tproxy-manager/tproxy-manager.ports'

  option bypass_v4_file '/etc/tproxy-manager/tproxy-manager.v4'
  option bypass_v6_file '/etc/tproxy-manager/tproxy-manager.v6'

  option src_mode 'off'
  option src_only_v4_file '/etc/tproxy-manager/tproxy-manager.src4.only'
  option src_only_v6_file '/etc/tproxy-manager/tproxy-manager.src6.only'
  option src_bypass_v4_file '/etc/tproxy-manager/tproxy-manager.src4.bypass'
  option src_bypass_v6_file '/etc/tproxy-manager/tproxy-manager.src6.bypass'
```

Замечания:

- `tproxy_port` задаёт единый порт, если не используются раздельные TCP/UDP-поля.
- `ifaces` — список LAN-интерфейсов, через которые перехватывается трафик.
- `port_mode`:
  - `bypass` — перечисленные порты исключаются из проксирования;
  - `only` — через прокси идут только перечисленные порты.
- `src_mode`:
  - `off`
  - `only`
  - `bypass`

## Формат файлов списков

### ports_file

Поддерживаются:

- `80`
- `1000-2000`
- `tcp:443`
- `udp:53`
- `both:123`

Пример:

```txt
80
tcp:443
udp:53
both:123
1000-2000
udp:6000-7000
```

### bypass_v4_file / bypass_v6_file

Поддерживаются IP и CIDR:

```txt
192.168.1.0/24
10.0.0.1
2001:db8::/32
```

### src_only_* / src_bypass_*

Поддерживаются IP и CIDR по тем же правилам.

Комментарии и пустые строки допустимы во всех списках.

## Диагностика

Проверьте:

```sh
/etc/init.d/tproxy-manager status
/etc/init.d/tproxy-manager diag
```

Полезно также смотреть:

```sh
logread | tail -n 200
nft list ruleset
ip rule
ip -6 rule
```

## Привязка к Xray/Mihomo

Сам TPROXY-движок не управляет конфигами `xray` или `mihomo`. Он только перехватывает трафик и перенаправляет его на локальный TPROXY listener.

Поэтому отдельно нужно убедиться, что ваш proxy-engine:

- слушает правильный порт;
- корректно принимает прозрачный трафик;
- запущен до применения правил или перезапущен после них.

## Интеграция с LuCI

Через LuCI-модуль `TPROXY` вы настраиваете те же параметры UCI и файлы списков, но без ручного редактирования `/etc/config/tproxy-manager`.

Если нужен UI-уровень, сценарии `Watchdog`, работа с `XRAY`, `MIHOMO` и GEO-обновлениями, используйте [README.md](../README.md).

## Безопасный откат

```sh
/etc/init.d/tproxy-manager stop
```

Это удаляет правила, маршруты и артефакты, созданные backend-скриптом.
