# TPROXY Engine: Low-Level Reference

[Русская версия](../tproxy-doc.md)

This document describes the low-level TPROXY engine used by TPROXY Manager:

- `/usr/bin/tproxy-manager.sh`
- `/etc/init.d/tproxy-manager`

The user-facing LuCI documentation for the `XRAY`, `MIHOMO`, `GEO updates`, and `WATCHDOG` tabs is in [README_EN.md](../../README_EN.md).

## Purpose

`tproxy-manager.sh` configures transparent traffic interception through `nftables` and policy routing on OpenWrt.

It:

- Manages the project `nftables` table.
- Creates and removes `ip rule` and `ip route` entries.
- Reads settings from the `tproxy-manager` UCI package.
- Uses list files from `/etc/tproxy-manager`.

Supported behavior:

- IPv4 and IPv6.
- Port modes: `bypass` and `only`.
- Source filtering modes: `off`, `only`, and `bypass`.
- Separate TCP and UDP `fwmark` values.
- Separate TCP and UDP routing table IDs.

## Main Files

UCI:

- `/etc/config/tproxy-manager`

Runtime scripts:

- `/usr/bin/tproxy-manager.sh`
- `/etc/init.d/tproxy-manager`

List files:

- `/etc/tproxy-manager/tproxy-manager.ports`
- `/etc/tproxy-manager/tproxy-manager.v4`
- `/etc/tproxy-manager/tproxy-manager.v6`
- `/etc/tproxy-manager/tproxy-manager.src4.only`
- `/etc/tproxy-manager/tproxy-manager.src6.only`
- `/etc/tproxy-manager/tproxy-manager.src4.bypass`
- `/etc/tproxy-manager/tproxy-manager.src6.bypass`

## Requirements

- OpenWrt with `nftables`
- `ip-full`
- `kmod-nft-tproxy`
- `kmod-nft-socket`
- root access

Package dependencies are declared in [pkg/tproxy-manager/CONTROL/control](../../pkg/tproxy-manager/CONTROL/control).

## Quick Start

Start through init.d:

```sh
/etc/init.d/tproxy-manager start
```

Stop:

```sh
/etc/init.d/tproxy-manager stop
```

Status:

```sh
/etc/init.d/tproxy-manager status
```

Diagnostics:

```sh
/etc/init.d/tproxy-manager diag
```

Direct backend calls:

```sh
/usr/bin/tproxy-manager.sh start
/usr/bin/tproxy-manager.sh restart only
/usr/bin/tproxy-manager.sh stop
/usr/bin/tproxy-manager.sh status
/usr/bin/tproxy-manager.sh diag
```

## Commands

Supported commands:

```txt
tproxy-manager.sh start [-q] [bypass|only]
tproxy-manager.sh restart [-q] [bypass|only]
tproxy-manager.sh stop
tproxy-manager.sh status
tproxy-manager.sh diag
```

The optional `[bypass|only]` argument overrides `port_mode` only for the current run.

## UCI Configuration

Base section:

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

Notes:

- `tproxy_port` is the common port when separate TCP/UDP ports are not used.
- `ifaces` is the list of LAN interfaces whose traffic is intercepted.
- `port_mode=bypass` means listed ports bypass the proxy.
- `port_mode=only` means only listed ports go through the proxy.
- `src_mode=off` disables source filtering.
- `src_mode=only` proxies only listed source addresses.
- `src_mode=bypass` excludes listed source addresses from proxying.

## GEO Datadir

The package creates `/usr/share/tproxy-manager` for GEO databases. The default `/etc/tproxy-manager/geo-sources.conf` downloads:

- `/usr/share/tproxy-manager/geoip.dat`
- `/usr/share/tproxy-manager/geosite.dat`

Point the proxy daemon to this directory. For Xray through UCI:

```sh
uci set xray.config.datadir='/usr/share/tproxy-manager/'
uci commit xray
/etc/init.d/xray restart
```

## List File Format

### ports_file

Supported examples:

```txt
80
1000-2000
tcp:443
udp:53
both:123
```

### bypass_v4_file / bypass_v6_file

IP addresses and CIDR networks are supported:

```txt
192.168.1.0/24
10.0.0.1
2001:db8::/32
```

### src_only_* / src_bypass_*

The same IP/CIDR rules apply.

Empty lines and comments are allowed in all list files.

## Diagnostics

Useful commands:

```sh
/etc/init.d/tproxy-manager status
/etc/init.d/tproxy-manager diag
logread | tail -n 200
nft list ruleset
ip rule
ip -6 rule
```

If rules are not applied, verify that `kmod-nft-tproxy`, `kmod-nft-socket`, and `ip-full` are installed and that `nft_table` is still `tp_mgr`.
