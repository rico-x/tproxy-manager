# vless2json.sh

[Русская версия](../vless2json.md)

`vless2json.sh` is the built-in protocol-aware converter used by `WATCHDOG`.

It is installed as:

- `/usr/bin/vless2json.sh`

Its job is intentionally small:

1. Read a file with links.
2. Take the first valid proxy link.
3. Parse the link.
4. Substitute parsed values into a JSON/JSONC template.
5. Print the resulting JSON to `stdout`.

## Usage

```sh
vless2json.sh -r /etc/tproxy-manager/watchdog.links -t /etc/tproxy-manager/watchdog-outbound.template.jsonc
```

Required arguments:

- `-r <links_file>`: file with links.
- `-t <template_file>`: JSON/JSONC template.

Help:

```sh
vless2json.sh --help
```

## Behavior

The converter:

- Ignores empty lines.
- Ignores lines starting with `#`.
- Supports `vless://...`, `hysteria2://...`, `hy2://...`, and `link # comment`.
- Uses the first valid proxy link from the file.
- Reads the template as JSONC.
- Removes comments before parsing.
- Prints clean JSON.

This is deliberate. During Watchdog tests and apply operations, the runtime creates a temporary one-line `links_file`, so the converter does not merge multiple links into one multi-outbound config.

## links_file Format

Supported line:

```txt
vless://uuid@example.com:443?...#Comment
hysteria2://password@example.com:443/?sni=example.com#Comment
```

Also supported:

```txt
vless://uuid@example.com:443?... # Comment
hy2://password@example.com:443/?sni=example.com # Comment
```

The external comment after ` space # space ` is used only as a fallback when the link itself has no `#fragment`.

## Supported VLESS Fields

The converter extracts:

- `address`
- `port`
- `uuid`
- `encryption`
- `flow`
- `type` / `network`
- `security`
- `sni` / `serverName`
- `fp` / `fingerprint`
- `pbk` / `publicKey`
- `sid` / `shortId`
- `spx` / `spiderX`
- `headerType`
- `path`
- `host`
- `authority`
- `serviceName`
- `mode`
- `allowinsecure`
- `alpn`
- `#fragment` as `remarks`

## Supported Hysteria 2 Fields

The converter extracts from `hysteria2://` and `hy2://` links:

- `auth`
- `address`
- `port`, default `443`
- `sni`
- `insecure`
- `pinSHA256`
- `ech`
- `alpn`
- `obfs`
- `obfs-password`
- `#fragment` as `remarks`

For Xray, HY2 links render to an outbound with `protocol: hysteria`, `settings.version = 2`, and `streamSettings.network = "hysteria"`. The recommended minimum Xray version for HY2 is `v26.3.27+`.
URI fields `pinSHA256`, `ech`, and `alpn` are mapped to Xray TLS fields `pinnedPeerCertSha256`, `echConfigList`, and `alpn`.
The `insecure` parameter is still parsed for URI compatibility, but the default HY2 template does not apply it: recent Xray builds removed `allowInsecure`, so `pinSHA256` should be used instead.

## Template Placeholders

Supported placeholders:

- `__REMARKS__`
- `__ADDRESS__`
- `__HOST__`
- `__PORT__`
- `__UUID__`
- `__USER_ID__`
- `__ENCRYPTION__`
- `__FLOW__`
- `__NETWORK__`
- `__TYPE__`
- `__SECURITY__`
- `__SERVER_NAME__`
- `__SNI__`
- `__FINGERPRINT__`
- `__FP__`
- `__PUBLIC_KEY__`
- `__PBK__`
- `__SHORT_ID__`
- `__SID__`
- `__SPIDER_X__`
- `__HEADER_TYPE__`
- `__PATH__`
- `__WS_PATH__`
- `__HOST_HEADER__`
- `__AUTHORITY__`
- `__SERVICE_NAME__`
- `__MODE__`
- `__ALLOW_INSECURE__`
- `__ALLOW_INSECURE_BOOL__`
- `__ALPN__`
- `__ALPN_ARRAY__`

HY2 adds:

- `__AUTH__`
- `__HY2_AUTH__`
- `__PORT_RAW__`
- `__PIN_SHA256__`
- `__PINNED_PEER_CERT_SHA256__`
- `__ECH__`
- `__ECH_CONFIG_LIST__`
- `__HY2_ALPN_ARRAY__`
- `__OBFS__`
- `__OBFS_PASSWORD__`
- `__HY2_HYSTERIA_SETTINGS__`
- `__HY2_TLS_SETTINGS__`
- `__HY2_UDPMASKS__`
- `__HY2_STREAM_SETTINGS__`

## Typed Substitution

If a template value is exactly one placeholder, typed substitution is used:

- `__PORT__` becomes a number.
- `__ALLOW_INSECURE_BOOL__` becomes a boolean.
- `__ALPN_ARRAY__` and `__HY2_ALPN_ARRAY__` become arrays of strings.
- `__HY2_STREAM_SETTINGS__`, `__HY2_HYSTERIA_SETTINGS__`, `__HY2_TLS_SETTINGS__`, and `__HY2_UDPMASKS__` become JSON objects or arrays.

If a placeholder is embedded in a larger string, substitution is textual.

Example:

```json
{
  "remarks": "__REMARKS__",
  "port": "__PORT__",
  "tls": "__SECURITY__",
  "label": "Node: __REMARKS__"
}
```

Result:

```json
{
  "remarks": "My node",
  "port": 443,
  "tls": "reality",
  "label": "Node: My node"
}
```

## Default Template

The package ships seed templates:

- `/usr/share/tproxy-manager/watchdog-outbound.template.jsonc`
- `/usr/share/tproxy-manager/watchdog-hysteria-outbound.template.jsonc`

During first install it is copied to:

- `/etc/tproxy-manager/watchdog-outbound.template.jsonc`
- `/etc/tproxy-manager/watchdog-hysteria-outbound.template.jsonc`

The default template includes:

- Main `vless` outbound with `tag: proxy`.
- Main `hysteria` outbound with `tag: proxy` in the HY2 template.
- `freedom` outbound with `tag: direct`.
- `blackhole` outbound with `tag: block`.

Edit the working copy in `/etc/tproxy-manager`, not the seed file in `/usr/share`.

## Limitations

- The converter does not remove incompatible template blocks automatically. If the link uses a different transport/security mode, the template must match it.
- If `links_file` contains multiple links, only the first valid link is used.
- For a different generation format, override `watchdog_vless2json` with a custom script.

## Watchdog Integration

`WATCHDOG` uses `vless2json.sh` in two paths:

1. Generating the active `OUTBOUND_FILE`.
2. Generating temporary test-instance configs.

Therefore the converter, outbound template, and test templates must stay compatible.
