# Config directory: roles and load order

[Русская версия](../config-layout.md)

All three proxy engines are configured the same way: the configuration lives as a
**directory of fragments by role**, and the package rewrites exactly one of them —
the one the applied link goes into. Everything else belongs to you and is never
touched while Watchdog runs.

Ready-made examples are in [config-examples](../config-examples) and pass each
engine's own validation (`xray -test`, `mihomo -t`, `sing-box check`). Copy them
as they are and replace the values with your own.

On a fresh install the package seeds a minimal working Mihomo and sing-box role
set. On upgrade, every existing monolithic profile stays active — including one
created by an older project release. There is no reliable way to distinguish it
from a file the operator has since changed, and replacing it with static roles
could lose a custom TPROXY port or the active outbound.

To migrate explicitly, move your ports, outbounds and rules into the role
directory and validate the complete set with the engine before restarting. Until
that directory exists, the init script, Watchdog and editor keep using the
compatible monolithic path; all user outbound templates work in that mode too.

## Roles

The number sets the load order, and it matters: fragments are combined in
ascending filename order, and arrays (`outbounds`, `rules`) are **appended to**
rather than replaced.

| № | Role | Purpose |
|---|---|---|
| `00` | general | Engine-wide options. Omitted where an engine has none |
| `01` | log | Logging |
| `02` | inbounds | Inbound connections: socks and TPROXY |
| `03` | outbounds-user | **Your** proxies. The package never writes this file |
| `04` | outbounds-managed | The applied link. **The package rewrites it** |
| `05` | routing | Routing rules |
| `06` | policy | Policy and stats. Xray only, optional |

## Where things live

| | Xray | Mihomo | sing-box |
|---|---|---|---|
| directory | `/etc/xray` | `/etc/mihomo/tproxy-manager.d` | `/etc/sing-box/tproxy-manager.d` |
| extension | `.json` (comments allowed) | `.yaml` | `.json` (comments allowed) |
| reads a directory | yes, `-confdir` | **no**, the package combines fragments | yes, `-C` |
| the package rewrites | `04_outbounds.json` | `tproxy-manager-proxies.yaml` | `04-outbounds-managed.json` |

The paths are configurable: `<engine>_profile_config_dir`,
`<engine>_profile_managed_file`, `<engine>_profile_user_file` in
`/etc/config/tproxy-manager`.

### What is different about Mihomo

Mihomo cannot read a config directory, so the fragments are combined into one file
(`mihomo_profile_assembled_file`, `/etc/mihomo/tproxy-manager.yaml` by default) by
`/usr/libexec/tproxy-manager/assemble-config` — when the service starts and after
a link is applied. Editing the combined file is pointless: it is rewritten from
the fragments.

Two requirements follow from that:

- **Top-level keys must not repeat across fragments.** In a YAML concatenation the
  last one would win, and a role declared twice would silently lose half its
  content. The assembler refuses to combine such a directory.
- The managed connection arrives through a **provider** rather than under the
  `proxies:` key, which would otherwise collide with your own fragment. That is
  why role `04` for Mihomo does not contain the connection but points at the file
  the package writes.
- The engine must run with `-d /etc/mihomo`: the provider's relative path resolves
  against that directory, and `GeoIP.dat` and `GeoSite.dat` live there too.

## Where to put your own proxies

Role `03`. The package does not touch it, so your proxy survives applying a link,
switching engines and upgrading the package.

Refer to it from the rules in role `05` by the tag you gave it. In the examples
that is `proxy-ru` — a separate server for the domains that have to leave through
a Russian address.

This used to require editing the connection template. It no longer does: a
template only describes the shape of the managed outbound, and your own proxies
live separately.

## The final rule

The last rule in role `05` has to send traffic to the managed connection. The
target has the same name in all three engines — `proxy`:

| engine | rule |
|---|---|
| Xray | `{ "type": "field", "inboundTag": ["redirect", "tproxy"], "outboundTag": "proxy" }` |
| Mihomo | `- MATCH,proxy` |
| sing-box | `"final": "proxy"` |

Without it, unmatched traffic follows the engine's own default. For Xray that is
the first outbound of the combined array, and role `03` loads **before** role
`04` — so traffic may leave through your own proxy instead of the managed one.

## The values used in the examples

The examples validate as they are, so they carry values that are valid in shape
rather than textual placeholders:

| value | in the examples | where it comes from in real life |
|---|---|---|
| socks port | `10808` | `watchdog_proxy_url` |
| TPROXY port | `61219` | `tproxy_port` |
| server address | `192.0.2.10`, `192.0.2.20` | the applied link |
| UUID | `00000000-0000-0000-0000-000000000000` | the link |
| REALITY public key | a throwaway example | the link |
| short id | `0123456789abcdef` | the link |

The addresses come from the range reserved for documentation (RFC 5737). The
values in role `04` are shown only to illustrate the result: that file is
rewritten every time a link is applied.

## Checking a change before it goes live

Every engine can validate its own configuration, and the package uses the same
tool — check an edit before the service restarts:

```sh
xray -test -confdir /etc/xray
sing-box check -C /etc/sing-box/tproxy-manager.d
/usr/libexec/tproxy-manager/assemble-config mihomo --check
```

For every engine `--check` invokes that engine's real validator. Applying a link
first validates a complete shadow configuration and only then replaces the
managed fragment; an assembly or restart failure restores the previous file.
