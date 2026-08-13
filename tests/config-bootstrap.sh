#!/bin/sh
# Upgrade safety for the role-fragment bootstrap. Existing monolithic profiles
# are user state even when an older tproxy-manager release generated them: their
# ports and active proxy must not be replaced with static package defaults.

set -u

DEFAULTS="${TPM_STAGE_DEFAULTS:-./pkg/tproxy-manager/etc/uci-defaults/90_tproxy_manager}"
SHARE="${TPM_STAGE_SHARE:-./pkg/tproxy-manager/usr/share/tproxy-manager}"
BASE="${TPM_TEST_BASE:-/tmp/tpm-config-bootstrap}"

passed=0
failed=0

check() {
  desc="$1"
  actual="$2"
  expected="$3"
  if [ "$actual" = "$expected" ]; then
    printf '  PASS %s\n' "$desc"
    passed=$((passed + 1))
  else
    printf '  FAIL %s\n       expected: %s\n       actual:   %s\n' "$desc" "$expected" "$actual"
    failed=$((failed + 1))
  fi
}

rm -rf "$BASE"
mkdir -p "$BASE"
trap 'rm -rf "$BASE"' EXIT HUP INT TERM

awk '/^seed_profile_dir_if_no_legacy\(\) \{$/,/^\}$/' "$DEFAULTS" > "$BASE/bootstrap-function.sh"
# shellcheck disable=SC1090,SC1091
. "$BASE/bootstrap-function.sh"

printf '%s\n' '== CONFIG BOOTSTRAP: upgrades keep the live monolith =='

# The decision must happen before the script creates its compatibility
# monolith. Otherwise every fresh install would look like an upgrade and never
# receive fragments.
mihomo_call_line="$(grep -n '^  /etc/mihomo/tproxy-manager.yaml mihomo ' "$DEFAULTS" | cut -d: -f1)"
mihomo_create_line="$(grep -n '^if \[ ! -s /etc/mihomo/tproxy-manager.yaml \]; then' "$DEFAULTS" | cut -d: -f1)"
singbox_call_line="$(grep -n '^  /etc/sing-box/tproxy-manager.json sing-box ' "$DEFAULTS" | cut -d: -f1)"
singbox_create_line="$(grep -n '^if \[ ! -s /etc/sing-box/tproxy-manager.json \]; then' "$DEFAULTS" | cut -d: -f1)"
check "Mihomo fresh/upgrade decision precedes monolith creation" \
  "$([ "$mihomo_call_line" -lt "$mihomo_create_line" ] && echo yes || echo no)" "yes"
check "sing-box fresh/upgrade decision precedes monolith creation" \
  "$([ "$singbox_call_line" -lt "$singbox_create_line" ] && echo yes || echo no)" "yes"

# Existing generated-looking Mihomo profile with a non-default port. This was
# precisely the dangerous case: the old signature heuristic classified it as
# package-owned and copied a fragment listening on 61219 instead.
MIHOMO_MONOLITH="$BASE/upgrade-mihomo/tproxy-manager.yaml"
MIHOMO_TARGET="$BASE/upgrade-mihomo/tproxy-manager.d"
mkdir -p "$(dirname "$MIHOMO_MONOLITH")"
cat > "$MIHOMO_MONOLITH" <<'EOF'
mode: rule
tproxy-port: 62001
proxy-groups:
  - name: TPROXY-MANAGER
rules:
  - MATCH,TPROXY-MANAGER
EOF
mihomo_before="$(cat "$MIHOMO_MONOLITH")"
seed_profile_dir_if_no_legacy "$MIHOMO_MONOLITH" mihomo "$MIHOMO_TARGET" "$SHARE/config-defaults/mihomo"
check "an existing Mihomo monolith does not get a fragment directory" \
  "$([ ! -e "$MIHOMO_TARGET" ] && echo absent || echo present)" "absent"
check "its non-default TPROXY port is byte-preserved" "$(cat "$MIHOMO_MONOLITH")" "$mihomo_before"

# Existing sing-box profile carries the currently active VLESS outbound. Static
# bootstrap data uses a direct outbound tagged proxy, which would leak traffic
# outside the proxy after the next restart if it were installed on upgrade.
SINGBOX_MONOLITH="$BASE/upgrade-singbox/tproxy-manager.json"
SINGBOX_TARGET="$BASE/upgrade-singbox/tproxy-manager.d"
mkdir -p "$(dirname "$SINGBOX_MONOLITH")"
cat > "$SINGBOX_MONOLITH" <<'EOF'
{
  "inbounds": [
    { "type": "mixed", "tag": "mixed-in", "listen_port": 10808 },
    { "type": "tproxy", "tag": "tproxy-in", "listen_port": 62002 }
  ],
  "outbounds": [
    { "type": "vless", "tag": "proxy", "server": "upgrade.example" },
    { "type": "direct", "tag": "direct" }
  ],
  "route": { "final": "proxy" }
}
EOF
singbox_before="$(cat "$SINGBOX_MONOLITH")"
seed_profile_dir_if_no_legacy "$SINGBOX_MONOLITH" sing-box "$SINGBOX_TARGET" "$SHARE/config-defaults/sing-box"
check "an existing sing-box monolith does not get a fragment directory" \
  "$([ ! -e "$SINGBOX_TARGET" ] && echo absent || echo present)" "absent"
check "its active proxy outbound and port are byte-preserved" "$(cat "$SINGBOX_MONOLITH")" "$singbox_before"

printf '\n%s\n' '== CONFIG BOOTSTRAP: fresh installs receive complete fragments =='

FRESH_MIHOMO="$BASE/fresh/mihomo/tproxy-manager.d"
seed_profile_dir_if_no_legacy "$BASE/fresh/mihomo/tproxy-manager.yaml" mihomo \
  "$FRESH_MIHOMO" "$SHARE/config-defaults/mihomo"
check "fresh Mihomo gets every shipped role" \
  "$(find "$FRESH_MIHOMO" -maxdepth 1 -type f -name '*.yaml' | wc -l | tr -d ' ')" "6"
check "fresh Mihomo role content is copied exactly" \
  "$(cmp "$SHARE/config-defaults/mihomo/02-inbounds.yaml" "$FRESH_MIHOMO/02-inbounds.yaml" >/dev/null 2>&1 && echo 1 || echo 0)" "1"

FRESH_SINGBOX="$BASE/fresh/sing-box/tproxy-manager.d"
seed_profile_dir_if_no_legacy "$BASE/fresh/sing-box/tproxy-manager.json" sing-box \
  "$FRESH_SINGBOX" "$SHARE/config-defaults/sing-box"
check "fresh sing-box gets every shipped role" \
  "$(find "$FRESH_SINGBOX" -maxdepth 1 -type f -name '*.json' | wc -l | tr -d ' ')" "6"
check "fresh sing-box role content is copied exactly" \
  "$(cmp "$SHARE/config-defaults/sing-box/04-outbounds-managed.json" "$FRESH_SINGBOX/04-outbounds-managed.json" >/dev/null 2>&1 && echo 1 || echo 0)" "1"

# Idempotence and symlink handling: neither an existing target nor any form of
# existing legacy path is adopted or overwritten.
EXISTING_TARGET="$BASE/existing-target"
mkdir -p "$EXISTING_TARGET"
printf '%s\n' keep > "$EXISTING_TARGET/operator-file"
seed_profile_dir_if_no_legacy "$BASE/no-monolith" mihomo "$EXISTING_TARGET" "$SHARE/config-defaults/mihomo"
check "an existing fragment directory is left untouched" "$(cat "$EXISTING_TARGET/operator-file")" "keep"

SYMLINK_LEGACY="$BASE/symlink-monolith"
SYMLINK_TARGET="$BASE/symlink-target"
ln -s "$BASE/missing-target" "$SYMLINK_LEGACY"
seed_profile_dir_if_no_legacy "$SYMLINK_LEGACY" mihomo "$SYMLINK_TARGET" "$SHARE/config-defaults/mihomo"
check "a dangling legacy symlink still counts as existing state" \
  "$([ ! -e "$SYMLINK_TARGET" ] && echo preserved || echo seeded)" "preserved"

printf '\n%d passed, %d failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
