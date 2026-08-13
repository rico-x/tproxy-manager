#!/bin/sh
# A rejected candidate must never replace the live managed fragment or restart
# the service. Tests use real engine validators and temporary profile trees.

set -u

BASE="${TPM_TEST_BASE:-/tmp/tpm-managed-apply-test}"
LIB="${TPM_STAGE_LIBEXEC:-/usr/libexec/tproxy-manager/watchdog}"
BIN="${TPM_STAGE_BIN:-/usr/bin}"
SHARE="${TPM_STAGE_SHARE:-/usr/share/tproxy-manager}"
DEFAULTS="$SHARE/config-defaults"
EXAMPLES="${TPM_STAGE_EXAMPLES:-}"
ASSEMBLE="${TPM_ASSEMBLE_CONFIG:-/usr/libexec/tproxy-manager/assemble-config}"

pass=0; fail=0; skipped=0
check() {
  name="$1"; got="$2"; want="$3"
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1)); printf '  PASS %s\n' "$name"
  else
    fail=$((fail + 1)); printf '  FAIL %s <- got %s, want %s\n' "$name" "$got" "$want"
  fi
}
digest() { md5sum "$1" | cut -d' ' -f1; }

rm -rf "$BASE"; mkdir -p "$BASE"
LOG_FILE="$BASE/watchdog.log"
SERVICE_PATH="$BASE/service"
RESTART_CMD=restart
cat > "$SERVICE_PATH" <<EOF
#!/bin/sh
printf '%s\n' called >> '$BASE/service.calls'
exit 0
EOF
chmod +x "$SERVICE_PATH"
log_msg() { printf '%s\n' "$*" >> "$LOG_FILE"; }

# shellcheck source=/dev/null
. "$LIB/render_apply.sh"

printf '== MANAGED APPLY: validation happens before promotion ==\n'

if command -v xray >/dev/null 2>&1 && [ -d "$EXAMPLES/xray" ]; then
  cp -a "$EXAMPLES/xray" "$BASE/xray"
  OUTBOUND_FILE="$BASE/xray/04-outbounds-managed.json"
  before="$(digest "$OUTBOUND_FILE")"
  cat > "$BASE/xray-candidate.json" <<'EOF'
[
  { "protocol": "freedom", "tag": "duplicate" },
  { "protocol": "freedom", "tag": "duplicate" }
]
EOF
  rm -f "$BASE/service.calls"
  apply_generated_outbounds "$BASE/xray-candidate.json" >/dev/null 2>&1; rc=$?
  check "Xray rejects a duplicate-tag candidate" "$rc" "1"
  check "Xray live outbounds stay byte-identical" "$(digest "$OUTBOUND_FILE")" "$before"
  check "Xray service was not restarted" "$([ -e "$BASE/service.calls" ] && echo yes || echo no)" "no"
else
  skipped=$((skipped + 3)); printf '  SKIP Xray unavailable\n'
fi

if command -v mihomo >/dev/null 2>&1 && [ -d "$DEFAULTS/mihomo" ]; then
  cp -a "$DEFAULTS/mihomo" "$BASE/mihomo"
  MIHOMO_CONFIG_DIR="$BASE/mihomo"
  MIHOMO_MANAGED_FILE="$BASE/tproxy-manager-proxies.yaml"
  MIHOMO_PROVIDER_FILE="$MIHOMO_MANAGED_FILE"
  PROXY2MIHOMO="$BIN/proxy2mihomo.lua"
  MIHOMO_VLESS_OUTBOUND_TEMPLATE_FILE="$BASE/mihomo-bad.yaml"
  MIHOMO_HY2_OUTBOUND_TEMPLATE_FILE="$SHARE/watchdog-mihomo-hysteria-outbound.template.yaml"
  ASSEMBLE_CONFIG="$ASSEMBLE"
  OUTBOUND_FILE="$MIHOMO_MANAGED_FILE"
  TPROXY_PORT=61219
  printf 'proxies:\n  - name: previous\n    type: direct\n' > "$MIHOMO_MANAGED_FILE"
  cat > "$MIHOMO_VLESS_OUTBOUND_TEMPLATE_FILE" <<'EOF'
  - name: __NAME__
    type: vless
    server: __ADDRESS__
    port: __PORT__
    uuid: __UUID__
    broken: [
EOF
  printf '%s\n' 'vless://00000000-0000-0000-0000-000000000000@example.com:443?type=tcp&security=tls&sni=example.com#bad' > "$BASE/link"
  before="$(digest "$MIHOMO_MANAGED_FILE")"
  rm -f "$BASE/service.calls"
  TPM_CONFIG_DIR_OVERRIDE="$MIHOMO_CONFIG_DIR" \
  TPM_ASSEMBLED_OVERRIDE="$BASE/mihomo-assembled.yaml" \
  TPM_MIHOMO_WORKDIR_OVERRIDE=/etc/mihomo \
    apply_mihomo_generated "$BASE/link" >/dev/null 2>&1; rc=$?
  check "Mihomo rejects an invalid provider candidate" "$rc" "1"
  check "Mihomo live provider stays byte-identical" "$(digest "$MIHOMO_MANAGED_FILE")" "$before"
  check "Mihomo service was not restarted" "$([ -e "$BASE/service.calls" ] && echo yes || echo no)" "no"
else
  skipped=$((skipped + 3)); printf '  SKIP Mihomo unavailable\n'
fi

if command -v sing-box >/dev/null 2>&1 && [ -d "$DEFAULTS/sing-box" ]; then
  cp -a "$DEFAULTS/sing-box" "$BASE/sing-box"
  SINGBOX_CONFIG_DIR="$BASE/sing-box"
  SINGBOX_MANAGED_FILE="$BASE/sing-box/04-outbounds-managed.json"
  SINGBOX_OUTBOUNDS_FILE="$SINGBOX_MANAGED_FILE"
  PROXY2SINGBOX="$BIN/proxy2singbox.lua"
  SINGBOX_VLESS_OUTBOUND_TEMPLATE_FILE="$BASE/singbox-bad.jsonc"
  SINGBOX_HY2_OUTBOUND_TEMPLATE_FILE="$SHARE/watchdog-singbox-hysteria-outbound.template.jsonc"
  OUTBOUND_FILE="$SINGBOX_MANAGED_FILE"
  TPROXY_PORT=61219
  printf '{ "tag": "direct" }\n' > "$SINGBOX_VLESS_OUTBOUND_TEMPLATE_FILE"
  printf '%s\n' 'vless://00000000-0000-0000-0000-000000000000@example.com:443?type=tcp&security=tls&sni=example.com#bad' > "$BASE/link"
  before="$(digest "$SINGBOX_MANAGED_FILE")"
  rm -f "$BASE/service.calls"
  apply_singbox_generated "$BASE/link" >/dev/null 2>&1; rc=$?
  check "sing-box rejects a duplicate-tag candidate" "$rc" "1"
  check "sing-box live outbounds stay byte-identical" "$(digest "$SINGBOX_MANAGED_FILE")" "$before"
  check "sing-box service was not restarted" "$([ -e "$BASE/service.calls" ] && echo yes || echo no)" "no"
else
  skipped=$((skipped + 3)); printf '  SKIP sing-box unavailable\n'
fi

rm -rf "$BASE"
printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skipped"
[ "$fail" -eq 0 ]
