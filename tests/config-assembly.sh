#!/bin/sh
# Core-backed regression tests for assemble-config. All files live below /tmp;
# no service or installed configuration is changed.

set -u

BASE="${TPM_TEST_BASE:-/tmp/tpm-config-assembly-test}"
ASSEMBLE="${TPM_ASSEMBLE_CONFIG:-${TPM_STAGE_LIBEXEC:-/usr/libexec/tproxy-manager}/assemble-config}"
DEFAULTS="${TPM_STAGE_SHARE:-/usr/share/tproxy-manager}/config-defaults"
EXAMPLES="${TPM_STAGE_EXAMPLES:-}"

pass=0; fail=0
check() {
  name="$1"; got="$2"; want="$3"
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1)); printf '  PASS %s\n' "$name"
  else
    fail=$((fail + 1)); printf '  FAIL %s <- got %s, want %s\n' "$name" "$got" "$want"
  fi
}
run_rc() { "$@" >/dev/null 2>&1; printf '%s' "$?"; }

rm -rf "$BASE"
mkdir -p "$BASE"

printf '== ASSEMBLE-CONFIG: --check runs the real cores ==\n'

if [ -x "$ASSEMBLE" ] && command -v mihomo >/dev/null 2>&1; then
  cp -a "$DEFAULTS/mihomo" "$BASE/mihomo"
  assembled="$BASE/mihomo.yaml"
  rc="$(TPM_CONFIG_DIR_OVERRIDE="$BASE/mihomo" TPM_ASSEMBLED_OVERRIDE="$assembled" \
    TPM_MIHOMO_WORKDIR_OVERRIDE=/etc/mihomo "$ASSEMBLE" mihomo --check >/dev/null 2>&1; printf '%s' "$?")"
  check "Mihomo accepts the shipped fragment set" "$rc" "0"
  check "--check does not write the assembled file" "$([ -e "$assembled" ] && echo yes || echo no)" "no"

  printf '\nrules: [\n' >> "$BASE/mihomo/05-routing.yaml"
  rc="$(TPM_CONFIG_DIR_OVERRIDE="$BASE/mihomo" TPM_ASSEMBLED_OVERRIDE="$assembled" \
    TPM_MIHOMO_WORKDIR_OVERRIDE=/etc/mihomo "$ASSEMBLE" mihomo --check >/dev/null 2>&1; printf '%s' "$?")"
  check "Mihomo --check rejects invalid YAML" "$rc" "1"
  check "a failed check still writes nothing" "$([ -e "$assembled" ] && echo yes || echo no)" "no"
else
  printf '  SKIP Mihomo or assembler unavailable\n'
fi

if [ -x "$ASSEMBLE" ] && command -v sing-box >/dev/null 2>&1; then
  cp -a "$DEFAULTS/sing-box" "$BASE/sing-box"
  rc="$(TPM_CONFIG_DIR_OVERRIDE="$BASE/sing-box" "$ASSEMBLE" singbox --check >/dev/null 2>&1; printf '%s' "$?")"
  check "sing-box accepts the shipped fragment set" "$rc" "0"
  printf '{ "inbounds": [{ "type": "definitely-invalid" }] }\n' > "$BASE/sing-box/02-inbounds.json"
  rc="$(TPM_CONFIG_DIR_OVERRIDE="$BASE/sing-box" "$ASSEMBLE" singbox --check >/dev/null 2>&1; printf '%s' "$?")"
  check "sing-box --check rejects an invalid merged directory" "$rc" "1"
else
  printf '  SKIP sing-box or assembler unavailable\n'
fi

if [ -x "$ASSEMBLE" ] && command -v xray >/dev/null 2>&1 && [ -d "$EXAMPLES/xray" ]; then
  cp -a "$EXAMPLES/xray" "$BASE/xray"
  rc="$(TPM_CONFIG_DIR_OVERRIDE="$BASE/xray" "$ASSEMBLE" xray --check >/dev/null 2>&1; printf '%s' "$?")"
  check "Xray accepts its fragment directory" "$rc" "0"
  printf '{ broken\n' > "$BASE/xray/99-invalid.json"
  rc="$(TPM_CONFIG_DIR_OVERRIDE="$BASE/xray" "$ASSEMBLE" xray --check >/dev/null 2>&1; printf '%s' "$?")"
  check "Xray --check rejects invalid JSON" "$rc" "1"
else
  printf '  SKIP Xray, assembler, or examples unavailable\n'
fi

check "unknown assemble option is rejected" "$(run_rc "$ASSEMBLE" mihomo --unknown)" "2"

rm -rf "$BASE"
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
