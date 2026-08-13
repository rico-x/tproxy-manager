#!/bin/sh
# Every one of the six user-editable outbound templates must affect live,
# single-probe and batch generation. Probe-layout templates stay internal; this
# suite verifies the user's template survives every public generation path.

set -u

BASE="${TPM_TEST_BASE:-/tmp/tpm-outbound-template-test}"
BIN="${TPM_STAGE_BIN:-/usr/bin}"
SHARE="${TPM_STAGE_SHARE:-/usr/share/tproxy-manager}"
MODULES="${TPM_STAGE_MODULES:-/usr/lib/lua/luci/model/cbi/tproxy_manager/modules}"
P2M="$BIN/proxy2mihomo.lua"
P2S="$BIN/proxy2singbox.lua"
V2J="$BIN/vless2json.sh"

pass=0; fail=0
check() {
  name="$1"; got="$2"; want="$3"
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1)); printf '  PASS %s\n' "$name"
  else
    fail=$((fail + 1)); printf '  FAIL %s <- got %s, want %s\n' "$name" "$got" "$want"
  fi
}

rm -rf "$BASE"; mkdir -p "$BASE"
printf '%s\n' 'vless://00000000-0000-0000-0000-000000000000@example.com:443?type=tcp&security=tls&sni=example.com#template-test' > "$BASE/vless.links"
printf '%s\n' 'hysteria2://password@example.com:443/?sni=example.com#hy2-template-test' > "$BASE/hy2.links"
printf '10882\t%s\n' "$(cat "$BASE/vless.links")" > "$BASE/vless.ports"
printf '10883\t%s\n' "$(cat "$BASE/hy2.links")" > "$BASE/hy2.ports"

# Xray uses the same rendered outbound for live apply and a single probe; batch
# mode asks the converter for just that outbound and retags it. sendThrough is a
# native outbound property, so it survives both whole-config and one-outbound
# rendering without making the generated config artificial.
awk 'BEGIN { done=0 } { print; if (!done && $0 ~ /"tag": "proxy",/) { print "      \"sendThrough\": \"0.0.0.1\","; done=1 } }' \
  "$SHARE/watchdog-outbound.template.jsonc" > "$BASE/xray-vless.jsonc"
awk 'BEGIN { done=0 } { print; if (!done && $0 ~ /"tag": "proxy",/) { print "      \"sendThrough\": \"0.0.0.2\","; done=1 } }' \
  "$SHARE/watchdog-hysteria-outbound.template.jsonc" > "$BASE/xray-hy2.jsonc"

for protocol in vless hy2; do
  case "$protocol" in
    vless) marker="0.0.0.1" ;;
    hy2) marker="0.0.0.2" ;;
  esac
  for mode in live single batch; do
    case "$mode" in
      live|single)
        "$V2J" -r "$BASE/$protocol.links" -t "$BASE/xray-$protocol.jsonc" > "$BASE/x-$protocol-$mode"
        ;;
      batch)
        "$V2J" -r "$BASE/$protocol.links" -t "$BASE/xray-$protocol.jsonc" \
          --one-outbound --tag "probe-$protocol" > "$BASE/x-$protocol-$mode"
        ;;
    esac
    check "Xray $protocol custom outbound reaches $mode generation" \
      "$(grep -c "$marker" "$BASE/x-$protocol-$mode")" "1"
  done
done

cat > "$BASE/mihomo.yaml" <<'EOF'
# USER-MIHOMO-OUTBOUND
  - name: __NAME__
    type: vless
    server: __ADDRESS__
    port: __PORT__
    uuid: __UUID__
    udp: true
    network: __NETWORK__
    tls: __TLS__
__OPTIONAL__
__REALITY__
__TRANSPORT__
EOF

for mode in provider runtime single batch; do
  case "$mode" in
    provider) "$P2M" -r "$BASE/vless.links" --provider --vless-template "$BASE/mihomo.yaml" > "$BASE/m-vless-$mode" ;;
    runtime)  "$P2M" -r "$BASE/vless.links" --runtime --tproxy-port 61219 --vless-template "$BASE/mihomo.yaml" > "$BASE/m-vless-$mode" ;;
    single)   "$P2M" -r "$BASE/vless.links" --test --port 10881 --template "$SHARE/watchdog-mihomo-test-config.template.yaml" --vless-template "$BASE/mihomo.yaml" > "$BASE/m-vless-$mode" ;;
    batch)    "$P2M" --batch --ports "$BASE/vless.ports" --template "$SHARE/watchdog-mihomo-batch-test-config.template.yaml" --vless-template "$BASE/mihomo.yaml" > "$BASE/m-vless-$mode" ;;
  esac
  check "Mihomo vless custom outbound reaches $mode generation" "$(grep -c USER-MIHOMO-OUTBOUND "$BASE/m-vless-$mode")" "1"
done

cat > "$BASE/mihomo-hy2.yaml" <<'EOF'
# USER-MIHOMO-HY2-OUTBOUND
  - name: __NAME__
    type: hysteria2
    server: __ADDRESS__
    port: __PORT__
    password: __PASSWORD__
    udp: true
__OPTIONAL__
EOF

for mode in provider runtime single batch; do
  case "$mode" in
    provider) "$P2M" -r "$BASE/hy2.links" --provider --hy2-template "$BASE/mihomo-hy2.yaml" > "$BASE/m-hy2-$mode" ;;
    runtime)  "$P2M" -r "$BASE/hy2.links" --runtime --tproxy-port 61219 --hy2-template "$BASE/mihomo-hy2.yaml" > "$BASE/m-hy2-$mode" ;;
    single)   "$P2M" -r "$BASE/hy2.links" --test --port 10881 --template "$SHARE/watchdog-mihomo-test-config.template.yaml" --hy2-template "$BASE/mihomo-hy2.yaml" > "$BASE/m-hy2-$mode" ;;
    batch)    "$P2M" --batch --ports "$BASE/hy2.ports" --template "$SHARE/watchdog-mihomo-batch-test-config.template.yaml" --hy2-template "$BASE/mihomo-hy2.yaml" > "$BASE/m-hy2-$mode" ;;
  esac
  check "Mihomo hy2 custom outbound reaches $mode generation" "$(grep -c USER-MIHOMO-HY2-OUTBOUND "$BASE/m-hy2-$mode")" "1"
done

cat > "$BASE/singbox.jsonc" <<'EOF'
{
  "domain_strategy": "prefer_ipv4"
}
EOF

for mode in outbounds runtime single batch; do
  case "$mode" in
    outbounds) "$P2S" -r "$BASE/vless.links" --outbounds --vless-template "$BASE/singbox.jsonc" > "$BASE/s-vless-$mode" ;;
    runtime)   "$P2S" -r "$BASE/vless.links" --runtime --tproxy-port 61219 --vless-template "$BASE/singbox.jsonc" > "$BASE/s-vless-$mode" ;;
    single)    "$P2S" -r "$BASE/vless.links" --test --port 10881 --template "$SHARE/watchdog-singbox-test-config.template.jsonc" --vless-template "$BASE/singbox.jsonc" > "$BASE/s-vless-$mode" ;;
    batch)     "$P2S" --batch --ports "$BASE/vless.ports" --template "$SHARE/watchdog-singbox-batch-test-config.template.jsonc" --vless-template "$BASE/singbox.jsonc" > "$BASE/s-vless-$mode" ;;
  esac
  check "sing-box vless custom outbound reaches $mode generation" "$(grep -c prefer_ipv4 "$BASE/s-vless-$mode")" "1"
done

cat > "$BASE/singbox-hy2.jsonc" <<'EOF'
{
  "domain_strategy": "prefer_ipv6"
}
EOF

for mode in outbounds runtime single batch; do
  case "$mode" in
    outbounds) "$P2S" -r "$BASE/hy2.links" --outbounds --hy2-template "$BASE/singbox-hy2.jsonc" > "$BASE/s-hy2-$mode" ;;
    runtime)   "$P2S" -r "$BASE/hy2.links" --runtime --tproxy-port 61219 --hy2-template "$BASE/singbox-hy2.jsonc" > "$BASE/s-hy2-$mode" ;;
    single)    "$P2S" -r "$BASE/hy2.links" --test --port 10881 --template "$SHARE/watchdog-singbox-test-config.template.jsonc" --hy2-template "$BASE/singbox-hy2.jsonc" > "$BASE/s-hy2-$mode" ;;
    batch)     "$P2S" --batch --ports "$BASE/hy2.ports" --template "$SHARE/watchdog-singbox-batch-test-config.template.jsonc" --hy2-template "$BASE/singbox-hy2.jsonc" > "$BASE/s-hy2-$mode" ;;
  esac
  check "sing-box hy2 custom outbound reaches $mode generation" "$(grep -c prefer_ipv6 "$BASE/s-hy2-$mode")" "1"
done

WATCHDOG="$MODULES/watchdog.lua"
check "the form exposes six outbound choices" "$(grep -c 'label = .*outbound template' "$WATCHDOG")" "6"
check "the form has no single-probe template input" "$(grep -c 'name=\"watchdog_.*test_template_file' "$WATCHDOG")" "0"
check "the form has no batch-template input" "$(grep -c 'name=\"watchdog_.*batch_test_template_file' "$WATCHDOG")" "0"

rm -rf "$BASE"
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
