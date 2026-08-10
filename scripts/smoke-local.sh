#!/usr/bin/env bash
set -euo pipefail

# Force a UTF-8 locale for the Cyrillic-detection grep below. Without this,
# a caller whose shell locale is "C" (LANG/LC_ALL unset — the default in a
# bare `bash script.sh` invocation on macOS) gets BSD grep doing byte-range
# comparison instead of codepoint comparison: multi-byte UTF-8 characters
# like "—" (em dash) or "·" (middle dot) then falsely match [А-Яа-яЁё],
# flagging dozens of legitimate English/HTML lines as "hardcoded Russian".
export LC_ALL="${LC_ALL:-en_US.UTF-8}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG_DIR="$ROOT/pkg/tproxy-manager"

section() {
  printf '\n== %s ==\n' "$1"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command not found: $1" >&2
    exit 1
  }
}

is_lua_file() {
  local file="$1"
  local first_line
  first_line="$(head -n 1 "$file" 2>/dev/null || true)"

  case "$file" in
    *.lua|*/usr/bin/vless2json.sh)
      return 0
      ;;
  esac

  case "$first_line" in
    '#!/usr/bin/lua'*|'#!/usr/bin/env lua'*)
      return 0
      ;;
  esac

  return 1
}

is_shell_file() {
  local file="$1"
  local first_line
  first_line="$(head -n 1 "$file" 2>/dev/null || true)"

  case "$first_line" in
    '#!/bin/sh'*|'#!/usr/bin/env sh'*|'#!/bin/ash'*|'#!/usr/bin/env ash'*)
      return 0
      ;;
  esac

  return 1
}

section "Prerequisites"
require_cmd luac
require_cmd python3
require_cmd sh
printf 'ok\n'

section "Lua syntax"
while IFS= read -r -d '' file; do
  if is_lua_file "$file"; then
    luac -p "$file"
  fi
done < <(find "$PKG_DIR" -type f -print0)
printf 'ok\n'

section "Test suites"
# The suites under tests/ exercise the rollback subsystem with injected faults
# (unreadable source, unwritable MANIFEST/KEEP/STAGE, failing chmod, rollback,
# and a process killed between two live writes). They need nixio and the LuCI
# Lua tree, so they cannot execute here — this checks they stay syntactically
# valid and runnable, and names the runner that executes them on a router.
test -d "$ROOT/tests"
suite_count=0
while IFS= read -r -d '' file; do
  case "$file" in
    *.lua) luac -p "$file" ;;
    *.sh)  sh -n "$file"; test -x "$file" || { echo "test suite must be executable: $file" >&2; exit 1; } ;;
  esac
  suite_count=$((suite_count + 1))
done < <(find "$ROOT/tests" \( -name '*.lua' -o -name '*.sh' \) -type f -print0)
if [ "$suite_count" -eq 0 ]; then
  echo "no test suites found under tests/" >&2
  exit 1
fi
test -x "$ROOT/scripts/test-on-device.sh"
printf 'ok (%d suite(s); run on a router: scripts/test-on-device.sh root@<host>)\n' "$suite_count"

section "Shell syntax"
while IFS= read -r -d '' file; do
  if is_shell_file "$file"; then
    sh -n "$file"
  fi
done < <(find "$PKG_DIR" \
  \( -path '*/usr/bin/*' -o -path '*/etc/init.d/*' -o -path '*/etc/uci-defaults/*' -o -path '*/usr/libexec/*' -o -path '*/CONTROL/*' \) \
  -type f -print0)

while IFS= read -r -d '' file; do
  bash -n "$file"
done < <(find "$ROOT/scripts" -type f -name '*.sh' -print0)
printf 'ok\n'

section "Shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S error -s bash "$ROOT"/scripts/*.sh
  while IFS= read -r -d '' file; do
    if is_shell_file "$file"; then
      shellcheck -S error -s sh "$file"
    fi
  done < <(find "$PKG_DIR" \
    \( -path '*/usr/bin/*' -o -path '*/etc/init.d/*' -o -path '*/etc/uci-defaults/*' -o -path '*/usr/libexec/*' -o -path '*/CONTROL/*' \) \
    -type f -print0)
  printf 'ok\n'
else
  printf 'skipped: shellcheck not installed\n'
fi

section "LuCI i18n"
if grep -RIn '[А-Яа-яЁё]' "$PKG_DIR/usr/lib/lua/luci"; then
  echo "LuCI Lua files must use English gettext msgids, not hardcoded Russian UI strings" >&2
  exit 1
fi
python3 "$ROOT/scripts/compile-luci-i18n.py" "$ROOT/po/tproxy-manager/ru.po" /tmp/tproxy-manager.ru.lmo
test -s /tmp/tproxy-manager.ru.lmo
printf 'ok\n'

section "Payload hygiene"
if find "$PKG_DIR" -name '.DS_Store' -type f | grep -q .; then
  find "$PKG_DIR" -name '.DS_Store' -type f
  echo ".DS_Store files must not be present in package payload" >&2
  exit 1
fi
if find "$PKG_DIR" \( -name '._*' -o -name '.AppleDouble' \) | grep -q .; then
  find "$PKG_DIR" \( -name '._*' -o -name '.AppleDouble' \)
  echo "macOS AppleDouble files must not be present in package payload" >&2
  exit 1
fi
test -f "$PKG_DIR/usr/share/tproxy-manager/happ-decrypt-keys.json"
test ! -e "$PKG_DIR/www/luci-static/resources/tproxy-manager/happ-decrypt.js"
test ! -e "$PKG_DIR/www/luci-static/resources/tproxy-manager/happ-decrypt-keys.json"
for executable in \
  "$PKG_DIR/etc/init.d/tproxy-manager" \
  "$PKG_DIR/etc/init.d/tproxy-manager-watchdog" \
  "$PKG_DIR/etc/init.d/tproxy-manager-mihomo" \
  "$PKG_DIR/etc/init.d/tproxy-manager-sing-box" \
  "$PKG_DIR/usr/bin/tproxy-manager.sh" \
  "$PKG_DIR/usr/bin/tproxy-manager-watchdog.sh" \
  "$PKG_DIR/usr/bin/vless2json.sh" \
  "$PKG_DIR/usr/bin/proxy2mihomo.lua" \
  "$PKG_DIR/usr/bin/proxy2singbox.lua"; do
  test -x "$executable" || {
    echo "expected executable payload file: $executable" >&2
    exit 1
  }
done
printf 'ok\n'

section "JSON/JSONC templates"
python3 - "$PKG_DIR" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])

def strip_json_comments(text: str) -> str:
    out = []
    i = 0
    n = len(text)
    in_string = False
    esc = False
    while i < n:
        c = text[i]
        d = text[i + 1] if i + 1 < n else ""
        if in_string:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_string = False
            i += 1
        else:
            if c == '"':
                in_string = True
                out.append(c)
                i += 1
            elif c == "/" and d == "/":
                i += 2
                while i < n and text[i] not in "\r\n":
                    i += 1
            elif c == "/" and d == "*":
                i += 2
                while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i += 2
            else:
                out.append(c)
                i += 1
    return "".join(out)

failed = False
for path in sorted(root.rglob("*")):
    if path.suffix not in {".json", ".jsonc"}:
        continue
    data = path.read_text(encoding="utf-8")
    data = data.replace('"__TEST_PORT__"', "10881")
    data = data.replace('"__OUTBOUNDS__"', '[{"tag":"proxy","protocol":"freedom","settings":{}}]')
    data = data.replace('"__BATCH_INBOUNDS__"', "[]")
    data = data.replace('"__BATCH_OUTBOUNDS__"', "[]")
    data = data.replace('"__BATCH_RULES__"', "[]")
    data = data.replace("__TEST_PORT__", "10881")
    data = data.replace("__OUTBOUNDS__", '[{"tag":"proxy","protocol":"freedom","settings":{}}]')
    data = data.replace("__BATCH_INBOUNDS__", "[]")
    data = data.replace("__BATCH_OUTBOUNDS__", "[]")
    data = data.replace("__BATCH_RULES__", "[]")
    try:
        json.loads(strip_json_comments(data))
    except Exception as exc:
        print(f"{path}: {exc}", file=sys.stderr)
        failed = True

if failed:
    sys.exit(1)
PY
printf 'ok\n'

section "Git whitespace"
git -C "$ROOT" diff --check
printf 'ok\n'
