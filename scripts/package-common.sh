#!/usr/bin/env bash
set -euo pipefail

trim() {
  local value="${1-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

control_field() {
  local field="$1"
  local file="$2"
  awk -v field="$field" '
    $0 ~ ("^" field ":") {
      sub("^" field ":[[:space:]]*", "", $0)
      print
      exit
    }
  ' "$file"
}

copy_payload_tree() {
  local src="$1"
  local dest="$2"
  mkdir -p "$dest"
  tar \
    --exclude='.DS_Store' \
    --exclude='CONTROL' \
    -C "$src" \
    -cf - . | tar -C "$dest" -xf -
}

copy_control_tree() {
  local src="$1"
  local dest="$2"
  mkdir -p "$dest/CONTROL"
  tar \
    --exclude='.DS_Store' \
    -C "$src/CONTROL" \
    -cf - . | tar -C "$dest/CONTROL" -xf -
}

normalize_tree() {
  local root="$1"

  find "$root" -name '.DS_Store' -type f -delete

  if [ -d "$root/etc/init.d" ]; then
    find "$root/etc/init.d" -type f -exec chmod 0755 {} +
  fi

  if [ -d "$root/etc/uci-defaults" ]; then
    find "$root/etc/uci-defaults" -type f -exec chmod 0755 {} +
  fi

  if [ -d "$root/usr/bin" ]; then
    find "$root/usr/bin" -type f -exec chmod 0755 {} +
  fi

  if [ -d "$root/CONTROL" ]; then
    find "$root/CONTROL" -type f -exec chmod 0755 {} +
  fi
}

inject_control_version() {
  local control_file="$1"
  local version="$2"
  if grep -q '^Version:' "$control_file"; then
    sed -i.bak "s/^Version:.*/Version: $version/" "$control_file"
    rm -f "$control_file.bak"
  else
    printf 'Version: %s\n' "$version" >> "$control_file"
  fi

  perl -0777 -pe 's/^\xEF\xBB\xBF//' -i "$control_file" || true
  sed -i.bak 's/\r$//' "$control_file" || true
  rm -f "$control_file.bak"
  tail -c1 "$control_file" | od -An -t x1 | grep -q '0a' || echo >> "$control_file"
}

split_depends_csv() {
  local raw="${1-}"
  local dep
  IFS=',' read -r -a deps <<< "$raw"
  for dep in "${deps[@]}"; do
    dep="$(trim "$dep")"
    [ -n "$dep" ] && printf '%s\n' "$dep"
  done
}

apk_depends_from_csv() {
  local raw="${1-}"
  local dep
  local out=()

  IFS=',' read -r -a deps <<< "$raw"
  for dep in "${deps[@]}"; do
    dep="$(trim "$dep")"
    [ -n "$dep" ] || continue
    dep="${dep// /}"
    dep="${dep//\(/}"
    dep="${dep//\)/}"
    out+=( "$dep" )
  done

  if [ "${#out[@]}" -gt 0 ]; then
    printf '%s' "${out[*]}"
  fi
}

apk_arch_from_control() {
  local arch="$1"
  if [ "$arch" = "all" ]; then
    printf 'noarch'
  else
    printf '%s' "$arch"
  fi
}
