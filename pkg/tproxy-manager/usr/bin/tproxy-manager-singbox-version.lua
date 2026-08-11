#!/usr/bin/lua

local core = require "tproxy_manager.core_version"

local function arch_name(arch)
  arch = tostring(arch or ""):lower()
  local map = {
    x86_64 = "amd64",
    amd64 = "amd64",
    i386 = "386",
    i686 = "386",
    aarch64 = "arm64",
    arm64 = "arm64",
    armv7l = "armv7",
    armv6l = "armv6",
    mips = "mips",
    mipsel = "mipsle",
    mips64 = "mips64",
    mips64el = "mips64le",
    riscv64 = "riscv64"
  }
  return map[arch] or arch
end

local cfg = {
  name = "singbox",
  binary = "sing-box",
  env_bin = "SINGBOX_BIN",
  bin_paths = { "/usr/bin/sing-box", "/usr/sbin/sing-box" },
  api_url = "https://api.github.com/repos/SagerNet/sing-box/releases?per_page=20",
  -- Inside a root-only directory, not directly in world-writable /tmp: the
  -- cache supplies the download URL that install() hands to curl.
  cache_dir = "/tmp/tproxy-manager-singbox-cache",
  cache_file = "/tmp/tproxy-manager-singbox-cache/releases.json",
  legacy_cache_file = "/tmp/tproxy-manager-singbox-releases.json",
  backup_dir = "/tmp/tproxy-manager-singbox-backup",
  backup_file = "/tmp/tproxy-manager-singbox-backup/sing-box.previous",
  backup_meta = "/tmp/tproxy-manager-singbox-backup/sing-box.previous.version",
  restart_service = "/etc/init.d/tproxy-manager-sing-box restart",
  asset_name = function(tag, arch)
    local version = tostring(tag or ""):gsub("^v", "")
    local a = arch_name(arch)
    local variant = (a == "arm64" or a == "amd64" or a == "armv7") and "-musl" or ""
    if version == "" then return "sing-box-linux-" .. a .. variant .. ".tar.gz" end
    return "sing-box-" .. version .. "-linux-" .. a .. variant .. ".tar.gz"
  end
}

core.dispatch(cfg, arg)
