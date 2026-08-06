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
  name = "mihomo",
  binary = "mihomo",
  env_bin = "MIHOMO_BIN",
  bin_paths = { "/usr/bin/mihomo", "/usr/sbin/mihomo" },
  version_args = { "-v" },
  api_url = "https://api.github.com/repos/MetaCubeX/mihomo/releases?per_page=20",
  cache_file = "/tmp/tproxy-manager-mihomo-releases.json",
  backup_dir = "/tmp/tproxy-manager-mihomo-backup",
  backup_file = "/tmp/tproxy-manager-mihomo-backup/mihomo.previous",
  backup_meta = "/tmp/tproxy-manager-mihomo-backup/mihomo.previous.version",
  restart_service = "/etc/init.d/tproxy-manager-mihomo restart",
  asset_name = function(tag, arch)
    tag = tostring(tag or "")
    local a = arch_name(arch)
    if tag == "" then return "mihomo-linux-" .. a .. ".gz" end
    return "mihomo-linux-" .. a .. "-" .. tag .. ".gz"
  end
}

core.dispatch(cfg, arg)
