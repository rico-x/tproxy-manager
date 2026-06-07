local jsonc = require "luci.jsonc"

local M = {}

local DEFAULT_HAPP_KEYS = "/usr/share/tproxy-manager/happ-decrypt-keys.json"

local function trim(value)
  return tostring(value or ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
end

local function shellescape(value)
  value = tostring(value or "")
  if value == "" then return "''" end
  return "'" .. value:gsub("'", "'\\''") .. "'"
end

local function exec_ok(cmd)
  local rc = os.execute(cmd)
  return rc == true or rc == 0
end

local function read_file(path)
  local fh = io.open(path, "rb")
  if not fh then return "" end
  local data = fh:read("*a") or ""
  fh:close()
  return data
end

local function ensure_dir(path)
  if path and path ~= "" then
    exec_ok("mkdir -p " .. shellescape(path) .. " >/dev/null 2>&1")
  end
end

local function write_file(path, data)
  local dir, base = tostring(path):match("^(.*)/([^/]+)$")
  if dir and dir ~= "" then ensure_dir(dir) end
  local tmp = string.format("%s/.%s.%d.%d.tmp", dir or ".", base or "tmp", os.time(), math.random(1, 1000000))
  local fh = assert(io.open(tmp, "wb"))
  fh:write(data or "")
  fh:close()
  assert(os.rename(tmp, path))
end

local function tmp_path(name)
  return string.format("/tmp/tproxy-manager-%s.%d.%d", name, os.time(), math.random(1, 1000000))
end

local b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function base64_decode(data)
  data = tostring(data or ""):gsub("%s+", ""):gsub("-", "+"):gsub("_", "/")
  if data == "" or data:find("[^A-Za-z0-9%+/%=]") then return nil end
  local rem = #data % 4
  if rem > 0 then data = data .. string.rep("=", 4 - rem) end
  local bits = data:gsub("=", ""):gsub(".", function(c)
    local idx = b64_chars:find(c, 1, true)
    if not idx then return "" end
    local value = idx - 1
    local out = {}
    for i = 6, 1, -1 do
      out[#out + 1] = (value % 2 ^ i - value % 2 ^ (i - 1) > 0) and "1" or "0"
    end
    return table.concat(out)
  end)
  local decoded = bits:gsub("%d%d%d?%d?%d?%d?%d?%d?", function(byte)
    if #byte ~= 8 then return "" end
    local value = 0
    for i = 1, 8 do
      if byte:sub(i, i) == "1" then value = value + 2 ^ (8 - i) end
    end
    return string.char(value)
  end)
  return decoded ~= "" and decoded or nil
end

local function bytes_to_hex(data)
  return (tostring(data or ""):gsub(".", function(c)
    return string.format("%02x", c:byte())
  end))
end

local function le64(value)
  value = tonumber(value) or 0
  local out = {}
  for i = 1, 8 do
    out[i] = string.char(value % 256)
    value = math.floor(value / 256)
  end
  return table.concat(out)
end

local function pad16(data)
  local rem = #data % 16
  if rem == 0 then return "" end
  return string.rep("\0", 16 - rem)
end

local function u32(value)
  return value % 4294967296
end

local function bxor(a, b)
  a = a or 0
  b = b or 0
  local out, bit = 0, 1
  for _ = 1, 32 do
    local aa = a % 2
    local bb = b % 2
    if aa ~= bb then out = out + bit end
    a = (a - aa) / 2
    b = (b - bb) / 2
    bit = bit * 2
  end
  return out
end

local function rotl(value, bits)
  return u32((value * 2 ^ bits) + math.floor(value / 2 ^ (32 - bits)))
end

local function read_u32le(data, offset)
  local a, b, c, d = data:byte(offset + 1, offset + 4)
  return (a or 0) + (b or 0) * 256 + (c or 0) * 65536 + (d or 0) * 16777216
end

local function write_u32le(value)
  value = u32(value)
  local a = value % 256
  value = math.floor(value / 256)
  local b = value % 256
  value = math.floor(value / 256)
  local c = value % 256
  value = math.floor(value / 256)
  local d = value % 256
  return string.char(a, b, c, d)
end

local function quarter_round(state, a, b, c, d)
  state[a] = u32(state[a] + state[b]); state[d] = rotl(bxor(state[d], state[a]), 16)
  state[c] = u32(state[c] + state[d]); state[b] = rotl(bxor(state[b], state[c]), 12)
  state[a] = u32(state[a] + state[b]); state[d] = rotl(bxor(state[d], state[a]), 8)
  state[c] = u32(state[c] + state[d]); state[b] = rotl(bxor(state[b], state[c]), 7)
end

local function chacha_block(key, nonce, counter)
  if #key ~= 32 then return nil, "ChaCha20 key must be 32 bytes" end
  if #nonce ~= 12 then return nil, "ChaCha20 nonce must be 12 bytes" end

  local state = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    read_u32le(key, 0), read_u32le(key, 4), read_u32le(key, 8), read_u32le(key, 12),
    read_u32le(key, 16), read_u32le(key, 20), read_u32le(key, 24), read_u32le(key, 28),
    u32(counter or 0), read_u32le(nonce, 0), read_u32le(nonce, 4), read_u32le(nonce, 8),
  }
  local working = {}
  for i = 1, 16 do working[i] = state[i] end
  for _ = 1, 10 do
    quarter_round(working, 1, 5, 9, 13)
    quarter_round(working, 2, 6, 10, 14)
    quarter_round(working, 3, 7, 11, 15)
    quarter_round(working, 4, 8, 12, 16)
    quarter_round(working, 1, 6, 11, 16)
    quarter_round(working, 2, 7, 12, 13)
    quarter_round(working, 3, 8, 9, 14)
    quarter_round(working, 4, 5, 10, 15)
  end
  local out = {}
  for i = 1, 16 do out[i] = write_u32le(working[i] + state[i]) end
  return table.concat(out)
end

local function chacha_xor(key, nonce, data, counter)
  local out = {}
  counter = counter or 0
  for offset = 1, #data, 64 do
    local block, err = chacha_block(key, nonce, counter)
    if not block then return nil, err end
    counter = counter + 1
    local chunk = data:sub(offset, offset + 63)
    local bytes = {}
    for i = 1, #chunk do
      bytes[i] = string.char(bxor(chunk:byte(i), block:byte(i)) % 256)
    end
    out[#out + 1] = table.concat(bytes)
  end
  return table.concat(out)
end

local function poly1305_mac(one_time_key, ciphertext)
  local input = ciphertext .. pad16(ciphertext) .. le64(0) .. le64(#ciphertext)
  local in_path = tmp_path("poly1305.in")
  write_file(in_path, input)
  local cmd = table.concat({
    "openssl mac",
    "-macopt", shellescape("hexkey:" .. bytes_to_hex(one_time_key)),
    "-in", shellescape(in_path),
    "POLY1305",
    "2>/dev/null",
  }, " ")
  local p = io.popen(cmd)
  local out = p and trim(p:read("*a") or "") or ""
  if p then p:close() end
  os.remove(in_path)
  if out == "" then return nil, "Poly1305 verification failed" end
  return out:lower()
end

local function chacha20poly1305_decrypt(key, nonce, sealed)
  if #sealed < 16 then return nil, "ChaCha20-Poly1305 payload too short" end
  local ciphertext = sealed:sub(1, #sealed - 16)
  local tag = sealed:sub(#sealed - 15)
  local block, err = chacha_block(key, nonce, 0)
  if not block then return nil, err end
  local mac, mac_err = poly1305_mac(block:sub(1, 32), ciphertext)
  if not mac then return nil, mac_err end
  if mac ~= bytes_to_hex(tag) then return nil, "ChaCha20-Poly1305 tag mismatch" end
  return chacha_xor(key, nonce, ciphertext, 1)
end

local HAPP_KEYS_CACHE = nil
local function load_happ_keys()
  if HAPP_KEYS_CACHE then return HAPP_KEYS_CACHE end
  local path = os.getenv("TPROXY_MANAGER_HAPP_KEYS_FILE") or DEFAULT_HAPP_KEYS
  local raw = read_file(path)
  if raw == "" then return nil, "Happ decrypt keys file not found: " .. path end
  local ok, parsed = pcall(jsonc.parse, raw)
  if not ok or type(parsed) ~= "table" then return nil, "Happ decrypt keys file is invalid" end
  HAPP_KEYS_CACHE = parsed
  return parsed
end

local function rsa_decrypt_b64_key(key_b64, cipher)
  local key_der = base64_decode(key_b64)
  if not key_der then return nil, "invalid RSA key encoding" end
  local key_path = tmp_path("rsa.key")
  local in_path = tmp_path("rsa.in")
  local out_path = tmp_path("rsa.out")
  local err_path = tmp_path("rsa.err")
  write_file(key_path, key_der)
  write_file(in_path, cipher)
  local cmd = table.concat({
    "openssl pkeyutl -decrypt",
    "-inkey", shellescape(key_path),
    "-keyform DER",
    "-in", shellescape(in_path),
    "-out", shellescape(out_path),
    "-pkeyopt rsa_padding_mode:pkcs1",
    "2>" .. shellescape(err_path),
  }, " ")
  local ok = exec_ok(cmd)
  local out = read_file(out_path)
  local err = trim(read_file(err_path))
  os.remove(key_path)
  os.remove(in_path)
  os.remove(out_path)
  os.remove(err_path)
  if not ok or out == "" then return nil, err ~= "" and err or "RSA decrypt failed" end
  return out
end

local function swap_pairs(value)
  value = tostring(value or "")
  local out = {}
  for i = 1, #value, 2 do
    local a = value:sub(i, i)
    local b = value:sub(i + 1, i + 1)
    if b ~= "" then out[#out + 1] = b .. a else out[#out + 1] = a end
  end
  return table.concat(out)
end

local function block_pair_swap(value)
  value = tostring(value or "")
  local full_len = #value - (#value % 4)
  local out = {}
  for offset = 1, full_len, 4 do
    out[#out + 1] = value:sub(offset + 2, offset + 3) .. value:sub(offset, offset + 1)
  end
  out[#out + 1] = value:sub(full_len + 1)
  return table.concat(out)
end

local RSA_BLOCK_SIZES = { 128, 512, 512, 512 }
local function decrypt_crypt1to4(ordinal, payload)
  local keys, err = load_happ_keys()
  if not keys then return nil, err end
  local key_b64 = type(keys.pkcs1_keys_b64) == "table" and keys.pkcs1_keys_b64[ordinal]
  if not key_b64 then return nil, "Happ RSA key is missing" end
  local cipher = base64_decode(payload)
  if not cipher then return nil, "invalid Happ payload encoding" end
  local block_size = RSA_BLOCK_SIZES[ordinal]
  if #cipher % block_size ~= 0 then return nil, "RSA payload size is invalid" end
  local out = {}
  for offset = 1, #cipher, block_size do
    local plain, dec_err = rsa_decrypt_b64_key(key_b64, cipher:sub(offset, offset + block_size - 1))
    if not plain then return nil, dec_err end
    out[#out + 1] = plain
  end
  return table.concat(out)
end

local function decrypt_crypt5(payload)
  local shuffled = block_pair_swap(payload)
  if #shuffled < 8 then return nil, "crypt5 payload too short" end
  local marker = shuffled:sub(1, 4) .. shuffled:sub(-4)
  local body = shuffled:sub(5, -5)
  if #body < 13 then return nil, "crypt5 body too short" end
  local nonce = body:sub(1, 12)
  local rest = body:sub(13)
  local digits = rest:match("^(%d+)")
  if not digits then return nil, "crypt5 segment length missing" end
  local segment_len = tonumber(digits) or 0
  local packed = rest:sub(#digits + 1)
  if #packed < 1 + segment_len then return nil, "crypt5 segment truncated" end
  local url_b64 = packed:sub(2, 1 + segment_len)
  local enc_str = packed:sub(2 + segment_len)
  local keys, err = load_happ_keys()
  if not keys then return nil, err end
  local key_b64 = type(keys.crypt5_keys_b64) == "table" and keys.crypt5_keys_b64[marker]
  if not key_b64 then return nil, "No RSA key found for marker: " .. marker end
  local rsa_plain, rsa_err = rsa_decrypt_b64_key(key_b64, base64_decode(enc_str) or "")
  if not rsa_plain then return nil, rsa_err end
  local chacha_key = base64_decode(swap_pairs(rsa_plain))
  if not chacha_key then return nil, "invalid crypt5 ChaCha key" end
  local sealed = base64_decode(url_b64)
  if not sealed then return nil, "invalid crypt5 encrypted payload" end
  local intermediate, dec_err = chacha20poly1305_decrypt(chacha_key, nonce, sealed)
  if not intermediate then return nil, dec_err end
  local final = base64_decode(swap_pairs(intermediate))
  if not final then return nil, "invalid crypt5 final payload" end
  return final
end

function M.decrypt(link)
  local path = tostring(link or "")
  if path:match("^happ://") then path = path:sub(8) end
  if path:match("^crypt5/") then return decrypt_crypt5(path:sub(8)) end
  if path:match("^crypt4/") then return decrypt_crypt1to4(4, path:sub(8)) end
  if path:match("^crypt3/") then return decrypt_crypt1to4(3, path:sub(8)) end
  if path:match("^crypt2/") then return decrypt_crypt1to4(2, path:sub(8)) end
  if path:match("^crypt/") then return decrypt_crypt1to4(1, path:sub(7)) end
  return nil, "unknown Happ link format"
end

function M.resolve_subscription_url(url)
  url = trim(url)
  if url:match("^https?://") then return url end
  if url:match("^happ://") then
    local decrypted, err = M.decrypt(url)
    if not decrypted then return nil, err end
    decrypted = trim(decrypted)
    if not decrypted:match("^https?://") then
      return nil, "decrypted Happ link is not an HTTP subscription URL"
    end
    return decrypted
  end
  return nil, "URL подписки должен начинаться с http://, https:// или happ://"
end

function M.decrypt_lines(text)
  local out = {}
  local count = 0
  for line in (tostring(text or "") .. "\n"):gmatch("([^\n]*)\n") do
    line = trim(line)
    if line ~= "" then
      count = count + 1
      local value, err = M.decrypt(line)
      if value then
        out[#out + 1] = "OK: " .. value
      else
        out[#out + 1] = "Error: " .. err .. "\nSource: " .. line
      end
    end
  end
  if count == 0 then return "" end
  return table.concat(out, "\n\n")
end

M.default_keys_path = DEFAULT_HAPP_KEYS

return M
