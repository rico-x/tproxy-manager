(function () {
  "use strict";

  var KEY_URL = "/luci-static/resources/tproxy-manager/happ-decrypt-keys.json";
  var keyData = null;
  var rsaCache = {};

  function fail(message) {
    throw new Error(message);
  }

  function bytesToBigInt(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return BigInt(hex ? "0x" + hex : "0");
  }

  function bigIntToBytes(value, length) {
    var hex = value.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    var bytes = new Uint8Array(length);
    var start = Math.max(0, length - hex.length / 2);
    for (var i = 0; i < hex.length; i += 2) {
      var idx = start + i / 2;
      if (idx >= 0 && idx < length) bytes[idx] = parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes;
  }

  function modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    var result = 1n;
    base %= modulus;
    while (exponent > 0n) {
      if (exponent & 1n) result = (result * base) % modulus;
      exponent >>= 1n;
      base = (base * base) % modulus;
    }
    return result;
  }

  function concatBytes(parts) {
    var total = 0;
    for (var i = 0; i < parts.length; i++) total += parts[i].length;
    var out = new Uint8Array(total);
    var pos = 0;
    for (var j = 0; j < parts.length; j++) {
      out.set(parts[j], pos);
      pos += parts[j].length;
    }
    return out;
  }

  function b64DecodeUrlSafe(value) {
    var s = String(value || "").replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
    return out;
  }

  function utf8Decode(bytes) {
    return new TextDecoder().decode(bytes);
  }

  function utf8Encode(text) {
    return new TextEncoder().encode(String(text || ""));
  }

  function swapPairs(s) {
    var arr = Array.from(String(s || ""));
    for (var i = 0; i + 1 < arr.length; i += 2) {
      var t = arr[i];
      arr[i] = arr[i + 1];
      arr[i + 1] = t;
    }
    return arr.join("");
  }

  function blockPairSwap(s) {
    s = String(s || "");
    var fullLen = s.length - (s.length % 4);
    var out = "";
    for (var offset = 0; offset < fullLen; offset += 4) {
      out += s.slice(offset + 2, offset + 4) + s.slice(offset, offset + 2);
    }
    return out + s.slice(fullLen);
  }

  function DerReader(bytes) {
    this.bytes = bytes;
    this.pos = 0;
  }

  DerReader.prototype.readByte = function () {
    if (this.pos >= this.bytes.length) fail("DER truncated");
    return this.bytes[this.pos++];
  };

  DerReader.prototype.readLength = function () {
    var first = this.readByte();
    if (first < 0x80) return first;
    var count = first & 0x7f;
    if (count === 0 || count > 4) fail("DER unsupported length");
    var len = 0;
    for (var i = 0; i < count; i++) len = (len << 8) | this.readByte();
    return len;
  };

  DerReader.prototype.readTag = function (tag) {
    var got = this.readByte();
    if (got !== tag) fail("DER unexpected tag 0x" + got.toString(16));
    var len = this.readLength();
    if (this.pos + len > this.bytes.length) fail("DER value truncated");
    var out = this.bytes.slice(this.pos, this.pos + len);
    this.pos += len;
    return out;
  };

  DerReader.prototype.readInteger = function () {
    var value = this.readTag(0x02);
    while (value.length > 1 && value[0] === 0) value = value.slice(1);
    return bytesToBigInt(value);
  };

  DerReader.prototype.readOctetString = function () {
    return this.readTag(0x04);
  };

  DerReader.prototype.readSequence = function () {
    return new DerReader(this.readTag(0x30));
  };

  function parsePkcs1PrivateKey(der) {
    var seq = new DerReader(der).readSequence();
    seq.readInteger();
    var n = seq.readInteger();
    seq.readInteger();
    var d = seq.readInteger();
    return { n: n, d: d, keySize: Math.ceil(n.toString(2).length / 8) };
  }

  function parsePkcs8PrivateKey(der) {
    var seq = new DerReader(der).readSequence();
    seq.readInteger();
    seq.readSequence();
    return parsePkcs1PrivateKey(seq.readOctetString());
  }

  function rsaKeyFromB64(b64, kind) {
    var cacheKey = kind + ":" + b64;
    if (rsaCache[cacheKey]) return rsaCache[cacheKey];
    var der = b64DecodeUrlSafe(b64);
    var key = kind === "pkcs8" ? parsePkcs8PrivateKey(der) : parsePkcs1PrivateKey(der);
    rsaCache[cacheKey] = key;
    return key;
  }

  function rsaDecrypt(privateKey, cipherBytes) {
    var block = bigIntToBytes(modPow(bytesToBigInt(cipherBytes), privateKey.d, privateKey.n), privateKey.keySize);
    if (block[0] !== 0 || block[1] !== 2) fail("RSA PKCS#1 padding error");
    var sep = -1;
    for (var i = 2; i < block.length; i++) {
      if (block[i] === 0) {
        sep = i;
        break;
      }
    }
    if (sep < 10) fail("RSA PKCS#1 separator not found");
    return block.slice(sep + 1);
  }

  function readU32LE(bytes, offset) {
    return ((bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0);
  }

  function writeU32LE(bytes, offset, value) {
    bytes[offset] = value & 0xff;
    bytes[offset + 1] = (value >>> 8) & 0xff;
    bytes[offset + 2] = (value >>> 16) & 0xff;
    bytes[offset + 3] = (value >>> 24) & 0xff;
  }

  function rotl(value, bits) {
    return ((value << bits) | (value >>> (32 - bits))) >>> 0;
  }

  function quarterRound(state, a, b, c, d) {
    state[a] = (state[a] + state[b]) >>> 0; state[d] = rotl(state[d] ^ state[a], 16);
    state[c] = (state[c] + state[d]) >>> 0; state[b] = rotl(state[b] ^ state[c], 12);
    state[a] = (state[a] + state[b]) >>> 0; state[d] = rotl(state[d] ^ state[a], 8);
    state[c] = (state[c] + state[d]) >>> 0; state[b] = rotl(state[b] ^ state[c], 7);
  }

  function chachaBlock(key, nonce, counter) {
    if (key.length !== 32) fail("ChaCha20 key must be 32 bytes");
    if (nonce.length !== 12) fail("ChaCha20 nonce must be 12 bytes");
    var constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    var state = new Uint32Array(16);
    state.set(constants, 0);
    for (var i = 0; i < 8; i++) state[4 + i] = readU32LE(key, i * 4);
    state[12] = counter >>> 0;
    state[13] = readU32LE(nonce, 0);
    state[14] = readU32LE(nonce, 4);
    state[15] = readU32LE(nonce, 8);
    var working = new Uint32Array(state);
    for (var round = 0; round < 10; round++) {
      quarterRound(working, 0, 4, 8, 12);
      quarterRound(working, 1, 5, 9, 13);
      quarterRound(working, 2, 6, 10, 14);
      quarterRound(working, 3, 7, 11, 15);
      quarterRound(working, 0, 5, 10, 15);
      quarterRound(working, 1, 6, 11, 12);
      quarterRound(working, 2, 7, 8, 13);
      quarterRound(working, 3, 4, 9, 14);
    }
    var out = new Uint8Array(64);
    for (var j = 0; j < 16; j++) writeU32LE(out, j * 4, (working[j] + state[j]) >>> 0);
    return out;
  }

  function chachaXor(key, nonce, data, counter) {
    var out = new Uint8Array(data.length);
    for (var offset = 0; offset < data.length; offset += 64) {
      var block = chachaBlock(key, nonce, counter++);
      for (var i = 0; i < 64 && offset + i < data.length; i++) out[offset + i] = data[offset + i] ^ block[i];
    }
    return out;
  }

  function leBytesToBigInt(bytes) {
    var out = 0n;
    for (var i = bytes.length - 1; i >= 0; i--) out = (out << 8n) + BigInt(bytes[i]);
    return out;
  }

  function bigIntToLE(value, length) {
    var out = new Uint8Array(length);
    for (var i = 0; i < length; i++) {
      out[i] = Number(value & 0xffn);
      value >>= 8n;
    }
    return out;
  }

  function poly1305Blocks(acc, r, bytes) {
    var p = (1n << 130n) - 5n;
    for (var offset = 0; offset < bytes.length; offset += 16) {
      var block = bytes.slice(offset, Math.min(offset + 16, bytes.length));
      var n = leBytesToBigInt(block) + (1n << BigInt(8 * block.length));
      acc = ((acc + n) * r) % p;
    }
    return acc;
  }

  function pad16(bytes) {
    var rem = bytes.length % 16;
    return rem === 0 ? new Uint8Array(0) : new Uint8Array(16 - rem);
  }

  function le64(value) {
    return bigIntToLE(BigInt(value), 8);
  }

  function poly1305Tag(oneTimeKey, ciphertext) {
    var rBytes = oneTimeKey.slice(0, 16);
    rBytes[3] &= 15; rBytes[7] &= 15; rBytes[11] &= 15; rBytes[15] &= 15;
    rBytes[4] &= 252; rBytes[8] &= 252; rBytes[12] &= 252;
    var r = leBytesToBigInt(rBytes);
    var s = leBytesToBigInt(oneTimeKey.slice(16, 32));
    var auth = concatBytes([
      new Uint8Array(0),
      pad16(new Uint8Array(0)),
      ciphertext,
      pad16(ciphertext),
      le64(0),
      le64(ciphertext.length)
    ]);
    var acc = poly1305Blocks(0n, r, auth);
    return bigIntToLE((acc + s) & ((1n << 128n) - 1n), 16);
  }

  function equalBytes(a, b) {
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function chacha20poly1305Decrypt(key, nonce, sealed) {
    if (sealed.length < 16) fail("ChaCha20-Poly1305 payload too short");
    var ciphertext = sealed.slice(0, sealed.length - 16);
    var tag = sealed.slice(sealed.length - 16);
    var oneTimeKey = chachaBlock(key, nonce, 0).slice(0, 32);
    if (!equalBytes(poly1305Tag(oneTimeKey, ciphertext), tag)) fail("ChaCha20-Poly1305 authentication failed");
    return chachaXor(key, nonce, ciphertext, 1);
  }

  async function loadKeys() {
    if (keyData) return keyData;
    var response = await fetch(KEY_URL, { cache: "force-cache" });
    if (!response.ok) fail("Failed to load Happ decrypt keys: HTTP " + response.status);
    keyData = await response.json();
    return keyData;
  }

  async function decryptCrypt1to4(ordinal, payload) {
    var keys = await loadKeys();
    var privateKey = rsaKeyFromB64(keys.pkcs1_keys_b64[ordinal], "pkcs1");
    var cipherBytes = b64DecodeUrlSafe(payload);
    if (cipherBytes.length % privateKey.keySize !== 0) fail("RSA payload size is invalid");
    var parts = [];
    for (var i = 0; i < cipherBytes.length; i += privateKey.keySize) {
      parts.push(rsaDecrypt(privateKey, cipherBytes.slice(i, i + privateKey.keySize)));
    }
    return utf8Decode(concatBytes(parts));
  }

  async function decryptCrypt5(payload) {
    var shuffled = blockPairSwap(payload);
    if (shuffled.length < 8) fail("crypt5 payload too short");
    var marker = shuffled.slice(0, 4) + shuffled.slice(-4);
    var body = shuffled.slice(4, -4);
    if (body.length < 13) fail("crypt5 body too short");
    var nonceStr = body.slice(0, 12);
    var rest = body.slice(12);
    var digitMatch = rest.match(/^(\d+)/);
    if (!digitMatch) fail("crypt5 segment length missing");
    var segmentLen = Number.parseInt(digitMatch[1], 10);
    var packed = rest.slice(digitMatch[1].length);
    if (packed.length < 1 + segmentLen) fail("crypt5 segment truncated");
    var urlB64 = packed.slice(1, 1 + segmentLen);
    var encStr = packed.slice(1 + segmentLen);
    var keys = await loadKeys();
    var rsaKeyB64 = keys.crypt5_keys_b64[marker];
    if (!rsaKeyB64) fail("No RSA key found for marker: " + marker);
    var privateKey = rsaKeyFromB64(rsaKeyB64, "pkcs8");
    var rsaPlain = utf8Decode(rsaDecrypt(privateKey, b64DecodeUrlSafe(encStr)));
    var chachaKey = b64DecodeUrlSafe(swapPairs(rsaPlain));
    var nonce = utf8Encode(nonceStr);
    var intermediate = chacha20poly1305Decrypt(chachaKey, nonce, b64DecodeUrlSafe(urlB64));
    return utf8Decode(b64DecodeUrlSafe(swapPairs(utf8Decode(intermediate))));
  }

  async function decryptLink(link) {
    var value = String(link || "").trim();
    var path = value.indexOf("happ://") === 0 ? value.slice(7) : value;
    if (path.indexOf("crypt5/") === 0) return decryptCrypt5(path.slice(7));
    if (path.indexOf("crypt4/") === 0) return decryptCrypt1to4(3, path.slice(7));
    if (path.indexOf("crypt3/") === 0) return decryptCrypt1to4(2, path.slice(7));
    if (path.indexOf("crypt2/") === 0) return decryptCrypt1to4(1, path.slice(7));
    if (path.indexOf("crypt/") === 0) return decryptCrypt1to4(0, path.slice(6));
    fail("Unknown link format: " + value);
  }

  function setOutput(text) {
    var out = document.getElementById("happ_decrypt_output");
    if (out) out.value = text;
  }

  async function runUiDecrypt() {
    var input = document.getElementById("happ_decrypt_input");
    if (!input) return;
    var lines = input.value.split(/\r?\n/).map(function (line) { return line.trim(); }).filter(Boolean);
    if (!lines.length) {
      setOutput("");
      return;
    }
    setOutput("Расшифровка...");
    var out = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      try {
        var result = await decryptLink(line);
        out.push("[" + (i + 1) + "] OK");
        out.push(result);
      } catch (e) {
        out.push("[" + (i + 1) + "] Error: " + (e && e.message ? e.message : String(e)));
        out.push(line);
      }
      if (i + 1 < lines.length) out.push("");
    }
    setOutput(out.join("\n"));
  }

  function initUi() {
    var run = document.getElementById("happ_decrypt_run");
    if (!run || run.dataset.bound === "1") return;
    run.dataset.bound = "1";
    run.addEventListener("click", function (event) {
      event.preventDefault();
      runUiDecrypt();
    });
    var clear = document.getElementById("happ_decrypt_clear");
    if (clear) clear.addEventListener("click", function (event) {
      event.preventDefault();
      var input = document.getElementById("happ_decrypt_input");
      if (input) input.value = "";
      setOutput("");
    });
  }

  window.TProxyHappDecrypt = { decryptLink: decryptLink, init: initUi };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initUi);
  else initUi();
})();
