#!/usr/bin/env python3
"""Compile a gettext .po file into LuCI .lmo format.

This intentionally mirrors OpenWrt LuCI po2lmo enough for package-local
translations, without requiring the OpenWrt SDK or a C toolchain.
"""

from __future__ import annotations

import ast
import os
import re
import struct
import sys
from dataclasses import dataclass, field


def sfh_get16(data: bytes, pos: int) -> int:
    return data[pos] + (data[pos + 1] << 8)


def signed_byte(value: int) -> int:
    return value - 256 if value >= 128 else value


def sfh_hash(data: bytes, init: int | None = None) -> int:
    length = len(data)
    if init is None:
        init = length
    if length <= 0:
        return 0

    h = init & 0xFFFFFFFF
    pos = 0
    rem = length & 3
    loops = length >> 2

    for _ in range(loops):
        h = (h + sfh_get16(data, pos)) & 0xFFFFFFFF
        tmp = ((sfh_get16(data, pos + 2) << 11) ^ h) & 0xFFFFFFFF
        h = (((h << 16) & 0xFFFFFFFF) ^ tmp) & 0xFFFFFFFF
        pos += 4
        h = (h + (h >> 11)) & 0xFFFFFFFF

    if rem == 3:
        h = (h + sfh_get16(data, pos)) & 0xFFFFFFFF
        h ^= (h << 16) & 0xFFFFFFFF
        h ^= (signed_byte(data[pos + 2]) << 18) & 0xFFFFFFFF
        h = (h + (h >> 11)) & 0xFFFFFFFF
    elif rem == 2:
        h = (h + sfh_get16(data, pos)) & 0xFFFFFFFF
        h ^= (h << 11) & 0xFFFFFFFF
        h = (h + (h >> 17)) & 0xFFFFFFFF
    elif rem == 1:
        h = (h + signed_byte(data[pos])) & 0xFFFFFFFF
        h ^= (h << 10) & 0xFFFFFFFF
        h = (h + (h >> 1)) & 0xFFFFFFFF

    h ^= (h << 3) & 0xFFFFFFFF
    h = (h + (h >> 5)) & 0xFFFFFFFF
    h ^= (h << 4) & 0xFFFFFFFF
    h = (h + (h >> 17)) & 0xFFFFFFFF
    h ^= (h << 25) & 0xFFFFFFFF
    h = (h + (h >> 6)) & 0xFFFFFFFF
    return h & 0xFFFFFFFF


@dataclass
class Message:
    ctxt: str | None = None
    msgid: str | None = None
    msgid_plural: str | None = None
    msgstr: dict[int, str] = field(default_factory=dict)


def unquote_po(value: str) -> str:
    return ast.literal_eval(value.strip())


def parse_po(path: str) -> list[Message]:
    messages: list[Message] = []
    current = Message()
    active: tuple[str, int | None] | None = None

    def flush() -> None:
        nonlocal current, active
        if current.msgid is not None or current.msgstr:
            messages.append(current)
        current = Message()
        active = None

    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line or line.startswith("#"):
                if not line:
                    flush()
                continue

            match = re.match(r"^(msgctxt|msgid|msgid_plural|msgstr)(?:\[(\d+)\])?\s+(\".*\")$", line)
            if match:
                field_name, plural_index, quoted = match.groups()
                text = unquote_po(quoted)
                if field_name == "msgctxt":
                    current.ctxt = text
                    active = ("ctxt", None)
                elif field_name == "msgid":
                    if current.msgid is not None or current.msgstr:
                        flush()
                    current.msgid = text
                    active = ("msgid", None)
                elif field_name == "msgid_plural":
                    current.msgid_plural = text
                    active = ("msgid_plural", None)
                else:
                    idx = int(plural_index or 0)
                    current.msgstr[idx] = text
                    active = ("msgstr", idx)
                continue

            if line.startswith('"') and active:
                text = unquote_po(line)
                field_name, idx = active
                if field_name == "ctxt":
                    current.ctxt = (current.ctxt or "") + text
                elif field_name == "msgid":
                    current.msgid = (current.msgid or "") + text
                elif field_name == "msgid_plural":
                    current.msgid_plural = (current.msgid_plural or "") + text
                elif field_name == "msgstr" and idx is not None:
                    current.msgstr[idx] = current.msgstr.get(idx, "") + text

    flush()
    return messages


def write_padded(out, data: bytes) -> None:
    out.write(data)
    out.write(b"\0" * ((4 - (len(data) % 4)) % 4))


def compile_lmo(po_path: str, out_path: str) -> None:
    entries: list[tuple[int, int, int, int]] = []
    data_chunks: list[bytes] = []
    offset = 0

    for msg in parse_po(po_path):
        if msg.msgid == "" and msg.msgstr.get(0):
            header = msg.msgstr[0]
            for field in header.split("\\n"):
                if field.lower().startswith("plural-forms: "):
                    value = field[14:].encode("utf-8")
                    entries.append((0, 0, offset, len(value)))
                    data_chunks.append(value)
                    offset += len(value) + ((4 - (len(value) % 4)) % 4)
                    break
            continue

        if msg.msgid is None:
            continue

        plural_count = max(msg.msgstr.keys(), default=0) + 1
        for idx, value in sorted(msg.msgstr.items()):
            if not value:
                continue
            if msg.ctxt and msg.msgid_plural:
                key = f"{msg.ctxt}\x01{msg.msgid}\x02{idx}"
            elif msg.ctxt:
                key = f"{msg.ctxt}\x01{msg.msgid}"
            elif msg.msgid_plural:
                key = f"{msg.msgid}\x02{idx}"
            else:
                key = msg.msgid

            key_bytes = key.encode("utf-8")
            val_bytes = value.encode("utf-8")
            key_id = sfh_hash(key_bytes)
            val_id = sfh_hash(val_bytes)
            if key_id == val_id:
                continue
            entries.append((key_id, plural_count, offset, len(val_bytes)))
            data_chunks.append(val_bytes)
            offset += len(val_bytes) + ((4 - (len(val_bytes) % 4)) % 4)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    if not entries:
        if os.path.exists(out_path):
            os.unlink(out_path)
        return

    with open(out_path, "wb") as out:
        for chunk in data_chunks:
            write_padded(out, chunk)
        for entry in sorted(entries, key=lambda e: e[0]):
            for value in entry:
                write_padded(out, struct.pack("!I", value))
        write_padded(out, struct.pack("!I", offset))


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"Usage: {argv[0]} input.po output.lmo", file=sys.stderr)
        return 1
    compile_lmo(argv[1], argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
