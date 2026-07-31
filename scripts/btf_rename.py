#!/usr/bin/env python3
"""Normalize Rust-origin BTF integer type names to C canonical names.

rustc's DWARF names primitives "u64", "i32", ... and llc carries those names
into .BTF. bpftool gen skeleton emits struct members using those BTF names
verbatim, so harness C code that expects C integer types ("unsigned long
long" etc., with matching printf formats) breaks. Renaming the base INT
types makes Rust-built objects indistinguishable from clang-built ones at
the skeleton level.

Strings are appended to the BTF string table (offsets of existing strings
never change, so .BTF.ext line-info references stay valid) and the .BTF
section is rewritten in place via llvm-objcopy.

Usage: btf_rename.py <obj.o> <llvm-objcopy>
"""

import struct
import subprocess
import sys
import tempfile
import os

RENAME = {
    "u8": "unsigned char",
    "u16": "unsigned short",
    "u32": "unsigned int",
    "u64": "unsigned long long",
    "usize": "unsigned long",
    "i8": "signed char",
    "i16": "short",
    "i32": "int",
    "i64": "long long",
    "isize": "long",
}

BTF_KIND_INT = 1
# extra bytes after struct btf_type, per kind (vlen-dependent handled below)
FIXED_EXTRA = {1: 4, 2: 0, 3: 12, 4: None, 5: 0, 6: None, 7: 0, 8: 0, 9: 0,
               10: 0, 11: 0, 12: 0, 13: None, 14: 4, 15: None, 16: 0,
               17: 4, 18: 0, 19: None}
PER_VLEN = {4: 12, 6: 8, 13: 8, 15: 12, 19: 12}  # struct/union share kind 4? no:
# kinds: 1 INT, 2 PTR, 3 ARRAY, 4 STRUCT, 5 UNION(=vlen*12), 6 ENUM, 7 FWD,
# 8 TYPEDEF, 9 VOLATILE, 10 CONST, 11 RESTRICT, 12 FUNC, 13 FUNC_PROTO,
# 14 VAR, 15 DATASEC, 16 FLOAT, 17 DECL_TAG, 18 TYPE_TAG, 19 ENUM64
FIXED_EXTRA[5] = None
PER_VLEN[5] = 12


def main(path, objcopy):
    with tempfile.TemporaryDirectory() as td:
        raw = os.path.join(td, "btf.bin")
        subprocess.check_call([objcopy, "--dump-section", f".BTF={raw}", path])
        data = bytearray(open(raw, "rb").read())

    magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", data, 0)
    assert magic == 0xEB9F, hex(magic)

    types_base = hdr_len + type_off
    str_base = hdr_len + str_off

    def get_str(off):
        end = data.index(b"\0", str_base + off)
        return data[str_base + off:end].decode()

    new_strings = bytearray()
    appended = {}  # name -> new offset

    def intern(name):
        if name not in appended:
            appended[name] = str_len + len(new_strings)
            new_strings.extend(name.encode() + b"\0")
        return appended[name]

    pos = types_base
    end = types_base + type_len
    renamed = 0
    while pos < end:
        name_off, info, _ = struct.unpack_from("<III", data, pos)
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        if kind == BTF_KIND_INT and name_off:
            name = get_str(name_off)
            if name in RENAME:
                struct.pack_into("<I", data, pos, intern(RENAME[name]))
                renamed += 1
        extra = FIXED_EXTRA.get(kind)
        if extra is None:
            extra = vlen * PER_VLEN[kind]
        pos += 12 + extra

    if not renamed:
        return

    # string table is the last section in the .BTF blob; append and fix str_len
    assert str_base + str_len == len(data), "string table not at end of .BTF"
    data.extend(new_strings)
    struct.pack_into("<I", data, 20, str_len + len(new_strings))

    with tempfile.TemporaryDirectory() as td:
        raw = os.path.join(td, "btf.bin")
        open(raw, "wb").write(data)
        subprocess.check_call(
            [objcopy, f"--update-section=.BTF={raw}", path])
    print(f"[btf_rename] {os.path.basename(path)}: "
          f"renamed {renamed} int type(s)")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
