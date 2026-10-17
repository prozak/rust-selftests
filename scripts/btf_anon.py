#!/usr/bin/env python3
"""Make the BTF types a translation had to name anonymous again.

C has anonymous structs and unions: a map value declared `struct { ... }`,
an unnamed union member. Rust has none, so scripts/naked_gen.py names them
(`__anon_type<id>` for a type, `<outer>__anon<i>` for a member's type,
`__anon<i>` for the member) and the translation declares `// BTF_ANON` to
have the names cleared here, since the harness sees them: bpftool's
skeleton writes a named type as a reference it never defines, so a `.data`
variable of such a type fails to compile the skeleton ("array type has
incomplete element type"), where an anonymous one is written inline as the
C object's is.

A name is cleared by pointing it at string offset 0 (the empty string),
in place: no type moves, nothing else changes.

Usage: btf_anon.py <obj.bpf.o>
"""
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from btf_test_tags import FIXED_EXTRA, PER_VLEN, elf_find_section  # noqa: E402

BTF_KIND_STRUCT, BTF_KIND_UNION = 4, 5
SYNTHETIC = re.compile(r"^(?:__anon_type\d+|\w+__anon\d+)$")
MEMBER = re.compile(r"^__anon\d+$")


def main(path):
    buf = bytearray(open(path, "rb").read())
    _shdr, off, size, _align = elf_find_section(buf, ".BTF")
    magic, _ver, _flags, hdr_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", buf, off)
    assert magic == 0xEB9F
    str_base = off + hdr_len + str_off

    def name(name_off):
        end = buf.index(b"\0", str_base + name_off)
        return buf[str_base + name_off:end].decode()

    pos, end, n = off + hdr_len + type_off, off + hdr_len + type_off + type_len, 0
    while pos < end:
        name_off, info, _size = struct.unpack_from("<III", buf, pos)
        kind, vlen = (info >> 24) & 0x1F, info & 0xFFFF
        if kind in (BTF_KIND_STRUCT, BTF_KIND_UNION):
            if SYNTHETIC.match(name(name_off)):
                struct.pack_into("<I", buf, pos, 0)
                n += 1
            for i in range(vlen):
                mpos = pos + 12 + 12 * i
                (mname_off,) = struct.unpack_from("<I", buf, mpos)
                if MEMBER.match(name(mname_off)):
                    struct.pack_into("<I", buf, mpos, 0)
                    n += 1
        extra = FIXED_EXTRA.get(kind)
        if extra is None:
            extra = vlen * PER_VLEN[kind]
        pos += 12 + extra
    open(path, "wb").write(buf)
    print(f"[btf_anon] {os.path.basename(path)}: {n} name(s) made anonymous")


if __name__ == "__main__":
    main(sys.argv[1])
