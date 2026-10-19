#!/usr/bin/env python3
"""Give a Rust struct the C object's member BTF (bitfields and enums).

libbpf's static linker matches the two objects' definitions of a weak map
member by member (linker.c glob_sym_btf_matches, exact for a map's key and
value types): member names, raw offsets (which encode a bitfield's size) and
the named types behind them. Rust has no bitfields and no C enum members, so
a struct that mirrors a C one with bitfield members (usdt.bpf.h's
`struct __bpf_usdt_arg_spec`) cannot be made to match from the source. The
translation declares the C's members in the C's order and byte layout for
its own reads, and

    // BTF_C_MEMBERS: __bpf_usdt_arg_spec

makes this pass rewrite the built object's BTF for that struct: the
struct's kflag and every member's offset word become the C object's, and a
member whose C type is an enum gets a copy of that enum appended to the
Rust BTF (the linker compares enums by name and size). Members must agree
in count, names and order, and scalar members in size. Append-only for
type ids and strings, as btf_type_tags.py: nothing existing moves, the grown
.BTF goes at EOF with the section header repointed.

Usage: btf_c_members.py <obj.bpf.o> <c.bpf.o> <prog.rs>
"""
import os
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "equiv"))
from btf_test_tags import elf_find_section  # noqa: E402
from btf_type_tags import walk_types  # noqa: E402
from bpfcore import Btf  # noqa: E402

K_INT, K_STRUCT, K_UNION, K_ENUM, K_ENUM64 = 1, 4, 5, 6, 19


def parse_source(path):
    return re.findall(r"^// BTF_C_MEMBERS: ([A-Za-z_]\w*)\s*$", Path(path).read_text(), re.M)


def find_struct(btf, name):
    hits = [t for t in btf.types.values() if t.kind in (K_STRUCT, K_UNION) and t.name == name]
    if len(hits) != 1:
        raise ValueError(f"{len(hits)} BTF structs named {name!r}")
    return hits[0]


def main(path, c_path, source):
    names = parse_source(source)
    if not names:
        return
    original = Path(c_path + ".corig")
    c_buf = (original if original.exists() else Path(c_path)).read_bytes()
    c_base, c_off, c_size, _ = elf_find_section(c_buf, ".BTF")
    c_btf = Btf(c_buf[c_off:c_off + c_size])

    buf = bytearray(Path(path).read_bytes())
    shdr_base, btf_off, btf_size, btf_align = elf_find_section(buf, ".BTF")
    data = bytearray(buf[btf_off:btf_off + btf_size])
    magic, _ver, _flags, hdr_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", data, 0)
    assert magic == 0xEB9F, hex(magic)
    str_base = hdr_len + str_off
    assert str_base + str_len == len(data), "string table not at end of .BTF"
    btf = Btf(bytes(data))
    positions = {tid: pos for tid, (pos, *_rest) in enumerate(walk_types(data, hdr_len, type_off, type_len), 1)}

    head = bytearray(data[:hdr_len + type_off + type_len])
    new_types, new_strings = bytearray(), bytearray()
    next_id = len(positions) + 1
    enums = {}
    done = []

    def intern(name):
        off = str_len + len(new_strings)
        new_strings.extend(name.encode() + b"\0")
        return off

    def copy_enum(ct):
        nonlocal next_id
        if ct.id in enums:
            return enums[ct.id]
        if ct.kind != K_ENUM:
            raise ValueError(f"{ct.name}: only 32-bit enums are copied")
        info = (ct.kflag << 31) | (K_ENUM << 24) | ct.vlen
        new_types.extend(struct.pack("<III", intern(ct.name), info, ct.size))
        for ename, val in ct.enums:
            new_types.extend(struct.pack("<Ii", intern(ename), val))
        enums[ct.id] = next_id
        next_id += 1
        return enums[ct.id]

    ints = {}

    def copy_int(ct):
        nonlocal next_id
        if ct.id not in ints:
            encoding = (ct.int_signed << 24) | ct.int_bits
            new_types.extend(struct.pack("<IIII", intern(ct.name), K_INT << 24, ct.size, encoding))
            ints[ct.id] = next_id
            next_id += 1
        return ints[ct.id]

    for name in names:
        rt, ct = find_struct(btf, name), find_struct(c_btf, name)
        if rt.size != ct.size or rt.vlen != ct.vlen or \
                [m.name for m in rt.members] != [m.name for m in ct.members]:
            raise ValueError(f"{name}: the Rust struct must have the C's size and "
                             "members (names, order)")
        pos = positions[rt.id]
        info = struct.unpack_from("<I", head, pos + 4)[0]
        struct.pack_into("<I", head, pos + 4, (info & 0x7FFFFFFF) | (ct.kflag << 31))
        for k, (rm, cm) in enumerate(zip(rt.members, ct.members)):
            mpos = pos + 12 + k * 12
            rbase, cbase = btf.resolve(rm.type), c_btf.resolve(cm.type)
            if cbase.kind in (K_ENUM, K_ENUM64):
                # the Rust member is the integer the translation reads the
                # (bit)field through; the C's enum takes its place in BTF
                if rbase.kind != K_INT:
                    raise ValueError(f"{name}.{rm.name}: the C enum member needs an integer")
                struct.pack_into("<I", head, mpos + 4, copy_enum(cbase))
            elif cbase.kind == K_INT:
                # a bitfield's Rust integer is the one the translation reads
                # the bits through, which may be narrower than the C's
                # storage unit (`__u16 scale_bitshift: 4` read from a byte):
                # the member then gets a copy of the C's integer type
                if rbase.kind != K_INT:
                    raise ValueError(f"{name}.{rm.name}: the C integer member needs an integer")
                if rbase.size != cbase.size:
                    struct.pack_into("<I", head, mpos + 4, copy_int(cbase))
            elif cbase.kind != rbase.kind or cbase.name != rbase.name:
                raise ValueError(f"{name}.{rm.name}: the member types differ in kind or name")
            raw = (cm.bitfield_size << 24) | cm.bit_offset if ct.kflag else cm.bit_offset
            struct.pack_into("<I", head, mpos + 8, raw)
        done.append(name)

    strings = data[str_base:str_base + str_len]
    out = bytearray(head)
    out.extend(new_types)
    out.extend(strings)
    out.extend(new_strings)
    struct.pack_into("<III", out, 12, type_len + len(new_types),
                     str_off + len(new_types), str_len + len(new_strings))
    align = max(btf_align, 1)
    pad = (-len(buf)) % align
    new_off = len(buf) + pad
    buf.extend(b"\0" * pad)
    buf.extend(out)
    struct.pack_into("<QQ", buf, shdr_base + 24, new_off, len(out))
    Path(path).write_bytes(buf)
    print(f"[btf_c_members] {os.path.basename(path)}: {' '.join(done)}"
          + (f", {len(enums)} enum(s) and {len(ints)} int(s) copied" if enums or ints else ""))


if __name__ == "__main__":
    main(*sys.argv[1:4])
