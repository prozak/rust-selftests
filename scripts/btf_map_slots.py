#!/usr/bin/env python3
"""Make a Rust-built object's statically-initialized prog-array / map-in-map
slots visible to libbpf.

libbpf's `__array(values, ...)` idiom asks one BTF struct to say two
contradictory things: the `values` member must be a ZERO-length array
(parse_btf_map_def rejects anything else -- "prog-array value spec is not a
zero-sized array"), yet the map's `.maps` storage must be long enough to hold
one pointer per slot, because bpf_object__collect_map_relos derives the slot
index from the RELOCATION offset against that storage. clang gets both by
widening the LLVM global's codegen type past its debuginfo type; a Rust
static's IR type and its DIType always come from the same declaration, so
`[Fn; 0]` gives a valid BTF and no storage, `[Fn; 1]` gives storage and a BTF
libbpf rejects.

Declare `[Fn; N]` -- rustc then emits byte-identical .maps storage and
.rel.maps entries to clang's -- and rewrite the BTF here. For each `.maps`
struct whose last member is `values` and resolves to a non-empty ARRAY, we
append an otherwise identical zero-length ARRAY and repoint the member at it.
Appending is safe for the same reason it is in btf_test_tags.py: new type ids
come after every existing one, no existing type's bytes move, and the member
edit is a 4-byte in-place field write. The member is repointed rather than the
array patched in place because rustc shares one ARRAY type across every map
with the same slot type.

Usage: btf_map_slots.py <obj.bpf.o>
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from btf_test_tags import FIXED_EXTRA, PER_VLEN, elf_find_section

BTF_KIND_ARRAY = 3
BTF_KIND_STRUCT = 4
BTF_KIND_VAR = 14
BTF_KIND_DATASEC = 15
MODS = (8, 9, 10, 11, 18)          # CONST, RESTRICT, VOLATILE, TYPEDEF, TYPE_TAG


def walk(data, hdr_len, type_off, type_len):
    """Yield (type id, byte offset in `data`, kind, vlen) for every BTF type."""
    pos, end, tid = hdr_len + type_off, hdr_len + type_off + type_len, 1
    while pos < end:
        _name_off, info, _sz = struct.unpack_from("<III", data, pos)
        kind, vlen = (info >> 24) & 0x1F, info & 0xFFFF
        yield tid, pos, kind, vlen
        extra = FIXED_EXTRA.get(kind)
        if extra is None:
            extra = vlen * PER_VLEN[kind]
        pos += 12 + extra
        tid += 1


def patch(path):
    buf = bytearray(open(path, "rb").read())
    shdr_base, btf_off, btf_size, btf_align = elf_find_section(buf, ".BTF")
    data = bytearray(buf[btf_off:btf_off + btf_size])

    magic, _ver, _flags, hdr_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", data, 0)
    assert magic == 0xEB9F, hex(magic)
    str_base = hdr_len + str_off
    assert str_base + str_len == len(data), "string table not at end of .BTF"

    def get_str(off):
        return data[str_base + off:data.index(b"\0", str_base + off)].decode()

    types = {tid: (pos, kind, vlen)
             for tid, pos, kind, vlen in walk(data, hdr_len, type_off, type_len)}
    next_tid = max(types) + 1 if types else 1

    def resolve(tid):
        while tid in types and types[tid][1] in MODS:
            tid = struct.unpack_from("<I", data, types[tid][0] + 8)[0]
        return tid

    # The .maps DATASEC lists exactly the map definitions libbpf will parse.
    maps = []
    for tid, (pos, kind, vlen) in types.items():
        if kind != BTF_KIND_DATASEC:
            continue
        name_off, = struct.unpack_from("<I", data, pos)
        if get_str(name_off) != ".maps":
            continue
        for i in range(vlen):
            var_tid, = struct.unpack_from("<I", data, pos + 12 + i * 12)
            maps.append(var_tid)

    new_types, patched = bytearray(), []
    zero_of = {}
    for var_tid in maps:
        if var_tid not in types or types[var_tid][1] != BTF_KIND_VAR:
            continue
        var_pos = types[var_tid][0]
        var_name = get_str(struct.unpack_from("<I", data, var_pos)[0])
        st = resolve(struct.unpack_from("<I", data, var_pos + 8)[0])
        if st not in types or types[st][1] != BTF_KIND_STRUCT:
            continue
        st_pos, _k, nmemb = types[st]
        if not nmemb:
            continue
        mpos = st_pos + 12 + (nmemb - 1) * 12          # last member
        mname_off, mtype = struct.unpack_from("<II", data, mpos)
        if get_str(mname_off) != "values":
            continue
        arr = resolve(mtype)
        if arr not in types or types[arr][1] != BTF_KIND_ARRAY:
            continue
        elem, index, nelems = struct.unpack_from("<III", data, types[arr][0] + 12)
        if nelems == 0:
            continue
        if arr not in zero_of:
            zero_of[arr] = next_tid + len(new_types) // 24
            new_types.extend(struct.pack("<III", 0, BTF_KIND_ARRAY << 24, 0))
            new_types.extend(struct.pack("<III", elem, index, 0))
        struct.pack_into("<I", data, mpos + 4, zero_of[arr])
        patched.append((var_name, nelems))

    if not patched:
        return []

    out = bytearray(data[:hdr_len + type_off + type_len])
    out.extend(new_types)
    out.extend(data[str_base:str_base + str_len])
    struct.pack_into("<II", out, 12,
                     type_len + len(new_types), str_off + len(new_types))

    pad = (-len(buf)) % max(btf_align, 1)
    new_off = len(buf) + pad
    buf.extend(b"\0" * pad)
    buf.extend(out)
    struct.pack_into("<QQ", buf, shdr_base + 24, new_off, len(out))
    open(path, "wb").write(buf)
    return patched


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    patched = patch(argv[1])
    if patched:
        print(f"[btf_map_slots] {os.path.basename(argv[1])}: "
              + ", ".join(f"{n} ({e} slot(s))" for n, e in patched))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
