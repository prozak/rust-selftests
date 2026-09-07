#!/usr/bin/env python3
"""Emit the BTF type tags (__kptr and friends) for a Rust-built object.

bpf_misc.h's `__kptr` / `__kptr_untrusted` / `__percpu_kptr` / `__uptr` are
`__attribute__((btf_type_tag("...")))` on a struct member's pointer type, and
clang emits them as a BTF_KIND_TYPE_TAG between the member's PTR and the
pointee STRUCT:

    [15] STRUCT 'rcu_node_stash' size=8 vlen=1
            'node' type_id=17 bits_offset=0
    [16] TYPE_TAG 'kptr' type_id=18
    [17] PTR '(anon)' type_id=16
    [18] STRUCT 'rcu_node_data' size=40 vlen=2

The kernel reads that tag to classify the field (kernel/bpf/btf.c:
btf_find_kptr); without it a load from the member is a plain scalar and any
dereference is rejected. rustc has no way to annotate a pointer type, so the
translation declares the tags in the source with bpf-rs-core's
`btf_type_tags!` macro (which expands to nothing) and this pass rewrites the
built object's .BTF:

    btf_type_tags! {
        rcu_node_stash.node: kptr;
    }

Like btf_test_tags.py the change is append-only for type ids and strings: a
TYPE_TAG and a PTR through it are added after every existing type, and the
member's 4-byte type id is overwritten in place to point at the new PTR. No
existing type's bytes move, so .BTF.ext stays valid; the grown blob is
appended at EOF with the section header repointed.

Usage: btf_type_tags.py <obj.bpf.o> <prog.rs>
"""

import os
import re
import struct
import sys

from btf_test_tags import (FIXED_EXTRA, PER_VLEN, TagError, _split_top,
                           _strip_noise, elf_find_section)

BTF_KIND_PTR = 2
BTF_KIND_STRUCT = 4
BTF_KIND_UNION = 5
BTF_KIND_TYPE_TAG = 18
MODIFIERS = {8, 9, 10, 11, 18}   # VOLATILE CONST RESTRICT (TYPEDEF) TYPE_TAG

# kptr tags recognized by btf_get_field_type, plus the arena annotation
# used by aggregate-return validation. Unknown names remain hard errors.
KNOWN_TAGS = {"kptr", "kptr_untrusted", "percpu_kptr", "uptr", "arena"}


# --- Source parsing ---------------------------------------------------------

def parse_source(path):
    """Read the btf_type_tags! declaration from a .rs translation.

    Returns [(struct_name, member_name, tag), ...] in source order, or []
    when the translation declares none.
    """
    src = open(path, encoding="utf-8").read()
    mask = _strip_noise(src)
    hits = [m for m in re.finditer(r"\bbtf_type_tags\s*!", mask)]
    if not hits:
        return []
    if len(hits) > 1:
        raise TagError(f"{path}: more than one btf_type_tags! declaration")

    i = hits[0].end()
    while i < len(mask) and mask[i].isspace():
        i += 1
    if i >= len(mask) or mask[i] not in "({[":
        raise TagError(f"{path}: btf_type_tags! is not followed by a delimiter")
    opener, closer = mask[i], {"(": ")", "{": "}", "[": "]"}[mask[i]]
    depth, j = 0, i
    while j < len(mask):
        if mask[j] == opener:
            depth += 1
        elif mask[j] == closer:
            depth -= 1
            if depth == 0:
                break
        j += 1
    if depth:
        raise TagError(f"{path}: unterminated btf_type_tags! body")
    body, bmask = src[i + 1:j], mask[i + 1:j]

    entries = []
    for stmt in _split_top(body, ";", bmask):
        if not stmt.strip():
            continue
        m = re.fullmatch(
            r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)"
            r"\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*", stmt)
        if not m:
            raise TagError(f"{path}: unparsable entry {stmt.strip()!r} "
                           "(expected `struct.member: tag`)")
        sname, mname, tag = m.groups()
        if tag not in KNOWN_TAGS:
            raise TagError(f"{path}: unknown type tag {tag!r} on "
                           f"{sname}.{mname} (known: {', '.join(sorted(KNOWN_TAGS))})")
        entries.append((sname, mname, tag))
    if not entries:
        raise TagError(f"{path}: empty btf_type_tags! declaration")
    return entries


# --- BTF surgery ------------------------------------------------------------

def walk_types(data, hdr_len, type_off, type_len):
    """[(pos, kind, name_off, size_or_type, vlen)] indexed by type id - 1."""
    out, pos, end = [], hdr_len + type_off, hdr_len + type_off + type_len
    while pos < end:
        name_off, info, sz = struct.unpack_from("<III", data, pos)
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        out.append((pos, kind, name_off, sz, vlen))
        extra = FIXED_EXTRA.get(kind)
        if extra is None:
            extra = vlen * PER_VLEN[kind]
        pos += 12 + extra
    return out


def inject(path, entries):
    buf = bytearray(open(path, "rb").read())
    shdr_base, btf_off, btf_size, btf_align = elf_find_section(buf, ".BTF")
    data = bytearray(buf[btf_off:btf_off + btf_size])

    magic, _ver, _flags, hdr_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", data, 0)
    assert magic == 0xEB9F, hex(magic)
    str_base = hdr_len + str_off
    assert str_base + str_len == len(data), "string table not at end of .BTF"

    def get_str(off):
        end = data.index(b"\0", str_base + off)
        return data[str_base + off:end].decode()

    types = walk_types(data, hdr_len, type_off, type_len)
    obj = os.path.basename(path)

    def find_struct(name):
        hits = [tid for tid, (_p, kind, name_off, _sz, vlen) in enumerate(types, 1)
                if kind in (BTF_KIND_STRUCT, BTF_KIND_UNION) and vlen
                and get_str(name_off) == name]
        if not hits:
            raise TagError(f"{obj}: no BTF struct named {name!r}")
        if len(hits) > 1:
            raise TagError(f"{obj}: {len(hits)} BTF structs named {name!r}")
        return hits[0]

    head = bytearray(data[:hdr_len + type_off + type_len])
    new_types, new_strings = bytearray(), bytearray()
    next_id = len(types) + 1
    done = []
    for sname, mname, tag in entries:
        sid = find_struct(sname)
        pos, _kind, _n, _sz, vlen = types[sid - 1]
        member = None
        for k in range(vlen):
            mpos = pos + 12 + k * 12
            m_name, m_type, _m_off = struct.unpack_from("<III", data, mpos)
            if get_str(m_name) == mname:
                member = (mpos, m_type)
                break
        if member is None:
            raise TagError(f"{obj}: struct {sname} has no member {mname!r}")
        mpos, ptr_id = member
        array = None
        if tag == "arena" and types[ptr_id - 1][1] == 3:
            apos = types[ptr_id - 1][0]
            array = bytes(data[apos:apos + 24])
            ptr_id = struct.unpack_from("<I", array, 12)[0]
        if types[ptr_id - 1][1] != BTF_KIND_PTR:
            raise TagError(f"{obj}: {sname}.{mname} is not a pointer, "
                           "a type tag applies to a pointer member")
        pointee = types[ptr_id - 1][3]
        t = pointee
        while t and types[t - 1][1] in MODIFIERS:
            if types[t - 1][1] == BTF_KIND_TYPE_TAG:
                raise TagError(f"{obj}: {sname}.{mname} already carries a "
                               f"type tag {get_str(types[t - 1][2])!r}")
            t = types[t - 1][3]
        if tag != "arena" and (not t or types[t - 1][1] not in (BTF_KIND_STRUCT, BTF_KIND_UNION)):
            raise TagError(f"{obj}: {sname}.{mname} does not point at a "
                           "struct; the kernel only classifies struct kptrs")

        tag_off = str_len + len(new_strings)
        new_strings.extend(tag.encode() + b"\0")
        new_types.extend(struct.pack("<III", tag_off, BTF_KIND_TYPE_TAG << 24, pointee))
        tag_id = next_id
        next_id += 1
        new_types.extend(struct.pack("<III", 0, BTF_KIND_PTR << 24, tag_id))
        struct.pack_into("<I", head, mpos + 4, next_id)
        next_id += 1
        if array is not None:
            cloned = bytearray(array)
            struct.pack_into("<I", cloned, 12, next_id - 1)
            new_types.extend(cloned)
            struct.pack_into("<I", head, mpos + 4, next_id)
            next_id += 1
        done.append(f"{sname}.{mname}:{tag}")

    strings = data[str_base:str_base + str_len]
    out = bytearray(head)
    out.extend(new_types)
    out.extend(strings)
    out.extend(new_strings)
    struct.pack_into("<III", out, 12,
                     type_len + len(new_types),
                     str_off + len(new_types),
                     str_len + len(new_strings))

    align = max(btf_align, 1)
    pad = (-len(buf)) % align
    new_off = len(buf) + pad
    buf.extend(b"\0" * pad)
    buf.extend(out)
    struct.pack_into("<QQ", buf, shdr_base + 24, new_off, len(out))
    open(path, "wb").write(buf)
    return done


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    obj, src = argv[1], argv[2]
    try:
        entries = parse_source(src)
        if not entries:
            return 0
        done = inject(obj, entries)
    except TagError as e:
        print(f"[btf_type_tags] ERROR: {e}", file=sys.stderr)
        return 1
    print(f"[btf_type_tags] {os.path.basename(obj)}: {' '.join(done)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
