#!/usr/bin/env python3
"""Give a struct member declared `*const c_void` the BTF type of a function
pointer.

C can leave a function-pointer member of a static struct NULL, as
struct_ops_forgotten_cb.c's `struct bpf_testmod_ops ops = { }` does: libbpf
skips the NULL member, and bpftool's skeleton still exposes `test_1` as a
settable `struct bpf_program *` because the member's BTF is a pointer to a
FUNC_PROTO. A Rust `fn` value cannot be null, and `Option<fn>` in such a
struct is an enum to the BTF emitter, so the translation declares the member
`*const c_void` and names the function whose signature it carries:

    // BTF_FN_PTR: bpf_testmod_ops.test_1 = test_1_forgotten

The member's type becomes a PTR to that FUNC's FUNC_PROTO (appended, so no
existing type moves, as in btf_map_slots.py). The function must be in the
object; the member must be a pointer.

Usage: btf_fn_ptrs.py <obj.bpf.o> <source.rs>
"""
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from btf_map_slots import MODS, walk  # noqa: E402
from btf_test_tags import elf_find_section  # noqa: E402

BTF_KIND_PTR, BTF_KIND_STRUCT, BTF_KIND_UNION, BTF_KIND_FUNC = 2, 4, 5, 12
DECL = re.compile(r"^// BTF_FN_PTR: ([A-Za-z_]\w*)\.([A-Za-z_]\w*) = ([A-Za-z_]\w*)\s*$", re.M)


def declarations(source):
    return [(m.group(1), m.group(2), m.group(3)) for m in DECL.finditer(source)]


def patch(path, decls):
    if not decls:
        return []
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
    next_tid = max(types) + 1

    def resolve(tid):
        while tid in types and types[tid][1] in MODS:
            tid = struct.unpack_from("<I", data, types[tid][0] + 8)[0]
        return tid

    def named(kind_set, name):
        return [tid for tid, (pos, kind, _v) in types.items()
                if kind in kind_set and get_str(struct.unpack_from("<I", data, pos)[0]) == name]

    new_types, done, ptr_of = bytearray(), [], {}
    for sname, mname, fname in decls:
        funcs = named({BTF_KIND_FUNC}, fname)
        if len(funcs) != 1:
            raise SystemExit(f"[btf_fn_ptrs] ERROR: {os.path.basename(path)}: expected one FUNC {fname}, found {len(funcs)}")
        proto = struct.unpack_from("<I", data, types[funcs[0]][0] + 8)[0]
        structs = named({BTF_KIND_STRUCT, BTF_KIND_UNION}, sname)
        if len(structs) != 1:
            raise SystemExit(f"[btf_fn_ptrs] ERROR: {os.path.basename(path)}: expected one struct {sname}, found {len(structs)}")
        st_pos, _k, nmemb = types[structs[0]]
        for i in range(nmemb):
            mpos = st_pos + 12 + i * 12
            m_name_off, m_type = struct.unpack_from("<II", data, mpos)
            if get_str(m_name_off) != mname:
                continue
            if types.get(resolve(m_type), (0, 0, 0))[1] != BTF_KIND_PTR:
                raise SystemExit(f"[btf_fn_ptrs] ERROR: {os.path.basename(path)}: {sname}.{mname} is not a pointer")
            if proto not in ptr_of:
                ptr_of[proto] = next_tid + len(new_types) // 12
                new_types.extend(struct.pack("<III", 0, BTF_KIND_PTR << 24, proto))
            struct.pack_into("<I", data, mpos + 4, ptr_of[proto])
            done.append(f"{sname}.{mname}={fname}")
            break
        else:
            raise SystemExit(f"[btf_fn_ptrs] ERROR: {os.path.basename(path)}: {sname} has no member {mname}")

    out = bytearray(data[:hdr_len + type_off + type_len])
    out.extend(new_types)
    out.extend(data[str_base:str_base + str_len])
    struct.pack_into("<II", out, 12, type_len + len(new_types), str_off + len(new_types))
    pad = (-len(buf)) % max(btf_align, 1)
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
    done = patch(argv[1], declarations(open(argv[2]).read()))
    if done:
        print(f"[btf_fn_ptrs] {os.path.basename(argv[1])}: " + ", ".join(done))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
