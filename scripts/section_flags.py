#!/usr/bin/env python3
"""Give a statically linked object the C object's ELF section flags.

libbpf's static linker (bpftool gen object, which builds the selftests'
multi-object skeletons listed in Makefile.skel's `<skel>.skel.h-deps`)
merges same-named sections only when their ELF type and flags are equal
(linker.c secs_match). clang emits `license` and `.maps` as writable data
(SHF_WRITE|SHF_ALLOC); rustc emits the immutable statics that define them
as read-only (SHF_ALLOC), so a Rust object cannot be linked with a C one.
For every section the Rust object shares with the C object (same name and
type), sh_flags is set to the C's, in place: only the 8 flag bytes of the
section header change, nothing moves.

Usage: section_flags.py <rust.bpf.o> <c.bpf.o>
"""
import struct
import sys
from pathlib import Path


def sections(buf):
    assert buf[:4] == b"\x7fELF" and buf[4] == 2 and buf[5] == 1, "not an ELF64-LE object"
    (e_shoff,) = struct.unpack_from("<Q", buf, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 0x3A)

    def shdr(i):
        base = e_shoff + i * e_shentsize
        sh_name, sh_type, sh_flags = struct.unpack_from("<IIQ", buf, base)
        sh_offset, = struct.unpack_from("<Q", buf, base + 24)
        return base, sh_name, sh_type, sh_flags, sh_offset

    _, _, _, _, stroff = shdr(e_shstrndx)
    result = {}
    for i in range(e_shnum):
        base, sh_name, sh_type, sh_flags, _ = shdr(i)
        end = buf.index(b"\0", stroff + sh_name)
        result[buf[stroff + sh_name:end].decode()] = (base, sh_type, sh_flags)
    return result


def main(rust_path, c_path):
    # A concurrent/previous swap must never make Rust its own ABI oracle.
    original = Path(c_path + ".corig")
    c_buf = (original if original.exists() else Path(c_path)).read_bytes()
    buf = bytearray(Path(rust_path).read_bytes())
    c_secs = sections(c_buf)
    changed = []
    for name, (base, sh_type, sh_flags) in sections(buf).items():
        if name not in c_secs or c_secs[name][1] != sh_type:
            continue
        c_flags = c_secs[name][2]
        if c_flags != sh_flags:
            struct.pack_into("<Q", buf, base + 8, c_flags)
            changed.append(f"{name}:{sh_flags:#x}->{c_flags:#x}")
    if changed:
        Path(rust_path).write_bytes(buf)
    print(f"[section_flags] {Path(rust_path).name}: " +
          (", ".join(changed) if changed else "no change"))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
