#!/usr/bin/env python3
"""Show how a C object compares a given global, at every site.

clang does not compile `_Bool` truthiness to one fixed encoding. It emits
`jne 0` at some sites, `jne 1` at others, `(x & 1) != 0` at others, and
sometimes no branch at all — `bool ? 1 : 0` is just the byte, so it passes
the raw byte through. All four have been seen in this corpus, twice within
a single file, so a translation has to mirror each site rather than pick an
encoding. This prints what to mirror.

    scripts/boolsites.py <c-object.bpf.o> <global name>

    test_varlen.bpf.o capture
      capture: section=.bss value=516 size=1
        raw_tp/sys_enter@6:  ldxb r1, [r1] ; and32 r1, 1 ; jeq32 r1, +38
        raw_tp/sys_exit@6:   ldxb r1, [r1] ; and32 r1, 1 ; jeq32 r1, +29

A site with no branch in the printed window means the value is used
directly (the flags-argument case); read a wider window with --window.

Also useful for the reverse check: if the Rust object emits the SAME
sequence, the translint bool-global report is a false positive and should
be suppressed with evidence rather than "fixed" (that is how
timer:async_cancel was cleared).
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "equiv"))

from bpfelf import BpfElf  # noqa: E402

OPS = {0x55: "jne", 0x15: "jeq", 0x56: "jne32", 0x16: "jeq32",
       0x5d: "jne_r", 0x1d: "jeq_r", 0x65: "jsgt", 0x6d: "jsgt_r",
       0x54: "and32", 0x57: "and64", 0x71: "ldxb", 0x69: "ldxh",
       0x61: "ldxw", 0x79: "ldxdw", 0xbf: "mov", 0xb7: "mov_imm",
       0xb4: "mov32_imm", 0xbc: "mov32", 0x84: "neg32", 0x67: "lsh",
       0x77: "rsh", 0x85: "call", 0x95: "exit", 0x63: "stxw",
       0x7b: "stxdw", 0x73: "stxb", 0x6b: "stxh"}


def fmt(op, dst, src, off, imm):
    name = OPS.get(op, f"op{op:#04x}")
    if name in ("ldxb", "ldxh", "ldxw", "ldxdw"):
        return f"{name} r{dst}, [r{src}{off:+d}]"
    if name.startswith(("stx",)):
        return f"{name} [r{dst}{off:+d}], r{src}"
    if name.startswith(("jne", "jeq", "jsgt")):
        rhs = f"r{src}" if name.endswith("_r") else str(imm)
        return f"{name} r{dst}, {rhs}, {off:+d}"
    if name in ("and32", "and64", "lsh", "rsh", "mov_imm", "mov32_imm"):
        return f"{name} r{dst}, {imm}"
    if name in ("mov", "mov32"):
        return f"{name} r{dst}, r{src}"
    if name == "call":
        return f"call {imm}"
    return name


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("object")
    ap.add_argument("symbol")
    ap.add_argument("--window", type=int, default=5,
                    help="instructions to print after the byte load")
    args = ap.parse_args()

    elf = BpfElf(args.object)
    syms = [s for s in elf.symbols if s.name == args.symbol]
    if not syms:
        sys.exit(f"no symbol {args.symbol} in {args.object}")
    sym = syms[0]
    print(f"{args.symbol}: section={elf.sections[sym.shndx].name} "
          f"value={sym.value} size={sym.size}")

    hits = 0
    for sec in elf.exec_sections():
        relocs = elf.relocs.get(sec.idx, {})
        data, n = sec.data, len(sec.data) // 8
        for i in range(n):
            op = data[i * 8]
            if op != 0x18:                       # ld_imm64 of the address
                continue
            rel = relocs.get(i * 8)
            if not rel or rel.sym.name != args.symbol:
                continue
            seq = []
            for j in range(i + 2, min(i + 2 + args.window, n)):
                o, regs, off, imm = struct.unpack_from("<BBhi", data, j * 8)
                seq.append(fmt(o, regs & 0xF, regs >> 4, off, imm))
                if OPS.get(o, "").startswith(("jne", "jeq", "jsgt")):
                    break
            print(f"  {sec.name}@{i}: " + " ; ".join(seq))
            hits += 1
    if not hits:
        print("  (no ld_imm64 relocation names it — inlined constant, or "
              "reached through another symbol)")


if __name__ == "__main__":
    main()
