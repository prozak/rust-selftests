#!/usr/bin/env python3
"""Compare a raw-asm function's instruction stream between two BPF objects.

A `// BPF_NAKED:` translation (scripts/naked_abi.py) carries the C source's
hand-written asm verbatim, so the built object must hold the same
instructions as the C object, in the same section: the only permitted
difference is the relocation bookkeeping of an `ld_imm64` or `call` whose
immediate is patched by libbpf (a map, a subprogram, a kfunc), and there
the two relocations must name the same symbol.

Usage: naked_verbatim.py <c.bpf.o> <rust.bpf.o> <function>...
       (no functions: every `// BPF_NAKED:` is read from the translation
       named like the Rust object, progs/<name>.rs)
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "equiv"))
from bpfelf import BpfElf  # noqa: E402

STT_FUNC = 2
STT_SECTION = 3
LD_IMM64 = 0x18


def function(elf, name):
    """(section name, bytes, {offset within the function: symbol name}) of
    a defined FUNC symbol, or None."""
    sym = next((s for s in elf.symbols
                if s.name == name and s.type == STT_FUNC
                and 0 < s.shndx < len(elf.sections)), None)
    if sym is None:
        return None
    sec = elf.sections[sym.shndx]
    data = sec.data[sym.value:sym.value + sym.size]
    relocs = {}
    for off, r in elf.relocs.get(sym.shndx, {}).items():
        if sym.value <= off < sym.value + sym.size:
            target = r.sym
            if target.type == STT_SECTION:
                imm = int.from_bytes(data[off - sym.value + 4:off - sym.value + 8], "little", signed=True)
                if len(data) >= off - sym.value + 16 and data[off - sym.value] == LD_IMM64:
                    hi = int.from_bytes(data[off - sym.value + 12:off - sym.value + 16], "little", signed=True)
                    imm = (imm & 0xFFFFFFFF) | (hi << 32)
                named = elf.named_symbol_at(target.shndx, imm)
                target_name = named.name if named else f"{elf.sections[target.shndx].name}+{imm}"
            else:
                target_name = target.name
            relocs[off - sym.value] = target_name
    return sec.name, data, relocs


def compare(c_elf, r_elf, name):
    """Differences between the C and Rust objects' instruction streams for
    function `name`, as a list of strings (empty: verbatim)."""
    c, r = function(c_elf, name), function(r_elf, name)
    if c is None or r is None:
        return [f"{name}: not a function of the {'C' if c is None else 'Rust'} object"]
    (csec, cdata, crel), (rsec, rdata, rrel) = c, r
    if csec != rsec:
        return [f"{name}: section {rsec!r}, C has {csec!r}"]
    if len(cdata) != len(rdata):
        return [f"{name}: {len(rdata) // 8} insns, C has {len(cdata) // 8}"]
    out, off, idx = [], 0, 0
    while off + 8 <= len(cdata):
        width = 16 if cdata[off] == LD_IMM64 else 8
        ci, ri = bytearray(cdata[off:off + width]), bytearray(rdata[off:off + width])
        cr, rr = crel.get(off), rrel.get(off)
        if (cr is None) != (rr is None):
            out.append(f"{name} insn {idx}: relocation against {rr!r}, C against {cr!r}")
        elif cr is not None and cr != rr:
            out.append(f"{name} insn {idx}: relocation against {rr!r}, C against {cr!r}")
        if cr is not None or rr is not None:
            ci[4:8] = b"\0\0\0\0"
            ri[4:8] = b"\0\0\0\0"
            if width == 16:
                ci[12:16] = b"\0\0\0\0"
                ri[12:16] = b"\0\0\0\0"
        if ci != ri:
            out.append(f"{name} insn {idx}: {ri.hex()}, C has {ci.hex()}")
        off += width
        idx += 1
        if len(out) > 8:
            out.append(f"{name}: ...")
            break
    return out


def naked_names(rs_path):
    with open(rs_path) as fh:
        return re.findall(r"^// BPF_NAKED: ([A-Za-z_][A-Za-z_0-9]*)\s*$", fh.read(), re.M)


def main(argv):
    if len(argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    c_elf, r_elf = BpfElf(argv[1]), BpfElf(argv[2])
    names = argv[3:]
    if not names:
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        stem = os.path.basename(argv[2]).split(".")[0]
        names = naked_names(os.path.join(repo, "progs", stem + ".rs"))
    diffs = [d for n in names for d in compare(c_elf, r_elf, n)]
    for d in diffs:
        print(d)
    if not diffs:
        print(f"{len(names)} function(s) verbatim")
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
