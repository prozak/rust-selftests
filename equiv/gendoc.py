#!/usr/bin/env python3
"""Generate equiv/SEMANTICS.md: how each BPF construct becomes a Z3 term.

Every entry runs the REAL Executor over a tiny synthetic program and
prints what came out — path conditions, the returned expression, and any
observable the program touched. Nothing here is hand-written prose about
the encoding, so the document cannot drift from the model: regenerate it
and any change to the lifter shows up as a diff.

    equiv/gendoc.py            # write equiv/SEMANTICS.md
    equiv/gendoc.py --check    # exit 1 if the file is out of date (CI)
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import z3

import check as _check
from bpfsym import Executor
from testkit import FakeElf, SEC_NAME, asm

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "SEMANTICS.md")

R0, R1, R2, R3, R4, R6, R10 = 0, 1, 2, 3, 4, 6, 10
MAP1 = {"m": {"key_size": 4, "value_size": 8, "map_type": 1,
              "max_entries": 2, "inner": None}}


def E(name, category, code, note, hsigs=None, **kw):
    return dict(name=name, category=category, code=code, note=note,
                hsigs=hsigs, kw=kw)


# generic (prototype-driven) helper signatures, in check.helper_sigs()'s
# shape — spelled out so the doc builds without a kernel BTF
HSIGS = {
    44: ("bpf_xdp_adjust_head", [(True, 56, None), (False, None, 4)], 4),
    120: ("bpf_get_ns_current_pid_tgid",
          [(False, None, 8), (False, None, 8), (True, 8, None),
           (False, None, 4)], 4),
    161: ("bpf_ima_inode_hash", [(True, 1088, None), (True, None, 2),
                                 (False, None, 4)], 4),
}


ENTRIES = [
    # ------------------------------------------------------------ registers
    E("Immediate move and return", "Core ISA",
      asm.prog(asm.mov64_imm(R0, 42), asm.exit_()),
      "A constant reaches r0 as a 64-bit bitvector literal; EXIT records "
      "one path whose return expression is that literal."),
    E("Register arithmetic", "Core ISA",
      asm.prog(asm.mov64_imm(R0, 6), asm.add64_imm(R0, 1), asm.exit_()),
      "ALU64 operations fold into the term as bitvector arithmetic; Z3 "
      "simplifies the constant chain, which is why a differently-written "
      "but equal computation still proves equivalent."),
    E("32-bit sub-register semantics", "Core ISA",
      asm.prog(asm.mov64_imm(R0, -1), asm.raw(0x04, R0, imm=0),
               asm.exit_()),
      "ALU32 writes zero-extend into the 64-bit register, exactly as the "
      "hardware does — the upper half is cleared, not preserved."),
    E("Bit masking", "Core ISA",
      asm.prog(asm.ldx(8, R1, R1, 0), asm.and64_imm(R1, 0xFF),
               asm.mov64_reg(R0, R1), asm.exit_()),
      "Masking a loaded word keeps the mask in the term, so a translation "
      "that narrows a value the C object tests in full is distinguishable."),

    # -------------------------------------------------------------- memory
    E("Context read", "Memory",
      asm.prog(asm.ldx(4, R0, R1, 16), asm.exit_()),
      "r1 enters as Ptr(\"ctx\", 0). A load becomes a Concat of Select "
      "terms over the shared `ctx` array — both objects read the same "
      "array, so reading a different offset is what makes them differ."),
    E("Stack round-trip", "Memory",
      asm.prog(asm.mov64_imm(R1, 7), asm.stx(8, R10, R1, -8),
               asm.ldx(8, R0, R10, -8), asm.exit_()),
      "The stack is a per-run region seeded from one shared `stack_init` "
      "array, so uninitialized residue is identical for both objects "
      "while writes stay private to each run."),
    E("Kernel memory through a data pointer", "Memory",
      asm.prog(asm.ldx(8, R2, R1, 0), asm.ldx(8, R0, R2, 24),
               asm.exit_()),
      "A pointer loaded out of the ctx is an ordinary bitvector, so "
      "dereferencing it reads the shared `kmem` array at that symbolic "
      "address. Stores through it write kmem, which is an observable."),

    # --------------------------------------------------------------- paths
    E("Conditional branch", "Paths",
      asm.prog(asm.ldx(8, R1, R1, 0), asm.jeq_imm(R1, 0, 2),
               asm.mov64_imm(R0, 1), asm.exit_(),
               asm.mov64_imm(R0, 2), asm.exit_()),
      "A symbolic branch forks execution; each path carries its own "
      "condition list, and the final query ITE-folds the paths so one "
      "solver call covers every execution."),
    E("Infeasible branch is pruned", "Paths",
      asm.prog(asm.mov64_imm(R1, 5), asm.jeq_imm(R1, 0, 1),
               asm.mov64_imm(R0, 1), asm.exit_()),
      "Feasibility is checked before queueing a side, so a branch that "
      "cannot be taken produces no path at all."),

    # ------------------------------------------------------------- helpers
    E("Environment read (shared oracle)", "Helpers",
      asm.prog(asm.call(5), asm.exit_()),
      "Argument-free environment helpers return an uninterpreted function "
      "applied to the call index. The SAME function is used for both "
      "objects, so the nth call agrees — that is what makes a program "
      "using ktime provable at all, and what makes an EXTRA call a "
      "detectable difference."),
    E("Side-effecting helper (trace event)", "Helpers",
      asm.prog(asm.ld_imm64(R1, 0), asm.mov64_imm(R2, 4), asm.call(6),
               asm.mov64_imm(R0, 0), asm.exit_()),
      "A side-effecting call appends [helper id][len][payload] to the "
      "shared `trace` region at a concrete cursor. Trace equality is an "
      "observable, so the call sequence and its arguments must match; a "
      "dropped call leaves symbolic residue that some input exposes.",
      rodata=b"hi\x00\x00", relocs={0: ".rodata"}),
    E("Nullable pointer helper (path fork)", "Helpers",
      asm.prog(asm.ld_imm64(R1, 0), asm.mov64_reg(R2, R10),
               asm.add64_imm(R2, -8), asm.call(1),
               asm.jeq_imm(R0, 0, 1), asm.ldx(8, R0, R0, 0),
               asm.exit_()),
      "map_lookup emits its question as a trace event and then forks on a "
      "shared per-index NULL oracle, so in any single model both objects' "
      "nth lookup takes the same branch. The non-null side points into a "
      "per-index `mapval:` region whose final contents are observable.",
      maps=MAP1, relocs={0: "m"}),
    E("Generic helper, prototype-driven", "Helpers",
      asm.prog(asm.mov64_imm(R2, 4), asm.call(44),
               asm.mov64_imm(R0, 0), asm.exit_()),
      "A helper with no bespoke model is driven by its prototype in the "
      "kernel's UAPI header. Each argument enters the trace event the way "
      "the KERNEL reads it: `int delta` is compared as 32 bits, so a "
      "difference confined to the upper half of the register — which the "
      "helper never sees — does not count as one. The context pointer is "
      "compared by identity, its contents already being an observable.",
      hsigs=HSIGS),
    E("Generic helper with a private buffer", "Helpers",
      asm.prog(asm.mov64_imm(R1, 0), asm.mov64_imm(R2, 0),
               asm.mov64_reg(R3, R10), asm.add64_imm(R3, -8),
               asm.mov64_imm(R4, 8), asm.call(120),
               asm.ldx(8, R0, R10, -8), asm.exit_()),
      "A pointer into private memory has its bytes captured, but as "
      "(written?, value) pairs: an output buffer holds only uninitialized "
      "residue at call time, and the two objects place their locals at "
      "different frame offsets, so comparing that residue would invent a "
      "divergence. The buffer is then havocked with a shared per-call "
      "value, which is why the load afterwards reads an oracle term "
      "rather than each object's own stack.",
      hsigs=HSIGS),
    E("Generic helper with a length-paired buffer", "Helpers",
      asm.prog(asm.mov64_imm(R1, 0), asm.st_imm(8, R10, -8, 1),
               asm.mov64_reg(R2, R10), asm.add64_imm(R2, -8),
               asm.mov64_imm(R3, 8), asm.call(161),
               asm.mov64_imm(R0, 0), asm.exit_()),
      "`bpf_ima_inode_hash(struct inode *, void *dst, u32 size)`: a `void "
      "*` has no extent of its own, but the prototype states it "
      "positionally in the next argument. That argument is what the model "
      "captures — a symbolic one bails, since guessing how much the kernel "
      "reads is exactly the kind of assumption this checker refuses.",
      hsigs=HSIGS),
]


def render_entry(e):
    elf = FakeElf(e["code"], **e["kw"])
    shared, _ = _check.global_regions({"A": elf})
    for nm, arr in (("ctx", "ctx"), ("kmem", "kmem"),
                    ("trace", "trace_init"), ("skbdata", "skbdata"),
                    ("sysret", "sysret")):
        shared[nm] = z3.Array(arr, z3.BitVecSort(64), z3.BitVecSort(8))
    ex = Executor(elf, elf.section_by_name(SEC_NAME), shared, "A",
                  helper_sigs=e["hsigs"])
    paths = ex.run(0)
    baseline = dict(shared)

    out = [f"### {e['name']}", "", e["note"], "", "```"]
    for i, ins in enumerate(_disasm(e["code"])):
        out.append(f"  {i:2d}  {ins}")
    out += ["```", "", f"*{len(paths)} path(s):*", ""]
    for i, p in enumerate(paths):
        conds = " ∧ ".join(str(z3.simplify(c)) for c in p.conds) or "(none)"
        out.append(f"- path {i}: `{_short(conds)}`")
        out.append(f"  - returns `{_short(str(z3.simplify(p.ret)))}`")
        # a region appears in mem as soon as it is READ (it gets cached
        # there), so report only regions whose array actually changed
        written = [r for r, arr in p.mem.items()
                   if isinstance(r, str)
                   and not (r in baseline and arr is baseline[r])]
        if written:
            out.append(f"  - writes: {', '.join(sorted(written))}")
    out.append("")
    return "\n".join(out)


def _short(s, limit=220):
    s = " ".join(s.split())
    return s if len(s) <= limit else s[:limit] + " …"


_OPS = {0xB7: "mov64 r{d}, {i}", 0xBF: "mov64 r{d}, r{s}",
        0xB4: "mov32 r{d}, {i}", 0x07: "add64 r{d}, {i}",
        0x0F: "add64 r{d}, r{s}", 0x57: "and64 r{d}, {i}",
        0x04: "add32 r{d}, {i}", 0x67: "lsh64 r{d}, {i}",
        0x61: "ldxw r{d}, [r{s}{o:+}]", 0x79: "ldxdw r{d}, [r{s}{o:+}]",
        0x71: "ldxb r{d}, [r{s}{o:+}]", 0x69: "ldxh r{d}, [r{s}{o:+}]",
        0x63: "stxw [r{d}{o:+}], r{s}", 0x7B: "stxdw [r{d}{o:+}], r{s}",
        0x73: "stxb [r{d}{o:+}], r{s}", 0x6B: "stxh [r{d}{o:+}], r{s}",
        0x62: "stw [r{d}{o:+}], {i}", 0x7A: "stdw [r{d}{o:+}], {i}",
        0x15: "if r{d} == {i} goto {o:+}", 0x55: "if r{d} != {i} goto {o:+}",
        0x25: "if r{d} > {i} goto {o:+}", 0x65: "if r{d} s> {i} goto {o:+}",
        0x05: "goto {o:+}", 0x85: "call {i}", 0x95: "exit",
        0x18: "lddw r{d}, ...", 0x00: "  (lddw high half)"}


def _disasm(code):
    import struct
    out = []
    for i in range(len(code) // 8):
        op, regs, off, imm = struct.unpack_from("<BBhi", code, i * 8)
        fmt = _OPS.get(op, f"opcode {op:#04x}")
        out.append(fmt.format(d=regs & 0xF, s=regs >> 4, o=off, i=imm))
    return out


def build():
    doc = ["# How BPF constructs become Z3 terms",
           "",
           "**Generated by `equiv/gendoc.py` — do not edit by hand.**",
           "Run `make semantics` to regenerate. Each example below is a real",
           "run of the lifter in `equiv/bpfsym.py` over a tiny synthetic",
           "program, so this file is a faithful, diffable record of the",
           "encoding: if a model change alters how something is represented,",
           "it shows up here as a reviewable diff.",
           "",
           "The prose in `equiv/README.md` explains *why* each encoding is",
           "sound; this file shows *what* it produces.",
           ""]
    by_cat = {}
    for e in ENTRIES:
        by_cat.setdefault(e["category"], []).append(e)
    for cat, entries in by_cat.items():
        doc.append(f"## {cat}")
        doc.append("")
        for e in entries:
            doc.append(render_entry(e))
    return "\n".join(doc).rstrip() + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if SEMANTICS.md is stale")
    args = ap.parse_args()
    text = build()
    if args.check:
        current = open(OUT).read() if os.path.exists(OUT) else ""
        if current != text:
            print("SEMANTICS.md is out of date — run `make semantics`")
            return 1
        print("SEMANTICS.md is up to date")
        return 0
    with open(OUT, "w") as f:
        f.write(text)
    print(f"wrote {os.path.relpath(OUT, os.path.dirname(HERE))} "
          f"({len(ENTRIES)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
