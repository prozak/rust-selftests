#!/usr/bin/env python3
"""Compare the bytecode clang and rustc emit for the SAME program.

    codegen/compare.py                 # analyse, write pairs.tsv + REPORT.md
    codegen/compare.py --all           # every paired program, not just proved ones
    codegen/compare.py --show <prog>:<func>   # side-by-side listing of one pair

By default only programs the equivalence checker has PROVED equivalent are
measured (equiv/results/baseline.tsv). That restriction is what makes the
numbers mean something: the two builds are known to compute the same thing,
so every instruction of difference is a codegen difference, not a
translation difference.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "equiv"))
sys.path.insert(0, HERE)

import check                                   # noqa: E402
from bpfelf import BpfElf                       # noqa: E402
import insns as I                               # noqa: E402

C_DIR = check.DEFAULT_C_DIR
R_DIR = os.path.join(REPO, "bld")
BASELINE = os.path.join(REPO, "equiv", "results", "baseline.tsv")
WAIVERS = os.path.join(REPO, "equiv", "waivers.tsv")

# order the report columns by what they diagnose
KINDS = ["alu64", "alu32", "ldx_stack", "stx_stack", "ldx_mem", "stx_mem",
         "ld_imm64", "branch", "goto", "call_helper", "call_bpf2bpf",
         "call_kfunc", "atomic", "endian", "exit", "ld_abs_ind", "other"]


def proved_objects():
    """Objects whose every program the checker proved equivalent."""
    if not os.path.exists(BASELINE):
        return None
    out = set()
    for line in open(BASELINE):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) >= 5 and f[4] == "EQUIV":
            out.add(f[0])
    return out


def waived():
    """(object, section:func) pairs the checker accepts as DIVERGENT.

    An object can be verdict-EQUIV while one of its programs is waived, and
    a waived program is by definition not doing the same thing in both
    builds — measuring its size difference as codegen would be wrong (the
    translation of test_core_reloc_type_based takes the C source's own
    skip branch, which "saves" 151 instructions)."""
    out = set()
    if not os.path.exists(WAIVERS):
        return out
    for line in open(WAIVERS):
        if line.startswith("#") or not line.strip():
            continue
        f = line.rstrip("\n").split("\t", 2)
        if len(f) >= 2:
            out.add((f[0], f[1].lstrip("?")))
    return out


def load(name):
    c = os.path.join(C_DIR, f"{name}.bpf.o")
    r = os.path.join(R_DIR, f"{name}.bpf.o")
    if not (os.path.exists(c) and os.path.exists(r)):
        return None
    corig = c + ".corig"
    if os.path.exists(corig) and open(c, "rb").read() != open(corig, "rb").read():
        print(f"  SKIP {name}: C object differs from .corig "
              f"(run `make restore-all`)", file=sys.stderr)
        return None
    try:
        return BpfElf(c), BpfElf(r)
    except Exception as e:                       # noqa: BLE001
        print(f"  SKIP {name}: {e}", file=sys.stderr)
        return None


def stats_for(elf, key):
    progs = check.programs(elf)
    if key not in progs:
        return None
    spans = I.func_spans(elf)
    if key not in spans:
        return None
    sec, off, size = spans[key]
    ins, funcs = I.whole_program(elf, sec, off, size)
    entry = I.decode(sec.data, off, size // 8)
    return I.FuncStats(key[1], ins), I.FuncStats(key[1], entry), len(funcs)


def collect(names):
    rows, skip = [], waived()
    for name in sorted(names):
        pair = load(name)
        if not pair:
            continue
        ec, er = pair
        kc, kr = check.programs(ec), check.programs(er)
        for key in sorted(set(kc) & set(kr)):
            label = f"{key[0]}:{key[1]}"
            if (name, label) in skip:
                continue
            sc, sr = stats_for(ec, key), stats_for(er, key)
            if not sc or not sr:
                continue
            rows.append((name, label, sc, sr))
    return rows


def write_tsv(rows, path):
    with open(path, "w") as f:
        f.write("\t".join(["object", "program", "c_insns", "rust_insns",
                           "c_entry", "rust_entry", "c_funcs", "rust_funcs",
                           "c_stack", "rust_stack"]
                          + [f"c_{k}" for k in KINDS]
                          + [f"rust_{k}" for k in KINDS]) + "\n")
        for name, prog, (wc, ec, nc), (wr, er, nr) in rows:
            f.write("\t".join([name, prog, str(wc.n), str(wr.n),
                               str(ec.n), str(er.n), str(nc), str(nr),
                               str(wc.stack_bytes), str(wr.stack_bytes)]
                              + [str(wc.get(k)) for k in KINDS]
                              + [str(wr.get(k)) for k in KINDS]) + "\n")


def pct(a, b):
    return f"{100.0 * a / b:.0f}%" if b else "—"


def build_report(rows):
    n = len(rows)
    tc = sum(r[2][0].n for r in rows)
    tr = sum(r[3][0].n for r in rows)
    same = sum(1 for r in rows if r[2][0].n == r[3][0].n)
    smaller = sum(1 for r in rows if r[3][0].n < r[2][0].n)
    bigger = sum(1 for r in rows if r[3][0].n > r[2][0].n)

    doc = ["# rustc vs clang: BPF codegen",
           "",
           "**Generated by `codegen/compare.py` — do not edit by hand.**",
           "",
           "Every program below has been PROVED semantically equivalent by",
           "`equiv/` in both builds, so each instruction of difference is",
           "the compiler's doing rather than the translation's. Counts",
           "follow bpf2bpf calls into `.text`, so a subprogram one compiler",
           "inlines and the other doesn't is counted the same way on both",
           "sides.",
           "",
           "## Summary",
           "",
           f"- **{n} program pairs**, {tr / tc:.3f}x total instruction count "
           f"(clang {tc:,} → rustc {tr:,})",
           f"- identical size: **{same} ({pct(same, n)})**; "
           f"rustc smaller: {smaller} ({pct(smaller, n)}); "
           f"rustc larger: {bigger} ({pct(bigger, n)})",
           ""]

    doc += ["## Where the instructions go", "",
            "Totals by instruction kind across all pairs. A category where",
            "rustc's share is out of line is a codegen lead; `*_stack` is",
            "frame traffic (spills, fills and locals).", "",
            "| kind | clang | rustc | delta |", "|---|---:|---:|---:|"]
    for k in KINDS:
        a = sum(r[2][0].get(k) for r in rows)
        b = sum(r[3][0].get(k) for r in rows)
        if not a and not b:
            continue
        d = b - a
        doc.append(f"| `{k}` | {a:,} | {b:,} | {d:+,} "
                   f"({(100.0 * d / a):+.0f}%) |" if a else
                   f"| `{k}` | {a:,} | {b:,} | {d:+,} |")
    doc.append("")

    doc += ["## Access widths", "",
            "How WIDE the loads and stores are. A copy that should be a few",
            "8-byte moves showing up as dozens of 1-byte ones is the",
            "signature of an unmergeable byte-at-a-time idiom.", "",
            "| access | clang | rustc | delta |", "|---|---:|---:|---:|"]
    WID = ["ldx_1B", "ldx_2B", "ldx_4B", "ldx_8B",
           "st_1B", "st_2B", "st_4B", "st_8B"]
    for w in WID:
        a = sum(r[2][0].widths.get(w, 0) for r in rows)
        b = sum(r[3][0].widths.get(w, 0) for r in rows)
        if not a and not b:
            continue
        doc.append(f"| `{w}` | {a:,} | {b:,} | {b - a:+,} "
                   + (f"({(100.0 * (b - a) / a):+.0f}%) |" if a else "|"))
    ac = sum(r[2][0].widths.get(w, 0) for r in rows for w in WID)
    ar = sum(r[3][0].widths.get(w, 0) for r in rows for w in WID)
    bc = sum(r[2][0].widths.get(w, 0) for r in rows for w in ("ldx_1B", "st_1B"))
    br = sum(r[3][0].widths.get(w, 0) for r in rows for w in ("ldx_1B", "st_1B"))
    doc += ["",
            f"Byte-width share of all memory access: clang "
            f"**{100.0 * bc / ac:.0f}%**, rustc **{100.0 * br / ar:.0f}%** "
            f"({br - bc:+,} single-byte accesses).", ""]

    ratio = sorted(rows, key=lambda r: -(r[3][0].n / max(r[2][0].n, 1)))
    doc += ["## Largest ratios", "",
            "| program | clang | rustc | ratio | biggest excess |",
            "|---|---:|---:|---:|---|"]
    for name, prog, (wc, _, _), (wr, _, _) in ratio[:25]:
        if wr.n <= wc.n:
            break
        deltas = sorted(((wr.get(k) - wc.get(k), k) for k in KINDS),
                        reverse=True)
        top = ", ".join(f"`{k}` +{d}" for d, k in deltas[:3] if d > 0)
        doc.append(f"| {name}:{prog.split(':')[-1]} | {wc.n} | {wr.n} | "
                   f"{wr.n / max(wc.n, 1):.1f}x | {top} |")
    doc.append("")

    absd = sorted(rows, key=lambda r: -(r[3][0].n - r[2][0].n))
    doc += ["## Largest absolute excess", "",
            "| program | clang | rustc | +insns | biggest excess |",
            "|---|---:|---:|---:|---|"]
    for name, prog, (wc, _, _), (wr, _, _) in absd[:25]:
        if wr.n <= wc.n:
            break
        deltas = sorted(((wr.get(k) - wc.get(k), k) for k in KINDS),
                        reverse=True)
        top = ", ".join(f"`{k}` +{d}" for d, k in deltas[:3] if d > 0)
        doc.append(f"| {name}:{prog.split(':')[-1]} | {wc.n} | {wr.n} | "
                   f"+{wr.n - wc.n} | {top} |")
    doc.append("")

    wins = sorted(rows, key=lambda r: (r[3][0].n - r[2][0].n))
    doc += ["## Where rustc wins", "",
            "| program | clang | rustc | -insns |", "|---|---:|---:|---:|"]
    for name, prog, (wc, _, _), (wr, _, _) in wins[:10]:
        if wr.n >= wc.n:
            break
        doc.append(f"| {name}:{prog.split(':')[-1]} | {wc.n} | {wr.n} | "
                   f"{wr.n - wc.n} |")
    doc.append("")

    sc = sum(r[2][0].stack_bytes for r in rows)
    sr = sum(r[3][0].stack_bytes for r in rows)
    deeper = sorted(rows, key=lambda r: -(r[3][0].stack_bytes - r[2][0].stack_bytes))
    doc += ["## Stack frames", "",
            "The verifier caps a frame at 512 bytes, so frame growth is a",
            "correctness risk and not only a size one.", "",
            f"- total frame bytes: clang {sc:,}, rustc {sr:,} "
            f"({sr / sc:.2f}x)" if sc else "- no frame use", "",
            "| program | clang | rustc | +bytes |", "|---|---:|---:|---:|"]
    for name, prog, (wc, _, _), (wr, _, _) in deeper[:10]:
        if wr.stack_bytes <= wc.stack_bytes:
            break
        doc.append(f"| {name}:{prog.split(':')[-1]} | {wc.stack_bytes} | "
                   f"{wr.stack_bytes} | +{wr.stack_bytes - wc.stack_bytes} |")
    doc.append("")

    inl = [(r[2][2], r[3][2], r[0], r[1]) for r in rows if r[2][2] != r[3][2]]
    doc += ["## Inlining", "",
            f"- {len(inl)} of {n} pairs use a different number of functions "
            f"(one compiler inlined a subprogram the other left out-of-line)",
            ""]
    return "\n".join(doc).rstrip() + "\n"


def show(rows, target):
    for name, prog, (wc, ec, _), (wr, er, _) in rows:
        if target not in f"{name}:{prog}":
            continue
        print(f"=== {name}:{prog}   clang {wc.n} insns, rustc {wr.n}")
        print(f"{'clang':<44s} rustc")
        a = [disasm(x) for x in wc.insns]
        b = [disasm(x) for x in wr.insns]
        for i in range(max(len(a), len(b))):
            print(f"{a[i] if i < len(a) else '':<44s} "
                  f"{b[i] if i < len(b) else ''}")
        return
    print(f"no pair matching {target}", file=sys.stderr)


def disasm(ins):
    op, dst, src, off, imm = ins
    return f"{I.classify(ins):<12s} op={op:#04x} r{dst}, r{src}, {off:+d}, {imm}"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--all", action="store_true",
                    help="include pairs the checker has not proved equivalent")
    ap.add_argument("--show", metavar="PROG:FUNC",
                    help="print a side-by-side instruction listing")
    ap.add_argument("--out", default=os.path.join(HERE, "REPORT.md"))
    ap.add_argument("--tsv", default=os.path.join(HERE, "pairs.tsv"))
    args = ap.parse_args()

    proved = proved_objects()
    names = [f[:-len(".bpf.o")] for f in os.listdir(R_DIR)
             if f.endswith(".bpf.o")]
    if not args.all:
        if proved is None:
            sys.exit("no equiv/results/baseline.tsv — pass --all to measure "
                     "unproved pairs too")
        names = [n for n in names if n in proved]
    rows = collect(names)
    if not rows:
        sys.exit("no comparable program pairs found")
    if args.show:
        return show(rows, args.show)
    write_tsv(rows, args.tsv)
    with open(args.out, "w") as f:
        f.write(build_report(rows))
    print(f"{len(rows)} program pairs -> "
          f"{os.path.relpath(args.out, REPO)}, "
          f"{os.path.relpath(args.tsv, REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
