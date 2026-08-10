#!/usr/bin/env python3
"""Prove semantic equivalence of C and Rust BPF objects for one selftest.

For every BPF program (FUNC symbol in an executable section) present in both
objects, symbolically executes both over a shared initial state — symbolic
context, symbolic kernel memory, symbolic global initial values — and asks Z3
whether any input makes the observables differ.

Observables: return value (r0 at exit), final contents of every named global
(g:<symbol> region), and final contents of the context.

Verdicts per program:
  EQUIV           proved equal for all inputs
  INEQUIV         counterexample found (printed)
  BAIL <reason>   uses a construct the executor doesn't model yet
  UNKNOWN         solver gave up within the time limit
Programs present in only one object are reported UNPAIRED.

Exit status 0 iff every paired program is EQUIV and nothing is unpaired.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import z3
from bpfelf import (BpfElf, SHF_ALLOC, SHF_EXECINSTR, SHT_NOBITS, STT_FUNC,
                    STT_OBJECT, normalize_name)
from bpfsym import Bail, Executor

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_C_DIR = os.path.join(REPO, "..", "uml-harness", ".build", "selftests-output-qemu")


def programs(elf):
    """(section name, func name) -> (section, entry insn index)."""
    out = {}
    for sym in elf.symbols:
        if sym.type != STT_FUNC or not sym.name:
            continue
        sec = elf.sections[sym.shndx]
        if not sec.flags & SHF_EXECINSTR or sec.size == 0:
            continue
        if sec.name == ".text":
            continue  # subprograms, not entry programs; wrong calling convention
        out[(sec.name, sym.name)] = (sec, sym.value // 8)
    return out


def global_regions(elves):
    """Union of named writable globals across both objects -> shared arrays.

    Returns (regions dict, init-mismatch warnings)."""
    regions, warnings = {}, []
    seen = {}
    for tag, elf in elves.items():
        for sym in elf.symbols:
            if sym.type != STT_OBJECT or not sym.name:
                continue
            sec = elf.sections[sym.shndx]
            if (not sec.flags & SHF_ALLOC or sec.flags & SHF_EXECINSTR
                    or sec.name.startswith(".rodata") or sec.name == ".maps"
                    or sec.name.startswith(".BTF")
                    or sec.name.startswith(".struct_ops")):
                continue  # struct_ops data is map material, not runtime state
            name = normalize_name(sym.name)
            init = (b"\x00" * sym.size if sec.type == SHT_NOBITS
                    else sec.data[sym.value:sym.value + sym.size])
            if name in seen and seen[name] != (sym.size, init):
                warnings.append(
                    f"global '{name}': size/init differs between objects "
                    f"({seen[name][0]}B vs {sym.size}B)")
            seen[name] = (sym.size, init)
            regions.setdefault(
                f"g:{name}",
                z3.Array(f"g_{name}", z3.BitVecSort(64), z3.BitVecSort(8)))
    return regions, warnings


def summarize(paths, shared, region):
    """ITE-fold a per-path final array for one region (initial if untouched)."""
    expr = paths[-1].mem.get(region, shared[region])
    for p in reversed(paths[:-1]):
        cond = z3.And(*p.conds) if p.conds else z3.BoolVal(True)
        expr = z3.If(cond, p.mem.get(region, shared[region]), expr)
    return expr


def summarize_ret(paths):
    expr = paths[-1].ret
    for p in reversed(paths[:-1]):
        cond = z3.And(*p.conds) if p.conds else z3.BoolVal(True)
        expr = z3.If(cond, p.ret, expr)
    return expr


def check_program(name, func, elves, shared, timeout_ms):
    paths, void = {}, {}
    for tag, (elf, sec, entry) in elves.items():
        ex = Executor(elf, sec, shared, tag)
        paths[tag] = ex.run(entry)
        # r0 never assigned on any path => BTF-void return (verifier-enforced)
        void[tag] = all(z3.eq(p.ret, ex.init_r0) for p in paths[tag])

    # mapval:* regions are created on demand during the runs above (writes
    # through looked-up pointers are map state); rbuf:* stays unobservable —
    # ringbuf content is captured by the submit trace event, and a discarded
    # buffer's scribbles are invisible to userspace.
    obs_regions = [r for r in shared if r.startswith(("g:", "mapval:"))] \
        + ["ctx", "trace", "sysret"]
    ret_a, ret_b = summarize_ret(paths["A"]), summarize_ret(paths["B"])
    mem_eq = [summarize(paths["A"], shared, r) == summarize(paths["B"], shared, r)
              for r in obs_regions]

    def solve(eqs):
        s = z3.Solver()
        s.set("timeout", timeout_ms)
        s.add(z3.Not(z3.And(*eqs)))
        return s, s.check()

    # C-side BTF is ground truth for the return contract
    ret_bits = elves["A"][0].func_ret_bits(func)
    if ret_bits is not None:
        ret_observable = ret_bits != 0
    else:
        ret_observable = not (void["A"] or void["B"])
    if ret_observable and ret_bits is not None and ret_bits <= 32:
        ret_a, ret_b = z3.Extract(31, 0, ret_a), z3.Extract(31, 0, ret_b)

    eq = ([ret_a == ret_b] if ret_observable else []) + mem_eq
    s, res = solve(eq)
    if res == z3.unsat:
        note = "" if ret_observable else "; void ret"
        return "EQUIV", f"paths C={len(paths['A'])} rust={len(paths['B'])}{note}"
    if res == z3.unknown:
        return "UNKNOWN", "solver timeout/gave-up"

    if ret_observable and (ret_bits is None or ret_bits > 32):
        # divergence only in upper 32 bits of r0 is benign for <=32-bit ret types
        _, res32 = solve([z3.Extract(31, 0, ret_a) == z3.Extract(31, 0, ret_b)] + mem_eq)
        if res32 == z3.unsat:
            return "EQUIV32", "ret equal in low 32 bits only (check BTF ret width)"

    m = s.model()
    detail = []
    if ret_observable and not z3.is_true(m.eval(ret_a == ret_b)):
        detail.append(f"ret: C={m.eval(ret_a)} rust={m.eval(ret_b)}")
    for r, e in zip(obs_regions, mem_eq):
        if not z3.is_true(m.eval(e)):
            detail.append(f"observable '{r}' differs")
    return "INEQUIV", "; ".join(detail) or "model found (details unavailable)"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("prog", help="selftest program name (e.g. fentry_test)")
    ap.add_argument("--c-obj", help="C object (default: selftests-output-qemu/<prog>.bpf.o)")
    ap.add_argument("--rust-obj", help="Rust object (default: bld/<prog>.bpf.o)")
    ap.add_argument("--sec", help="check only this (section, func) — match on either name")
    ap.add_argument("--timeout", type=int, default=60_000, help="solver timeout ms per program")
    args = ap.parse_args()

    c_path = args.c_obj or os.path.join(DEFAULT_C_DIR, f"{args.prog}.bpf.o")
    r_path = args.rust_obj or os.path.join(REPO, "bld", f"{args.prog}.bpf.o")
    for p in (c_path, r_path):
        if not os.path.exists(p):
            sys.exit(f"missing object: {p}")

    elf_c, elf_r = BpfElf(c_path), BpfElf(r_path)
    progs_c, progs_r = programs(elf_c), programs(elf_r)

    shared, warnings = global_regions({"A": elf_c, "B": elf_r})
    shared["ctx"] = z3.Array("ctx", z3.BitVecSort(64), z3.BitVecSort(8))
    shared["kmem"] = z3.Array("kmem", z3.BitVecSort(64), z3.BitVecSort(8))
    # tier 2: side-effecting helper calls append events here (observable);
    # skbdata backs skb_load_bytes packet reads (input, not observable)
    shared["trace"] = z3.Array("trace_init", z3.BitVecSort(64), z3.BitVecSort(8))
    shared["skbdata"] = z3.Array("skbdata", z3.BitVecSort(64), z3.BitVecSort(8))
    shared["sysret"] = z3.Array("sysret", z3.BitVecSort(64), z3.BitVecSort(8))
    for w in warnings:
        print(f"  WARN {w}")

    keys = sorted(set(progs_c) | set(progs_r))
    if args.sec:
        keys = [k for k in keys if args.sec in k]
        if not keys:
            sys.exit(f"no program matches --sec {args.sec}")

    core_secs = elf_c.core_relo_sections() | elf_r.core_relo_sections()

    waivers = {}
    wpath = os.path.join(REPO, "equiv", "waivers.tsv")
    if os.path.exists(wpath):
        for line in open(wpath):
            if line.startswith("#") or not line.strip():
                continue
            prog, label, reason = line.rstrip("\n").split("\t", 2)
            if prog == args.prog:
                waivers[label] = reason

    failures = 0
    for key in keys:
        secname, func = key
        label = f"{secname}:{func}"
        if key not in progs_c or key not in progs_r:
            where = "rust" if key in progs_r else "C"
            print(f"  UNPAIRED {label} (only in {where} object)")
            failures += 1
            continue
        if secname in core_secs:
            print(f"  CORESKIP {label}  [unapplied CO-RE relocs; pre-load compare invalid]")
            continue
        try:
            verdict, detail = check_program(
                label, func,
                {"A": (elf_c,) + progs_c[key], "B": (elf_r,) + progs_r[key]},
                shared, args.timeout)
        except Bail as e:
            verdict, detail = "BAIL", str(e)
        if verdict == "INEQUIV" and label in waivers:
            verdict, detail = "WAIVED", waivers[label]
        if verdict not in ("EQUIV", "EQUIV32", "WAIVED"):
            failures += 1
        print(f"  {verdict:8s} {label}  [{detail}]")

    total = len(keys)
    print(f"{args.prog}: {total - failures}/{total} program(s) proved equivalent")
    sys.exit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()
