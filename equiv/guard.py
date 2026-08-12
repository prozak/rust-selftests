#!/usr/bin/env python3
"""Equivalence regression guard: hash-gated re-proving.

Keeps a committed baseline (results/baseline.tsv) mapping each selftest to
the hashes of its C object, Rust object and the prover toolchain, plus the
last verdict. A run:

  - skips programs whose hashes are unchanged (fast path — the whole
    corpus checks in seconds when nothing changed);
  - re-proves anything whose objects or toolchain changed, or that is new;
  - ALARMS (exit 1, loud output) on any INEQUIV, and on any verdict
    downgrade from EQUIV (a program that proved before and now bails or
    times out deserves eyes even though it isn't proof of divergence);
  - updates the baseline in place for rows that were re-proved.

Usage:
  equiv/guard.py                # guard everything present in bld/
  equiv/guard.py name1 name2    # guard a subset (after editing those)
  equiv/guard.py --jobs 10 --timeout 120
  equiv/guard.py --reseed sweep-summary.tsv   # rebuild baseline verdicts
                                # from an existing sweep summary + hashes

A toolchain change (equiv/*.py, waivers.tsv, kernel BTF) invalidates every
row, which means a full re-sweep; the guard says so instead of silently
re-proving 550 programs — pass --all to actually do it.
"""
import argparse
import concurrent.futures as cf
import hashlib
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DEFAULT_C_DIR = os.path.join(REPO, "..", "uml-harness", ".build",
                             "selftests-output-qemu")
BASELINE = os.path.join(HERE, "results", "baseline.tsv")
TOOL_FILES = ["bpfelf.py", "bpfsym.py", "bpfcore.py", "check.py",
              "waivers.tsv"]
GOOD = ("EQUIV", "WAIVED-EQUIV")
NONPROOF = ("BAIL", "TIMEOUT", "UNKNOWN", "NOPROGS")


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tool_hash():
    h = hashlib.md5()
    for f in TOOL_FILES:
        h.update(open(os.path.join(HERE, f), "rb").read())
    kbtf = os.path.join(REPO, "bld", "vmlinux.btf")
    if os.path.exists(kbtf):
        h.update(md5(kbtf).encode())
    return h.hexdigest()


def load_baseline():
    rows = {}
    if os.path.exists(BASELINE):
        for line in open(BASELINE):
            if line.startswith("#") or not line.strip():
                continue
            name, chash, rhash, thash, verdict, detail = \
                line.rstrip("\n").split("\t", 5)
            rows[name] = dict(c=chash, r=rhash, t=thash, verdict=verdict,
                              detail=detail)
    return rows


def save_baseline(rows):
    os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
    with open(BASELINE, "w") as f:
        f.write("# name\tc_md5\trust_md5\ttool_md5\tverdict\tdetail\n")
        for name in sorted(rows):
            r = rows[name]
            f.write(f"{name}\t{r['c']}\t{r['r']}\t{r['t']}\t"
                    f"{r['verdict']}\t{r['detail']}\n")


def prove(name, timeout_s, solver_ms):
    """Run check.py; return (verdict, detail) in sweep.sh's taxonomy."""
    try:
        p = subprocess.run(
            [sys.executable, os.path.join(HERE, "check.py"), name,
             "--timeout", str(solver_ms)],
            capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", f"killed after {timeout_s}s"
    out = p.stdout + p.stderr
    counts = {k: sum(1 for line in out.splitlines()
                     if line.startswith(f"  {k} "))
              for k in ("EQUIV", "EQUIV32", "INEQUIV", "BAIL", "UNKNOWN",
                        "UNPAIRED", "WAIVED")}
    n_eq = counts["EQUIV"] + counts["EQUIV32"] + counts["WAIVED"]
    total_line = next((line for line in out.splitlines()
                       if "program(s) proved" in line), "")
    if counts["INEQUIV"]:
        bad = [line.strip() for line in out.splitlines()
               if line.startswith("  INEQUIV")]
        return "INEQUIV", "; ".join(bad)[:400]
    if counts["BAIL"]:
        return "BAIL", total_line.strip()
    if counts["UNKNOWN"] or counts["UNPAIRED"]:
        return "UNKNOWN", total_line.strip()
    if n_eq and p.returncode == 0:
        return "EQUIV", total_line.strip()
    if "0/0 program" in out:
        return "NOPROGS", ""
    return "ERROR", out.strip().splitlines()[-1][:200] if out.strip() else ""


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("names", nargs="*",
                    help="subset to guard (default: everything in bld/)")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=180,
                    help="wall seconds per program")
    ap.add_argument("--solver-ms", type=int, default=30_000)
    ap.add_argument("--all", action="store_true",
                    help="re-prove everything even on toolchain change")
    ap.add_argument("--reseed",
                    help="seed baseline verdicts from a sweep summary.tsv "
                         "(assumes it was produced with the CURRENT objects "
                         "and toolchain)")
    args = ap.parse_args()

    thash = tool_hash()
    baseline = load_baseline()

    if args.reseed:
        n = 0
        for line in open(args.reseed):
            if not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            name, verdict = parts[0], parts[1]
            c_obj = os.path.join(DEFAULT_C_DIR, f"{name}.bpf.o")
            r_obj = os.path.join(REPO, "bld", f"{name}.bpf.o")
            if not (os.path.exists(c_obj) and os.path.exists(r_obj)):
                continue
            baseline[name] = dict(c=md5(c_obj), r=md5(r_obj), t=thash,
                                  verdict=verdict,
                                  detail="seeded from " +
                                  os.path.basename(args.reseed))
            n += 1
        save_baseline(baseline)
        print(f"seeded {n} rows into {os.path.relpath(BASELINE, REPO)}")
        return 0

    if args.names:
        names = args.names
    else:
        names = sorted(
            f[:-len(".bpf.o")] for f in os.listdir(os.path.join(REPO, "bld"))
            if f.endswith(".bpf.o"))

    stale_tool = [n for n in names
                  if n in baseline and baseline[n]["t"] != thash]
    if stale_tool and not args.all:
        print(f"TOOLCHAIN CHANGED: {len(stale_tool)} baseline rows are "
              f"stale (equiv/*.py, waivers.tsv or kernel BTF differ).")
        print("A full re-sweep is required: rerun with --all "
              "(or sweep.sh + --reseed).")
        return 2

    work, cached, missing, alarms_cached = [], [], [], []
    for name in names:
        c_obj = os.path.join(DEFAULT_C_DIR, f"{name}.bpf.o")
        r_obj = os.path.join(REPO, "bld", f"{name}.bpf.o")
        if not (os.path.exists(c_obj) and os.path.exists(r_obj)):
            missing.append(name)
            continue
        chash, rhash = md5(c_obj), md5(r_obj)
        row = baseline.get(name)
        if (row and row["c"] == chash and row["r"] == rhash
                and row["t"] == thash):
            if row["verdict"] == "INEQUIV":
                # a recorded divergence keeps alarming until the objects
                # change (i.e. someone fixed the translation)
                alarms_cached.append((name, row["detail"]))
            cached.append(name)
            continue
        work.append((name, chash, rhash))

    print(f"{len(cached)} unchanged (cached), {len(work)} to prove, "
          f"{len(missing)} missing objects")

    alarms, downgrades = [], []
    if work:
        with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futs = {ex.submit(prove, name, args.timeout, args.solver_ms):
                    (name, chash, rhash) for name, chash, rhash in work}
            for fut in cf.as_completed(futs):
                name, chash, rhash = futs[fut]
                verdict, detail = fut.result()
                old = baseline.get(name, {}).get("verdict")
                marker = ""
                if verdict == "INEQUIV":
                    alarms.append((name, detail))
                    marker = "  <<< ALARM"
                elif old in GOOD and verdict in NONPROOF:
                    downgrades.append((name, old, verdict))
                    marker = f"  <<< was {old}"
                print(f"  {verdict:8s} {name}{marker}")
                baseline[name] = dict(c=chash, r=rhash, t=thash,
                                      verdict=verdict, detail=detail)
        save_baseline(baseline)

    alarms += alarms_cached
    if alarms:
        print(f"\n*** {len(alarms)} INEQUIV — the translation and C object "
              f"DIVERGE: ***")
        for name, detail in alarms:
            print(f"  {name}: {detail}")
    if downgrades:
        print(f"\n{len(downgrades)} verdict downgrade(s) (not divergence, "
              f"but previously proved):")
        for name, old, new in downgrades:
            print(f"  {name}: {old} -> {new}")
    if not work:
        print("everything up to date")
    return 1 if alarms else 0


if __name__ == "__main__":
    sys.exit(main())
