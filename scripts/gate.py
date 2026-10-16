#!/usr/bin/env python3
"""Incremental QEMU gate: re-run only the translations whose inputs changed.

Keeps a committed baseline (qemu/gate/baseline.tsv) mapping each translation
to the hashes of its Rust object, its C object and the gate environment
(kernel image, module BTF, the swap/boot scripts, test exclusions, guest
size; see qemu_gate.env_hash), plus the last verdict. A run:

  - restores the C objects, checks the kernel pin, brings bld/ up to date;
  - skips translations whose three hashes are unchanged (the whole corpus
    passes in the time of a `make all` when nothing changed);
  - runs the rest through the kernel's own selftests in QEMU, N overlay
    workers at a time (scripts/gate-overlay.sh), the objects named in
    scripts/gate-serial afterwards, alone in the shared output;
  - ALARMS (exit 1) on every FAIL, cached ones included, and on a PASS
    that became NO-ORACLE; a FAIL keeps alarming until its objects change;
  - updates the baseline rows that ran.

An environment change invalidates every row, which means an hour-long full
re-gate: the guard says so (exit 2) instead of starting it; pass --all to
do it, or run `make ci-nightly` and --reseed its runtime-after.tsv.

Usage:
  scripts/gate.py                     # everything in progs/
  scripts/gate.py name1 name2         # a subset (after editing those)
  scripts/gate.py --all name1         # force these names
  scripts/gate.py --all               # accept an environment change
  scripts/gate.py --reseed nightly/<run>/runtime-after.tsv
  scripts/gate.py --reseed nightly/<run>/summary.json   # verdicts only

Exit 0: no alarm. 1: alarms, downgrades or a failed stage. 2: usage, a
held lock, a changed environment without --all.
"""
import argparse
import json
from pathlib import Path
import os
import signal
import sys
import time

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "equiv"))
sys.path.insert(0, str(REPO / "scripts"))
import guard  # noqa: E402
import paths  # noqa: E402
import qemu_gate  # noqa: E402
from qemu_gate import CANCELLED, interrupted, run, stop_children  # noqa: E402

C_DIR = Path(guard.DEFAULT_C_DIR).resolve()
KERNEL = Path(paths.KERNEL_SRC).resolve()
BASELINE = "qemu/gate/baseline.tsv"
LOG_DIR = "qemu/gate/logs"


def kvm_available():
    """A usable /dev/kvm: permissions alone are not enough (ENODEV when the
    host exposes no hardware virtualization), hence a real open."""
    try:
        os.close(os.open("/dev/kvm", os.O_RDWR))
        return True
    except OSError:
        return False


def reseed(source, names, hashes, ehash):
    """Baseline rows from a nightly's record of the current objects.

    A runtime-after.tsv carries the nightly's own hashes, which must equal
    the current ones row by row; a summary.json carries verdicts only and
    is taken on trust that its run used the current objects (it is checked
    against the C hashes its object-hashes.json recorded)."""
    source = Path(source)
    rows, mismatched = {}, []
    if source.suffix == ".json":
        runtime = json.loads(source.read_text())["runtime"]
        recorded = source.with_name("object-hashes.json")
        c_hashes = json.loads(recorded.read_text()) if recorded.exists() else {}
        for name in names:
            if name not in runtime:
                continue
            if name in c_hashes and c_hashes[name]["c"] != hashes[name][1]:
                mismatched.append(f"{name} (C object)")
                continue
            rows[name] = qemu_gate.baseline_row(*hashes[name], ehash, runtime[name])
    else:
        for name, row in qemu_gate.parse_baseline(source.read_text()).items():
            if name not in hashes:
                continue
            current = dict(r=hashes[name][0], c=hashes[name][1], e=ehash)
            stale = [k for k in current if row[k] != current[k]]
            if stale:
                mismatched.append(f"{name} ({', '.join(stale)})")
                continue
            rows[name] = dict(row)
    return rows, mismatched


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("names", nargs="*",
                    help="subset to gate (default: everything in progs/)")
    ap.add_argument("--workers", type=int, choices=range(1, 9), default=4,
                    help="QEMU guests at once, each over a private overlay; "
                         "1 runs serially in the shared selftests output")
    ap.add_argument("--build-jobs", type=int, choices=range(1, 9), default=4)
    ap.add_argument("--runtime-timeout", type=int, default=1200,
                    help="wall seconds per swap-build-boot run")
    ap.add_argument("--all", action="store_true",
                    help="re-run named translations even if unchanged; "
                         "with none named, re-run everything after an "
                         "environment change")
    ap.add_argument("--reseed", type=Path,
                    help="seed baseline rows from a nightly's "
                         "runtime-after.tsv (hashes checked) or summary.json")
    args = ap.parse_args(argv)
    if args.runtime_timeout <= 0:
        ap.error("--runtime-timeout must be positive")
    env = qemu_gate.make_env(REPO, KERNEL, C_DIR, lambda m: ap.error(f"gate {m}"))
    locks = qemu_gate.take_locks([REPO / "nightly" / ".lock", C_DIR / ".ci-nightly.lock"],  # noqa: F841
                                 ap.error)
    baseline_path = REPO / BASELINE
    log_dir = REPO / LOG_DIR
    baseline = qemu_gate.load_baseline(baseline_path)
    names = args.names or sorted(p.stem for p in (REPO / "progs").glob("*.rs"))
    unknown = [n for n in names if not (REPO / "progs" / f"{n}.rs").is_file()]
    if unknown:
        ap.error("no such translation: " + ", ".join(unknown))
    if not names:
        ap.error("empty translation corpus")
    make = ["make", "--no-print-directory"]
    hashes = {}          # name -> (rust md5, C md5)
    state = dict(e="", work=[], done=0, alarms=[], downgrades=[])

    def stage(name, command, stage_env=None):
        if run(command, log_dir / f"{name}.log", stage_env or env):
            raise RuntimeError(f"{name} failed; see {LOG_DIR}/{name}.log")

    def record(name, result):
        # Called by the gate under its lock; the baseline is saved after
        # every object so an interrupted run keeps what it learned.
        old = baseline.get(name, {}).get("verdict")
        row = qemu_gate.baseline_row(*hashes[name], state["e"], result)
        marker = ""
        if result["verdict"] == "FAIL":
            state["alarms"].append((name, row["summary"]))
            marker = "  <<< ALARM"
        elif old == "PASS" and result["verdict"] != "PASS":
            state["downgrades"].append((name, old, result["verdict"]))
            marker = f"  <<< was {old}"
        baseline[name] = row
        qemu_gate.save_baseline(baseline_path, baseline)
        state["done"] += 1
        print(f"  {result['verdict']:9s} {name} [{state['done']}/{len(state['work'])}]{marker}",
              flush=True)

    gate = qemu_gate.Gate(run=run, env=env, log_dir=log_dir, timeout=args.runtime_timeout,
                          base=REPO, on_row=record)
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    status = 0
    try:
        stage("restore-all", make + ["restore-all"])
        qemu_gate.pristine(C_DIR)
        stage("check-kernel-commit", make + ["check-kernel-commit"])
        stage("build", make + [f"-j{args.build_jobs}", "all"])
        missing = [n for n in names if not (C_DIR / f"{n}.bpf.o").is_file()
                   or not (REPO / "bld" / f"{n}.bpf.o").is_file()]
        if missing:
            raise RuntimeError("missing objects: " + ", ".join(missing))
        state["e"] = qemu_gate.env_hash(REPO, KERNEL, C_DIR, env)
        hashes.update({n: (guard.md5(REPO / "bld" / f"{n}.bpf.o"), guard.md5(C_DIR / f"{n}.bpf.o"))
                       for n in names})

        if args.reseed:
            rows, mismatched = reseed(args.reseed, names, hashes, state["e"])
            if mismatched:
                print(f"REFUSED: {len(mismatched)} row(s) of {args.reseed} do not describe "
                      f"the current objects/environment:")
                for item in mismatched[:20]:
                    print(f"  {item}")
                return 2
            baseline.update(rows)
            qemu_gate.save_baseline(baseline_path, baseline)
            print(f"seeded {len(rows)} rows into {BASELINE}")
            return 0

        stale_env = [n for n in names if n in baseline and baseline[n]["e"] != state["e"]]
        if stale_env and not args.all:
            print(f"ENVIRONMENT CHANGED: {len(stale_env)} baseline rows are stale (the "
                  f"kernel image, module BTF, swap/boot scripts, known-bad-tests, "
                  f"gate-serial or QEMU_CPUS differ).")
            print(f"A full re-gate is required (about an hour with {args.workers} workers): "
                  f"rerun with --all, or run make ci-nightly and --reseed its runtime-after.tsv.")
            return 2

        force = args.all and bool(args.names)
        cached, alarms_cached = [], []
        for name in names:
            row = baseline.get(name)
            r, c = hashes[name]
            if (row and not force and row["r"] == r and row["c"] == c
                    and row["e"] == state["e"]):
                if row["verdict"] == "FAIL":
                    # a recorded failure keeps alarming until the objects
                    # change (i.e. someone fixed the translation)
                    alarms_cached.append((name, row["summary"]))
                cached.append(name)
                continue
            state["work"].append(name)
        work = state["work"]
        print(f"{len(cached)} unchanged (cached), {len(work)} to run", flush=True)
        if work:
            if not kvm_available() and not env.get("QEMU_ALLOW_TCG"):
                raise RuntimeError("/dev/kvm cannot be opened; fix it or set QEMU_ALLOW_TCG=1 "
                                   "(emulated guests are slow and their verdicts are not evidence)")
            if args.workers > 1:
                workers = qemu_gate.overlay_envs(env, Path(paths.BUILD_DIR).resolve() / "gate",
                                                 args.workers)
            else:
                workers = [env]
            serial = qemu_gate.read_serial(REPO / "scripts/gate-serial")
            start = time.monotonic()
            gate.run_all(work, workers, serial)
            print(f"gated {state['done']} object(s) in {round(time.monotonic() - start)}s "
                  f"with {len(workers)} worker(s)")
        alarms = state["alarms"] + alarms_cached
        if alarms:
            print(f"\n*** {len(alarms)} FAIL — the translation's consumers fail in the guest: ***")
            for name, summary in alarms:
                print(f"  {name}: {summary}")
        if state["downgrades"]:
            print(f"\n{len(state['downgrades'])} verdict downgrade(s) (the oracle went away):")
            for name, old, new in state["downgrades"]:
                print(f"  {name}: {old} -> {new}")
        if not work:
            print("everything up to date")
        status = 1 if alarms or state["downgrades"] else 0
    except KeyboardInterrupt:
        print("gate: interrupted", flush=True)
        status = 1
    except Exception as exc:
        print(f"gate: error: {exc}", flush=True)
        status = 1
    finally:
        # A second interrupt must not interrupt recovery of the shared C tree.
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        stop_children()
        CANCELLED.clear()
        try:
            for name in gate.active_in_shared_tree():
                if run(["scripts/swap-and-test.sh", name, "c"], log_dir / "restore-active.log",
                       dict(env, SWAP_ONLY="1"), args.runtime_timeout):
                    print(f"gate: error: restoring {name}'s derived files failed; "
                          f"see {LOG_DIR}/restore-active.log", flush=True)
                    status = status or 1
            if run(make + ["restore-all"], log_dir / "restore-final.log", env):
                print(f"gate: error: restore-all failed; see {LOG_DIR}/restore-final.log", flush=True)
                status = status or 1
            qemu_gate.pristine(C_DIR)
        except Exception as exc:
            print(f"gate: error: {exc}", flush=True)
            status = status or 1
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    return status


if __name__ == "__main__":
    sys.exit(main())
