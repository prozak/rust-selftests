#!/usr/bin/env python3
"""Fresh whole-stack validation on the pinned QEMU stack; never reseeds baselines."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import tarfile
import time

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "equiv"))
import guard  # noqa: E402

C_DIR = Path(guard.DEFAULT_C_DIR).resolve()
KERNEL = C_DIR.parent / "bpf-next-x86"
GOOD = {"EQUIV", "WAIVED-EQUIV"}
CHILDREN = set()
CHILD_LOCK = threading.RLock()
CANCELLED = threading.Event()


def stop_children():
    with CHILD_LOCK:
        for child in CHILDREN:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def interrupted(signum, frame):
    CANCELLED.set()
    stop_children()
    raise KeyboardInterrupt


def run(argv, log, env, timeout=None):
    """Log without pipe buffering; kill the whole subprocess tree on timeout."""
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("wb") as output:
        output.write(("$ " + repr([str(a) for a in argv]) + "\n").encode())
        output.flush()
        with CHILD_LOCK:
            if CANCELLED.is_set():
                return 130
            child = subprocess.Popen(argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                     stdout=output, stderr=subprocess.STDOUT,
                                     start_new_session=True)
            CHILDREN.add(child)
        try:
            return child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # The process group may have exited at the deadline.
            child.wait()
            output.write(f"\nnightly: timed out after {timeout}s\n".encode())
            return 124
        finally:
            with CHILD_LOCK:
                CHILDREN.discard(child)


def read_baseline(text):
    rows = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name, c, r, t, verdict, detail = line.split("\t", 5)
        if name in rows:
            raise ValueError(f"duplicate baseline row: {name}")
        rows[name] = dict(c=c, r=r, t=t, verdict=verdict, detail=detail)
    return rows


def proof_diff(before, after):
    changes = []
    for name in sorted(before.keys() | after.keys()):
        old = before.get(name, {}).get("verdict")
        new = after.get(name, {}).get("verdict")
        if old != new:
            changes.append(dict(name=name, before=old, after=new,
                                regression=old in GOOD and new not in GOOD))
    return changes


def runtime_result(name, rc, text):
    summary = next((line for line in reversed(text.splitlines())
                    if line.startswith("Summary:")), "")
    if rc == 0 and summary:
        return "PASS", summary
    if rc != 124 and f"no prog_tests consume {name}" in text:
        return "NO-ORACLE", summary
    return "FAIL", summary or f"exit {rc}; no test summary"


def pristine():
    bad = [p.name for p in C_DIR.glob("*.bpf.o.corig")
           if not p.with_suffix("").exists()
           or guard.md5(p) != guard.md5(p.with_suffix(""))]
    if bad:
        raise RuntimeError("C objects not restored: " + ", ".join(bad))


def counts(rows):
    return dict(sorted(Counter(row["verdict"] for row in rows.values()).items()))


def save_report(out, report):
    def write(name, text):
        temporary = out / (name + ".tmp")
        temporary.write_text(text)
        temporary.replace(out / name)

    write("summary.json", json.dumps(report, indent=2) + "\n")
    lines = ["# Nightly validation", "", f"Status: **{report['status']}**", "",
             f"Commit: `{report['commit']}`; kernel pin: `{report['kernel_pin']}`.",
             f"Expected objects: {len(report['names'])}.", "",
             "Verifier acceptance/rejection is checked by the QEMU consumers.",
             "PASS can include skipped assertions and sibling C programs; inspect the logs.",
             "Existing known-bad-tests exclusions are copied alongside this report.", "",
             "## Stages", "", "| Stage | Exit | Seconds |", "|---|---:|---:|"]
    for stage in report["stages"]:
        lines.append(f"| {stage['name']} | {stage['exit']} | {stage['seconds']} |")
    for title, key in [("Proof", "proof"), ("Runtime", "runtime")]:
        lines += ["", f"## {title}", "",
                  f"Completed: {len(report[key])}/{len(report['names'])} objects.",
                  "", str(counts(report[key]))]
    lines += ["", "## Runtime failures and missing oracles", "",
              "| Object | Rust | C | Summary |", "|---|---|---|---|"]
    for name, row in report["runtime"].items():
        if row["verdict"] != "PASS":
            note = row["summary"].replace("|", "\\|")
            lines.append(f"| {name} | {row['verdict']} | {row['c_verdict']} | {note} |")
    lines += ["", "## Proof verdict changes", "",
              "| Object | Before | After | Regression |", "|---|---|---|---|"]
    for row in report["proof_changes"]:
        lines.append(f"| {row['name']} | {row['before']} | {row['after']} | {row['regression']} |")
    lines += ["", "## Runtime verdict changes", "",
              "| Object | Before | After |", "|---|---|---|"]
    for row in report.get("runtime_changes", []):
        lines.append(f"| {row['name']} | {row['before']} | {row['after']} |")
    if report.get("error"):
        lines += ["", "## Error", "", report["error"]]
    write("REPORT.md", "\n".join(lines) + "\n")


def git(*args):
    return subprocess.check_output(["git", *args], cwd=REPO)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--jobs", type=int, choices=range(1, 9), default=8)
    ap.add_argument("--build-jobs", type=int, choices=range(1, 9), default=4)
    ap.add_argument("--proof-timeout", type=int, default=180)
    ap.add_argument("--runtime-timeout", type=int, default=1200)
    args = ap.parse_args(argv)
    if min(args.proof_timeout, args.runtime_timeout) <= 0:
        ap.error("timeouts must be positive")
    env = os.environ.copy()
    # The checker and codegen also read modules from their default C directory.
    # Reject alternate stacks rather than silently mix kernels or object trees.
    expected = {"FLAVOR": "qemu", "KERNEL_SRC": str(KERNEL),
                "SELFTESTS_SRC": str(KERNEL / "tools/testing/selftests/bpf"),
                "SELFTESTS_OUTPUT": str(C_DIR), "VMLINUX_BTF": str(KERNEL / "vmlinux"),
                "QEMU_KERNEL": str(KERNEL / "arch/x86/boot/bzImage"),
                "TEST_RUNNER": str(REPO / "scripts/qemu-test-progs")}
    for key, value in expected.items():
        if env.get(key, value) != value:
            ap.error(f"nightly requires {key}={value}")
    env.update(expected)
    for key in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL", "SWAP_ONLY"):
        env.pop(key, None)
    env.setdefault("LLVM_PREFIX", str(C_DIR.parent / "llvm-install"))
    env.setdefault("QEMU_CPUS", "4")
    nightly = REPO / "nightly"
    nightly.mkdir(exist_ok=True)
    locks = []
    for path in (nightly / ".lock", C_DIR / ".ci-nightly.lock"):
        try:
            lock = path.open("a")
            locks.append(lock)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            ap.error(f"another nightly run holds {path}")
        except OSError as exc:
            ap.error(f"cannot lock {path}: {exc}")
    out = (args.out or nightly / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")).resolve()
    out.mkdir(parents=True, exist_ok=False)
    names = sorted(p.stem for p in (REPO / "progs").glob("*.rs"))
    if not names:
        ap.error("empty translation corpus")
    report = dict(status="RUNNING", commit=git("rev-parse", "HEAD").decode().strip(),
                  kernel_pin=(REPO / "kernel-commit").read_text().strip(), names=names,
                  stages=[], proof={}, runtime={}, proof_changes=[],
                  configuration=dict(jobs=args.jobs, build_jobs=args.build_jobs,
                                     proof_timeout=args.proof_timeout, solver_ms=30000,
                                     runtime_timeout=args.runtime_timeout,
                                     qemu_cpus=env["QEMU_CPUS"]))
    print(f"nightly: {out} ({len(names)} objects)", flush=True)
    before_text = git("show", "HEAD:equiv/results/baseline.tsv").decode()
    before = read_baseline(before_text)
    (out / "baseline-before.tsv").write_text(before_text)
    (out / "source.diff").write_bytes(git("diff", "HEAD", "--binary"))
    (out / "source-status.txt").write_bytes(git("status", "--short"))
    # Include uncommitted/new source files too; a git diff alone omits them.
    with tarfile.open(out / "sources.tar.gz", "w:gz") as archive:
        for directory in ("progs", "scripts", "equiv", "codegen", "bpf-rs-core"):
            for path in sorted((REPO / directory).rglob("*")):
                if path.is_file() and (path.suffix in {".rs", ".py", ".sh", ".toml"}
                                       or path.name in {"waivers.tsv", "known-bad-tests", "qemu-test-progs"}):
                    archive.add(path, arcname=str(path.relative_to(REPO)))
        for name in ("Makefile", "kernel-commit"):
            if (REPO / name).is_file():
                archive.add(REPO / name, arcname=name)
    old_runtime = git("show", "HEAD:qemu/gate/results.md").decode()
    (out / "runtime-before.md").write_text(old_runtime)
    (out / "known-bad-tests").write_bytes((REPO / "scripts/known-bad-tests").read_bytes())
    old_gate = {parts[1].strip(): parts[2].strip() for line in old_runtime.splitlines()
                if len(parts := line.split("|")) >= 5 and parts[2].strip() in {"PASS", "FAIL", "NO-ORACLE"}}
    make = ["make", "--no-print-directory"]
    active = None
    failed = False

    def stage(name, command, timeout=None, stage_env=None):
        print(f"nightly: {name}", flush=True)
        start = time.monotonic()
        rc = run(command, out / f"{name}.log", stage_env or env, timeout)
        report["stages"].append(dict(name=name, exit=rc, seconds=round(time.monotonic() - start, 1)))
        save_report(out, report)
        return rc

    def require(name, command):
        if stage(name, command):
            raise RuntimeError(f"{name} failed; see {name}.log")

    handlers = {sig: signal.signal(sig, interrupted)
                for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        require("restore-before", make + ["restore-all"])
        pristine()
        require("kernel-pin", make + ["check-kernel-commit"])
        require("ci-fast", make + ["ci-fast"])
        require("rebuild", make + ["-B", f"-j{args.build_jobs}", "all"])
        require("translint", [sys.executable, "scripts/translint.py"])
        pristine()
        missing = [n for n in names if not (C_DIR / f"{n}.bpf.o").is_file()
                   or not (REPO / "bld" / f"{n}.bpf.o").is_file()]
        if missing:
            raise RuntimeError("missing objects: " + ", ".join(missing))
        thash = guard.tool_hash()
        hashes = {n: dict(c=guard.md5(C_DIR / f"{n}.bpf.o"),
                          r=guard.md5(REPO / "bld" / f"{n}.bpf.o"), t=thash) for n in names}
        (out / "object-hashes.json").write_text(json.dumps(hashes, indent=2) + "\n")
        # Preserve tool versions and kernel/module identities with the reports.
        require("toolchain", ["bash", "-ec", 'rustc --version; "$LLVM_PREFIX/bin/llc" --version; git -C "$KERNEL_SRC" rev-parse HEAD'])
        inputs = [KERNEL / "vmlinux", Path(env["QEMU_KERNEL"]),
                  REPO / "bld/vmlinux.btf", *C_DIR.glob("*.ko")]
        (out / "kernel-hashes.json").write_text(json.dumps(
            {str(p): guard.md5(p) for p in inputs if p.exists()}, indent=2) + "\n")

        def prove(name):
            log = out / "proof" / f"{name}.log"
            rc = run([sys.executable, "-u", "equiv/check.py", name, "--timeout", "30000"],
                     log, env, args.proof_timeout)
            verdict, detail = guard.classify(log.read_text(errors="replace"), rc)
            if rc == 124 and verdict != "INEQUIV":
                verdict, detail = "TIMEOUT", f"killed after {args.proof_timeout}s"
            return dict(**hashes[name], verdict=verdict, detail=detail, exit=rc)

        print("nightly: fresh proof sweep", flush=True)
        start = time.monotonic()
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = {pool.submit(prove, n): n for n in names}
            for future in as_completed(futures):
                name = futures[future]
                row = report["proof"][name] = future.result()
                print(f"proof [{len(report['proof'])}/{len(names)}] {name}: {row['verdict']}", flush=True)
                save_report(out, report)
        report["proof_changes"] = proof_diff(before, report["proof"])
        failed |= any(r["verdict"] in {"INEQUIV", "ERROR"} for r in report["proof"].values())
        failed |= any(r["regression"] for r in report["proof_changes"])
        report["stages"].append(dict(name="proof", exit=int(failed), seconds=round(time.monotonic() - start, 1)))
        with (out / "baseline-after.tsv").open("w") as f:
            f.write("# name\tc_md5\trust_md5\ttool_md5\tverdict\tdetail\n")
            for name, row in sorted(report["proof"].items()):
                detail = row["detail"].replace("\t", " ").replace("\n", " ")
                f.write(f"{name}\t{row['c']}\t{row['r']}\t{row['t']}\t{row['verdict']}\t{detail}\n")
        (out / "proof-diff.json").write_text(json.dumps(report["proof_changes"], indent=2) + "\n")

        print("nightly: serial QEMU verifier/runtime gate", flush=True)
        start = time.monotonic()
        runtime_failed = False
        for name in names:
            active = name
            log = out / "runtime" / f"{name}.log"
            rc = run(["scripts/swap-and-test.sh", name, "rust"], log, env, args.runtime_timeout)
            verdict, note = runtime_result(name, rc, log.read_text(errors="replace"))
            c_env = env if verdict == "FAIL" else dict(env, SWAP_ONLY="1")
            c_log = out / "runtime" / f"{name}.c.log"
            c_rc = run(["scripts/swap-and-test.sh", name, "c"], c_log, c_env, args.runtime_timeout)
            c_verdict, c_note = runtime_result(name, c_rc, c_log.read_text(errors="replace"))
            report["runtime"][name] = dict(verdict=verdict, exit=rc, summary=note,
                                           c_exit=c_rc, c_verdict=c_verdict if verdict == "FAIL" else "NOT-RUN",
                                           c_summary=c_note if verdict == "FAIL" else "")
            runtime_failed |= verdict == "FAIL" or (old_gate.get(name) == "PASS" and verdict != "PASS")
            print(f"runtime [{len(report['runtime'])}/{len(names)}] {name}: {verdict}; restore exit {c_rc}", flush=True)
            save_report(out, report)
            # No consumer is an explicit limitation, not an infrastructure failure.
            if c_rc and c_verdict != "NO-ORACLE":
                if verdict != "FAIL" or c_verdict != "FAIL" or not c_note.startswith("Summary:"):
                    raise RuntimeError(f"C restoration/rebuild failed for {name}; see runtime/{name}.c.log")
            pristine()
            active = None
        failed |= runtime_failed
        report["stages"].append(dict(name="qemu-verifier-runtime", exit=int(runtime_failed), seconds=round(time.monotonic() - start, 1)))
        report["runtime_changes"] = [dict(name=n, before=old_gate.get(n), after=r["verdict"])
                                     for n, r in report["runtime"].items() if old_gate.get(n) != r["verdict"]]
        require("restore-before-codegen", make + ["restore-all"])
        pristine()
        if any(guard.md5(C_DIR / f"{n}.bpf.o") != h["c"]
               or guard.md5(REPO / "bld" / f"{n}.bpf.o") != h["r"] for n, h in hashes.items()):
            raise RuntimeError("objects changed after proof; codegen evidence would be stale")
        failed |= bool(stage("codegen", [sys.executable, "codegen/compare.py",
                                       "--baseline", str(out / "baseline-after.tsv"),
                                       "--out", str(out / "codegen.md"), "--tsv", str(out / "codegen.tsv")]))
        report["status"] = "FAIL" if failed else "PASS"
    except (Exception, KeyboardInterrupt) as exc:
        report["status"] = "INTERRUPTED" if isinstance(exc, KeyboardInterrupt) else "ERROR"
        report["error"] = str(exc) or "interrupted"
        failed = True
    finally:
        # A second interrupt must not interrupt recovery of the shared C tree.
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        stop_children()
        CANCELLED.clear()

        def cleanup_error(message):
            nonlocal failed
            report["error"] = "; ".join(filter(None, [report.get("error"), message]))
            report["status"] = "ERROR"
            failed = True

        def cleanup_stage(name, command, timeout=None, stage_env=None):
            # Failure to launch/rebuild one recovery command must not skip the
            # final object restoration (or leave a PASS report on disk).
            try:
                if stage(name, command, timeout, stage_env):
                    cleanup_error(f"{name} failed; see {name}.log")
            except Exception as exc:
                cleanup_error(f"{name}: {exc}")

        try:
            # Restore derived skeletons/test_progs for an interrupted swap.
            if active is not None:
                cleanup_stage("restore-active", ["scripts/swap-and-test.sh", active, "c"],
                              args.runtime_timeout, dict(env, SWAP_ONLY="1"))
            cleanup_stage("restore-final", make + ["restore-all"])
            try:
                pristine()
            except Exception as exc:
                cleanup_error(str(exc))
            save_report(out, report)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    print(f"nightly: {report['status']} — {out / 'REPORT.md'}", flush=True)
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
