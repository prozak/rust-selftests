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
import paths  # noqa: E402

C_DIR = Path(guard.DEFAULT_C_DIR).resolve()
KERNEL = Path(paths.KERNEL_SRC).resolve()
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


def pristine(tree=None):
    bad = [p.name for p in (tree or C_DIR).glob("*.bpf.o.corig")
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
    ap.add_argument("--gate-workers", type=int, choices=range(1, 9), default=1,
                    help="QEMU gate VMs at once; 1 runs serially in the "
                         "shared selftests output")
    ap.add_argument("--gate-mode", choices=("overlay", "copy"), default="overlay",
                    help="with --gate-workers > 1: each worker writes into a "
                         "private overlay over the shared output "
                         "(scripts/gate-overlay.sh, ~40 MB per object), or into "
                         "its own trimmed copy of it (scripts/gate-workers.sh, "
                         "~0.7 GB per worker; for hosts without unprivileged "
                         "user namespaces)")
    args = ap.parse_args(argv)
    if min(args.proof_timeout, args.runtime_timeout) <= 0:
        ap.error("timeouts must be positive")
    env = os.environ.copy()
    # The checker and codegen read modules from equiv/paths.py's directories.
    # Every stage gets those same values; reject an environment where the
    # kernel-derived paths point at a different tree than KERNEL_SRC.
    expected = {"FLAVOR": "qemu", "BUILD_DIR": str(Path(paths.BUILD_DIR).resolve()),
                "KERNEL_SRC": str(KERNEL),
                "SELFTESTS_SRC": str(KERNEL / "tools/testing/selftests/bpf"),
                "SELFTESTS_OUTPUT": str(C_DIR), "VMLINUX_BTF": str(KERNEL / "vmlinux"),
                "QEMU_KERNEL": str(KERNEL / "arch/x86/boot/bzImage"),
                "TEST_RUNNER": str(REPO / "scripts/qemu-test-progs")}
    for key, value in expected.items():
        given = env.get(key, value)
        if (given if key == "FLAVOR" else os.path.realpath(given)) != value:
            ap.error(f"nightly requires {key}={value}")
    env.update(expected)
    for key in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL", "SWAP_ONLY"):
        env.pop(key, None)
    env.setdefault("LLVM_PREFIX", paths.LLVM_PREFIX)
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
                                     gate_workers=args.gate_workers,
                                     gate_mode=args.gate_mode,
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
    workers = []           # per-worker stage environments
    active_by_worker = {}  # worker index -> object currently swapped in
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

        # Each object: swap the Rust object in and run its consumers, then
        # get back to the C object, running the tests again (the oracle) only
        # when the Rust run failed. Serially that means swapping the C object
        # back into the shared output and rebuilding. With --gate-workers N,
        # N objects run at once: in overlay mode each run writes into a fresh
        # private layer and the shared output is never touched, so going back
        # to C costs nothing; in copy mode each worker owns a trimmed copy.
        # Objects named in scripts/gate-serial run afterwards, alone and in
        # the shared tree.
        gate_root = Path(paths.BUILD_DIR).resolve() / "gate"
        if args.gate_workers > 1 and args.gate_mode == "overlay":
            for k in range(1, args.gate_workers + 1):
                workers.append(dict(env, GATE_DIR=str(gate_root / f"w{k}")))
        elif args.gate_workers > 1:
            require("gate-workers", ["scripts/gate-workers.sh", str(args.gate_workers)])
            for k in range(1, args.gate_workers + 1):
                tree = gate_root / f"w{k}" / C_DIR.name
                workers.append(dict(env, SELFTESTS_OUTPUT=str(tree)))
        else:
            workers.append(env)
        serial_file = REPO / "scripts/gate-serial"
        serial = {line.strip() for line in (serial_file.read_text().splitlines()
                                            if serial_file.exists() else [])
                  if line.strip() and not line.startswith("#")}
        report_lock = threading.Lock()

        def under_kvm(log):
            # vng falls back to TCG silently; an emulated guest is several
            # times slower and produces failures of its own (#52), so its
            # verdicts are not evidence. A run that never booted is judged
            # on its own log.
            text = log.read_text(errors="replace")
            if (not wenv_allows_tcg and "Linux version" in text
                    and "Hypervisor detected: KVM" not in text):
                raise RuntimeError(f"guest ran without KVM (TCG); see {log.relative_to(out)}")

        wenv_allows_tcg = bool(env.get("QEMU_ALLOW_TCG"))

        def gate_overlay(name, wenv):
            def one(which, log):
                rc = run(["scripts/gate-overlay.sh", wenv["GATE_DIR"], name, which],
                         log, wenv, args.runtime_timeout)
                under_kvm(log)
                return rc, *runtime_result(name, rc, log.read_text(errors="replace"))

            rc, verdict, note = one("rust", out / "runtime" / f"{name}.log")
            row = dict(verdict=verdict, exit=rc, summary=note,
                       c_exit=0, c_verdict="NOT-RUN", c_summary="")
            if verdict == "FAIL":
                c_rc, c_verdict, c_note = one("c", out / "runtime" / f"{name}.c.log")
                row.update(c_exit=c_rc, c_verdict=c_verdict, c_summary=c_note)
            return row

        def gate_one(name, wenv):
            if "GATE_DIR" in wenv:
                return gate_overlay(name, wenv)
            log = out / "runtime" / f"{name}.log"
            rc = run(["scripts/swap-and-test.sh", name, "rust"], log, wenv, args.runtime_timeout)
            under_kvm(log)
            verdict, note = runtime_result(name, rc, log.read_text(errors="replace"))
            c_env = wenv if verdict == "FAIL" else dict(wenv, SWAP_ONLY="1")
            c_log = out / "runtime" / f"{name}.c.log"
            c_rc = run(["scripts/swap-and-test.sh", name, "c"], c_log, c_env, args.runtime_timeout)
            under_kvm(c_log)
            c_verdict, c_note = runtime_result(name, c_rc, c_log.read_text(errors="replace"))
            # No consumer is an explicit limitation, not an infrastructure failure.
            if c_rc and c_verdict != "NO-ORACLE":
                if verdict != "FAIL" or c_verdict != "FAIL" or not c_note.startswith("Summary:"):
                    raise RuntimeError(f"C restoration/rebuild failed for {name}; see runtime/{name}.c.log")
            pristine(Path(wenv["SELFTESTS_OUTPUT"]))
            return dict(verdict=verdict, exit=rc, summary=note,
                        c_exit=c_rc, c_verdict=c_verdict if verdict == "FAIL" else "NOT-RUN",
                        c_summary=c_note if verdict == "FAIL" else "")

        def record(name, row):
            nonlocal runtime_failed
            with report_lock:
                report["runtime"][name] = row
                runtime_failed |= row["verdict"] == "FAIL" or (
                    old_gate.get(name) == "PASS" and row["verdict"] != "PASS")
                print(f"runtime [{len(report['runtime'])}/{len(names)}] {name}: "
                      f"{row['verdict']}; restore exit {row['c_exit']}", flush=True)
                save_report(out, report)

        def worker_loop(k, queue):
            while not CANCELLED.is_set():
                with report_lock:
                    if not queue:
                        return
                    name = queue.pop(0)
                    active_by_worker[k] = name
                record(name, gate_one(name, workers[k]))
                with report_lock:
                    active_by_worker.pop(k, None)

        print(f"nightly: QEMU verifier/runtime gate, {len(workers)} worker(s)", flush=True)
        start = time.monotonic()
        runtime_failed = False
        if len(workers) == 1:
            worker_loop(0, list(names))
        else:
            with ThreadPoolExecutor(max_workers=len(workers)) as pool:
                queue = [n for n in names if n not in serial]
                for future in [pool.submit(worker_loop, k, queue)
                               for k in range(len(workers))]:
                    future.result()
            # The classic way, alone in the shared tree: for stress tests
            # another VM's load would perturb, and for consumers an
            # overlay cannot satisfy (see scripts/gate-serial).
            workers.append(env)
            worker_loop(len(workers) - 1, [n for n in names if n in serial])
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
            # Worker trees are private copies, refreshed by gate-workers.sh
            # on the next run; only the shared tree's object needs restoring.
            for k, name in list(active_by_worker.items()):
                if workers[k] is env:
                    cleanup_stage("restore-active", ["scripts/swap-and-test.sh", name, "c"],
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
