"""The QEMU verifier/runtime gate, shared by its two drivers.

ci_nightly.py runs every translation afresh and never writes a baseline;
gate.py re-runs only the translations whose inputs changed, against the
committed qemu/gate/baseline.tsv. Both swap an object into the selftests
output through scripts/swap-and-test.sh (alone, in the shared tree) or
scripts/gate-overlay.sh (N at once, each in a private overlay), judge the
guest's test_progs summary, and put the C object back. An overlay worker
boots its guest once and feeds it its objects one after another (Guest,
scripts/gate-guest-loop): booting per object cost ~16 s of boot, init and
setup for a median 0.5 s of tests (docs/gate-runtime.md). While the guest
runs one object the worker builds the next one's layer (gate-overlay.sh
step 1, in a thread) in the other of its two slots, so the host-side build
(~1.2 s, more than a median object's tests) overlaps the guest. Anything
but a PASS from that guest is rerun the classic way, alone in a fresh
guest, so a verdict other than PASS never rests on a shared kernel.

The driver passes its own `run` into Gate so that a test's substitute
reaches every guest launch; the process bookkeeping here (CHILDREN,
CANCELLED, stop_children, interrupted) is what those `run`s share.
"""
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "equiv"))
import guard  # noqa: E402

CHILDREN = set()
CHILD_LOCK = threading.RLock()
CANCELLED = threading.Event()
BASELINE_HEADER = "# name\trust_md5\tc_md5\tenv_md5\tverdict\tseconds\tsummary\n"
# Everything besides the two objects that decides a gate verdict: the
# kernel and its modules, the scripts that swap, build and boot, the test
# exclusions and the guest size. The selftests output tree itself is not
# hashed (test_progs is relinked on every swap); the kernel pin and the
# per-object C hash stand for it, as in the nightly.
ENV_FILES = ["scripts/swap-and-test.sh", "scripts/affected_tests.py",
             "scripts/qemu-test-progs", "scripts/gate-overlay.sh",
             "scripts/gate-record-filter", "scripts/known-bad-tests",
             "scripts/gate-serial", "scripts/extra-consumers",
             "scripts/gate-guest-loop"]


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


def run(argv, log, env, timeout=None, cwd=REPO):
    """Log without pipe buffering; kill the whole subprocess tree on timeout."""
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("wb") as output:
        output.write(("$ " + repr([str(a) for a in argv]) + "\n").encode())
        output.flush()
        with CHILD_LOCK:
            if CANCELLED.is_set():
                return 130
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
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
            output.write(f"\ngate: timed out after {timeout}s\n".encode())
            return 124
        finally:
            with CHILD_LOCK:
                CHILDREN.discard(child)


def spawn(argv, log, env, cwd=REPO):
    """A child that outlives the call (a worker's guest), appending to log;
    registered like run()'s so stop_children() reaches it. The caller
    discards it from CHILDREN when it is gone. None once cancelled."""
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("ab") as output:
        output.write(("$ " + repr([str(a) for a in argv]) + "\n").encode())
        output.flush()
        with CHILD_LOCK:
            if CANCELLED.is_set():
                return None
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                     stdout=output, stderr=subprocess.STDOUT,
                                     start_new_session=True)
            CHILDREN.add(child)
    return child


class Guest:
    """A worker's guest, booted once (scripts/qemu-test-progs under GATE_LOOP)
    and fed objects through <worker>/jobs/<n>: the host posts a slot's upper
    (gate-overlay.sh step 1 under GATE_PREPARE) as a job, the guest writes
    its rc there (scripts/gate-guest-loop has the protocol)."""

    def __init__(self, spawn, wenv, log):
        self.dir = Path(wenv["GATE_DIR"])
        self.log = log
        self.next_job = 0
        self.checked = False  # under_kvm, once the boot log is there
        shutil.rmtree(self.dir / "jobs", ignore_errors=True)
        (self.dir / "jobs").mkdir(parents=True)
        (self.dir / "stop").unlink(missing_ok=True)
        self.proc = spawn(["scripts/qemu-test-progs"], log, dict(wenv, GATE_LOOP=str(self.dir)))

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def post(self, upper):
        """Post a prepared slot's upper as the next job; ready goes last, it
        is what the guest acts on. Returns the job number."""
        n = self.next_job
        self.next_job += 1
        job = self.dir / "jobs" / str(n)
        job.mkdir(parents=True)
        (job / "upper").write_text(f"{upper}\n")
        (job / "ready").touch()
        return n

    def job_log(self, n):
        return self.dir / "jobs" / str(n) / "log"

    def wait(self, n, timeout):
        """test_progs's exit status for job n, or None when the guest died
        or the deadline passed; the guest is stopped then."""
        rc_file = self.dir / "jobs" / str(n) / "rc"
        deadline = time.monotonic() + timeout
        while True:
            if rc_file.exists():  # written by rename: complete once seen
                return int(rc_file.read_text().strip() or 99)
            if not self.alive() or time.monotonic() > deadline or CANCELLED.is_set():
                self.stop()
                return None
            time.sleep(0.05)

    def stop(self, grace=15):
        """Ask the loop to leave; kill the guest's process group if it does
        not within grace seconds (vng's power-off takes a moment)."""
        self.request_stop()
        self.join(grace)

    def request_stop(self):
        (self.dir / "stop").touch()

    def join(self, grace=15):
        proc, self.proc = self.proc, None
        if proc is None:
            return
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        finally:
            with CHILD_LOCK:
                CHILDREN.discard(proc)


# test_progs' exit status when the -t filter selected no test: the consumer
# defines a test function the selftests Makefile did not register
# (gen_tests_hdr's sed takes `void test_x(void)` at the start of a line;
# prog_tests/uretprobe_stack.c prefixes its with `__weak`), so nothing ran,
# with the C object either. Not a PASS, and not a FAIL of the translation.
EXIT_NO_TEST = 2


def runtime_result(name, rc, text):
    summary = next((line for line in reversed(text.splitlines())
                    if line.startswith("Summary:")), "")
    if rc == 0 and summary:
        return "PASS", summary
    if rc == EXIT_NO_TEST and summary.startswith("Summary: 0/0 PASSED"):
        return "NO-ORACLE", "no registered test ran (test_progs EXIT_NO_TEST)"
    if rc != 124 and (f"no prog_tests consume {name}" in text
                      or re.search(r"^\[swap\] affected tests:\s*$", text, re.M)):
        # no consumer at all, or every consumer is in known-bad-tests
        return "NO-ORACLE", summary
    return "FAIL", summary or f"exit {rc}; no test summary"


def pristine(tree):
    """Every backed-up C object must be the installed one."""
    bad = [p.name for p in Path(tree).glob("*.bpf.o.corig")
           if not p.with_suffix("").exists()
           or guard.md5(p) != guard.md5(p.with_suffix(""))]
    if bad:
        raise RuntimeError("C objects not restored: " + ", ".join(bad))


def read_serial(path):
    """The objects scripts/gate-serial keeps out of the parallel workers."""
    path = Path(path)
    if not path.exists():
        return set()
    return {line.strip() for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")}


def under_kvm(log, allow_tcg, base, booted=False):
    # vng falls back to TCG silently; an emulated guest is several times
    # slower and produces failures of its own (#52), so its verdicts are
    # not evidence. A run that never booted is judged on its own log; a
    # guest known to have booted (`booted`: it answered a job) must show
    # its banner, or the check would skip in silence.
    text = log.read_text(errors="replace")
    if "Linux version" not in text:
        if booted:
            raise RuntimeError(f"guest log has no kernel banner; see {log.relative_to(base)}")
        return
    if not allow_tcg and "Hypervisor detected: KVM" not in text:
        raise RuntimeError(f"guest ran without KVM (TCG); see {log.relative_to(base)}")


def make_env(repo, kernel, c_dir, error):
    """The stage environment: the QEMU flavor with every kernel-derived path
    under KERNEL_SRC. `error` reports a conflicting caller environment."""
    import paths
    env = os.environ.copy()
    expected = {"FLAVOR": "qemu", "BUILD_DIR": str(Path(paths.BUILD_DIR).resolve()),
                "KERNEL_SRC": str(kernel),
                "SELFTESTS_SRC": str(kernel / "tools/testing/selftests/bpf"),
                "SELFTESTS_OUTPUT": str(c_dir), "VMLINUX_BTF": str(kernel / "vmlinux"),
                "QEMU_KERNEL": str(kernel / "arch/x86/boot/bzImage"),
                "TEST_RUNNER": str(repo / "scripts/qemu-test-progs")}
    for key, value in expected.items():
        given = env.get(key, value)
        if (given if key == "FLAVOR" else os.path.realpath(given)) != value:
            error(f"requires {key}={value}")
    env.update(expected)
    for key in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL", "SWAP_ONLY"):
        env.pop(key, None)
    env.setdefault("LLVM_PREFIX", paths.LLVM_PREFIX)
    env.setdefault("QEMU_CPUS", "4")
    return env


def take_locks(lock_paths, error):
    """Hold every lock (non-blocking) for as long as the returned files live:
    one gate per checkout and per shared selftests output."""
    locks = []
    for path in lock_paths:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            lock = path.open("a")
            locks.append(lock)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            error(f"another gate or nightly run holds {path}")
        except OSError as exc:
            error(f"cannot lock {path}: {exc}")
    return locks


def overlay_envs(env, gate_root, n):
    return [dict(env, GATE_DIR=str(Path(gate_root) / f"w{k}")) for k in range(1, n + 1)]


def parse_baseline(text):
    """Rows keyed by name. A row is name, Rust md5, C md5, env md5, verdict,
    the wall seconds its last run took (empty when unknown; files from
    before the column have six fields) and the test summary."""
    rows = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t", 6)
        if len(fields) == 6:
            fields.insert(5, "")
        name, r, c, e, verdict, seconds, summary = fields
        if name in rows:
            raise ValueError(f"duplicate baseline row: {name}")
        rows[name] = dict(r=r, c=c, e=e, verdict=verdict, seconds=seconds, summary=summary)
    return rows


def load_baseline(path):
    path = Path(path)
    return parse_baseline(path.read_text()) if path.exists() else {}


def save_baseline(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w") as f:
        f.write(BASELINE_HEADER)
        for name in sorted(rows):
            row = rows[name]
            summary = row["summary"].replace("\t", " ").replace("\n", " ")
            f.write(f"{name}\t{row['r']}\t{row['c']}\t{row['e']}\t{row['verdict']}\t"
                    f"{row.get('seconds', '')}\t{summary}\n")
    temporary.replace(path)


def recorded_seconds(rows):
    """name -> seconds from baseline rows that carry a number."""
    seconds = {}
    for name, row in rows.items():
        try:
            seconds[name] = float(row.get("seconds") or "")
        except ValueError:
            pass
    return seconds


def longest_first(names, seconds):
    """Unknown durations first (in the given order), then longest first;
    ties keep the given order."""
    return sorted(names, key=lambda n: (n in seconds, -seconds.get(n, 0.0)))


def baseline_row(rust_md5, c_md5, env_md5, result):
    """A baseline row from a gate result (Gate.gate_one's dict)."""
    summary = result["summary"]
    if result["verdict"] == "NO-ORACLE" and not summary:
        summary = "no consuming prog_tests"
    if result["verdict"] == "FAIL":
        oracle = {"PASS": "C-PASS", "NO-ORACLE": "C-NOCONSUMER"}.get(result["c_verdict"], "C-FAIL")
        summary = f"{summary}; {oracle}"
    return dict(r=rust_md5, c=c_md5, e=env_md5, verdict=result["verdict"],
                seconds=str(result.get("seconds", "")), summary=summary)


def env_hash(repo, kernel, c_dir, env):
    """One hash over every gate input that is not one of the two objects."""
    repo, kernel, c_dir = Path(repo), Path(kernel), Path(c_dir)
    h = hashlib.md5()
    h.update((repo / "kernel-commit").read_bytes())
    for patch in sorted((repo / "patches/kernel").glob("*.patch")):
        h.update(patch.name.encode() + b"\0" + patch.read_bytes())
    for binary in (Path(env["QEMU_KERNEL"]), repo / "bld/vmlinux.btf"):
        h.update(binary.name.encode() + b"\0")
        h.update(guard.md5(binary).encode() if binary.exists() else b"missing")
    guard.module_btf_digest(h, str(c_dir))
    for name in ENV_FILES:
        path = repo / name
        h.update(name.encode() + b"\0")
        h.update(path.read_bytes() if path.exists() else b"")
    h.update(f"QEMU_CPUS={env.get('QEMU_CPUS', '')}".encode())
    return h.hexdigest()


class Gate:
    """Run objects through the gate on a set of worker environments.

    A worker environment with GATE_DIR runs through gate-overlay.sh, in the
    worker's one guest when `spawn` is given (Guest, with the next object's
    step 1 overlapping the guest: pipelined_loop; the classic one guest per
    object otherwise, and as the rerun of anything but a PASS); the shared
    environment (the one given to the constructor) runs through
    swap-and-test.sh in the shared tree. on_row(name, result) is called
    for every finished object, under the gate's lock.
    """

    SLOTS = 2  # layers per worker: one the guest runs, one the host builds

    def __init__(self, *, run, env, log_dir, timeout, base, on_row, spawn=None):
        self.run = run
        self.spawn = spawn
        self.guests = {}       # GATE_DIR -> Guest
        self.boots = {}        # GATE_DIR -> guests booted, for the log names
        self.shared_env = env
        self.log_dir = Path(log_dir)
        self.timeout = timeout
        self.base = Path(base)
        self.on_row = on_row
        self.allow_tcg = bool(env.get("QEMU_ALLOW_TCG"))
        self.lock = threading.Lock()
        self.workers = []
        self.active_by_worker = {}

    def classic(self, name, wenv, which, log):
        """One object alone in a fresh guest: gate-overlay.sh over
        <worker>/upper (never a slot, which may hold the next object)."""
        rc = self.run(["scripts/gate-overlay.sh", wenv["GATE_DIR"], name, which],
                      log, wenv, self.timeout)
        under_kvm(log, self.allow_tcg, self.base)
        return rc, *runtime_result(name, rc, log.read_text(errors="replace"))

    def gate_overlay(self, name, wenv):
        """The classic way, one guest per object (a worker without spawn)."""
        rc, verdict, note = self.classic(name, wenv, "rust", self.log_dir / f"{name}.log")
        row = dict(verdict=verdict, exit=rc, summary=note,
                   c_exit=0, c_verdict="NOT-RUN", c_summary="")
        return self.with_oracle(name, wenv, row)

    def with_oracle(self, name, wenv, row):
        if row["verdict"] == "FAIL":
            c_rc, c_verdict, c_note = self.classic(name, wenv, "c", self.log_dir / f"{name}.c.log")
            row.update(c_exit=c_rc, c_verdict=c_verdict, c_summary=c_note)
        return row

    def prepare(self, name, wenv, slot):
        """gate-overlay.sh step 1 of `name` into the worker's slot
        (GATE_PREPARE): the layer the guest will run, with the -t filter and
        -d denylist in it. What finish() needs, `seconds` included."""
        log = self.log_dir / f"{name}.log"
        slot_dir = Path(wenv["GATE_DIR"]) / f"s{slot}"
        start = time.monotonic()
        rc = self.run(["scripts/gate-overlay.sh", str(slot_dir), name, "rust"],
                      log, dict(wenv, GATE_PREPARE="1"), self.timeout)
        seconds = time.monotonic() - start
        with log.open("ab") as out:
            out.write(f"[gate] step 1 took {seconds:.2f} s (rc {rc})\n".encode())
        return dict(name=name, log=log, rc=rc, upper=slot_dir / "upper", seconds=seconds)

    def finish(self, wenv, prepared):
        """The verdict dict of a prepared object: its job in the worker's
        guest, the classic rerun of anything but a PASS, the C oracle after
        a FAIL."""
        name, log = prepared["name"], prepared["log"]
        row = self.gate_in_guest(wenv, prepared)
        if row is None:
            rc, verdict, note = self.classic(name, wenv, "rust", log)
            row = dict(verdict=verdict, exit=rc, summary=note,
                       c_exit=0, c_verdict="NOT-RUN", c_summary="")
        return self.with_oracle(name, wenv, row)

    def guest_for(self, wenv):
        key = wenv["GATE_DIR"]
        guest = self.guests.get(key)
        if guest is None or not guest.alive():
            self.boots[key] = self.boots.get(key, 0) + 1
            log = self.log_dir / f"guest-{Path(key).name}-{self.boots[key]}.log"
            guest = self.guests[key] = Guest(self.spawn, wenv, log)
        return guest

    def gate_in_guest(self, wenv, prepared):
        """The prepared object as one job of the worker's guest. None when it
        has to be rerun the classic way: a FAIL, a guest that died (a kernel
        crash is the usual reason) or a job past the timeout; the guest is
        stopped then, so nothing a failing test left behind reaches the next
        object. A step-1 failure (no consumer, a build error) is judged as
        it is: the classic path would fail the same step."""
        name, log, rc = prepared["name"], prepared["log"], prepared["rc"]
        if rc:
            verdict, note = runtime_result(name, rc, log.read_text(errors="replace"))
            return dict(verdict=verdict, exit=rc, summary=note,
                        c_exit=0, c_verdict="NOT-RUN", c_summary="")
        guest = self.guest_for(wenv)
        n = guest.post(prepared["upper"])
        rc = guest.wait(n, self.timeout)
        job_log = guest.job_log(n)
        with log.open("ab") as out:
            out.write(f"\n[gate] job {n} of {guest.log.name}: "
                      f"{'rc ' + str(rc) if rc is not None else 'no result (guest gone or timed out)'}\n".encode())
            if job_log.exists():
                out.write(job_log.read_bytes())
        if rc is None:
            shutil.copyfile(log, log.with_suffix(".loop.log"))
            return None
        if not guest.checked:
            under_kvm(guest.log, self.allow_tcg, self.base, booted=True)
            guest.checked = True
        verdict, note = runtime_result(name, rc, log.read_text(errors="replace"))
        if verdict == "FAIL":
            guest.stop()
            self.guests.pop(wenv["GATE_DIR"], None)
            shutil.copyfile(log, log.with_suffix(".loop.log"))
            return None
        return dict(verdict=verdict, exit=rc, summary=note,
                    c_exit=0, c_verdict="NOT-RUN", c_summary="")

    def stop_guests(self):
        guests = list(self.guests.values())
        self.guests.clear()
        for guest in guests:
            guest.request_stop()
        for guest in guests:
            guest.join()

    def gate_one(self, name, wenv):
        """The verdict dict, with `seconds`: the wall time the worker spent on
        the object (the C re-run after a FAIL included)."""
        start = time.monotonic()
        result = self._gate_one(name, wenv)
        result["seconds"] = round(time.monotonic() - start)
        return result

    def _gate_one(self, name, wenv):
        if "GATE_DIR" in wenv:
            return self.gate_overlay(name, wenv)
        log = self.log_dir / f"{name}.log"
        rc = self.run(["scripts/swap-and-test.sh", name, "rust"], log, wenv, self.timeout)
        under_kvm(log, self.allow_tcg, self.base)
        verdict, note = runtime_result(name, rc, log.read_text(errors="replace"))
        c_env = wenv if verdict == "FAIL" else dict(wenv, SWAP_ONLY="1")
        c_log = self.log_dir / f"{name}.c.log"
        c_rc = self.run(["scripts/swap-and-test.sh", name, "c"], c_log, c_env, self.timeout)
        under_kvm(c_log, self.allow_tcg, self.base)
        c_verdict, c_note = runtime_result(name, c_rc, c_log.read_text(errors="replace"))
        # No consumer is an explicit limitation, not an infrastructure failure.
        if c_rc and c_verdict != "NO-ORACLE":
            if verdict != "FAIL" or c_verdict != "FAIL" or not c_note.startswith("Summary:"):
                raise RuntimeError(f"C restoration/rebuild failed for {name}; "
                                   f"see {c_log.relative_to(self.base)}")
        pristine(wenv["SELFTESTS_OUTPUT"])
        return dict(verdict=verdict, exit=rc, summary=note,
                    c_exit=c_rc, c_verdict=c_verdict if verdict == "FAIL" else "NOT-RUN",
                    c_summary=c_note if verdict == "FAIL" else "")

    def take(self, queue):
        with self.lock:
            return queue.pop(0) if queue else None

    def worker_loop(self, k, queue):
        if self.spawn and "GATE_DIR" in self.workers[k]:
            return self.pipelined_loop(k, queue)
        while not CANCELLED.is_set():
            name = self.take(queue)
            if name is None:
                return
            with self.lock:
                self.active_by_worker[k] = name
            result = self.gate_one(name, self.workers[k])
            with self.lock:
                self.on_row(name, result)
                self.active_by_worker.pop(k, None)

    def pipelined_loop(self, k, queue):
        """An overlay worker with a guest: while the guest runs one object,
        a builder thread prepares the next one in the other slot. A slot is
        rebuilt only after the rc of its last job (the guest has unmounted
        it by then). `seconds` of an object = its step 1 + the rest, so the
        column's sum exceeds the worker's wall time by the overlap. An
        object prepared when the gate is cancelled is dropped unrecorded."""
        wenv = self.workers[k]
        count = 0
        with ThreadPoolExecutor(max_workers=1) as builder:
            def start(name):
                nonlocal count
                future = builder.submit(self.prepare, name, wenv, count % self.SLOTS)
                count += 1
                return future

            name = self.take(queue)
            if name is None:
                return
            self.guest_for(wenv)  # boot now: it overlaps the first step 1
            pending = start(name)
            while pending is not None:
                prepared = pending.result()
                if CANCELLED.is_set():
                    return
                name = self.take(queue)
                pending = start(name) if name is not None else None
                with self.lock:
                    self.active_by_worker[k] = prepared["name"]
                started = time.monotonic()
                result = self.finish(wenv, prepared)
                result["seconds"] = round(prepared["seconds"] + time.monotonic() - started)
                with self.lock:
                    self.on_row(prepared["name"], result)
                    self.active_by_worker.pop(k, None)

    def run_all(self, names, workers, serial, seconds=None):
        """Every name once: the non-serial ones over `workers`, then the
        serial ones alone in the shared tree. One worker means the shared
        tree for everything. `seconds` (name -> the last recorded run time)
        orders the parallel queue longest first, the standard greedy
        against a long object landing last; names without a record (new
        translations) go first."""
        self.workers = list(workers)
        if len(self.workers) == 1:
            self.worker_loop(0, list(names))
            return
        with ThreadPoolExecutor(max_workers=len(self.workers)) as pool:
            queue = longest_first([n for n in names if n not in serial], seconds or {})
            try:
                for future in [pool.submit(self.worker_loop, k, queue)
                               for k in range(len(self.workers))]:
                    future.result()
            finally:
                self.stop_guests()
        # The classic way, alone in the shared tree: stress tests another
        # VM's load would perturb (see scripts/gate-serial).
        self.workers.append(self.shared_env)
        self.worker_loop(len(self.workers) - 1, [n for n in names if n in serial])

    def active_in_shared_tree(self):
        """Objects a worker had swapped into the shared tree when it stopped;
        overlay workers never touch it."""
        return [name for k, name in list(self.active_by_worker.items())
                if self.workers[k] is self.shared_env]
