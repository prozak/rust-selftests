"""The incremental QEMU gate re-runs exactly what changed and keeps the C tree pristine."""
import fcntl
import hashlib
import json
from pathlib import Path
import signal
import sys
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import fake_guest  # noqa: E402
import gate  # noqa: E402
import qemu_gate  # noqa: E402

ENV_FILES = ["scripts/swap-and-test.sh", "scripts/affected_tests.py", "scripts/qemu-test-progs",
             "scripts/gate-overlay.sh", "scripts/gate-record-filter", "scripts/known-bad-tests"]


def md5(path):
    return hashlib.md5(Path(path).read_bytes()).hexdigest()


@pytest.fixture
def stack(tmp_path, monkeypatch):
    repo = tmp_path / "repo with spaces"
    c_dir = tmp_path / "selftests"
    kernel = tmp_path / "kernel"
    build = tmp_path / "build"
    for p in [repo / "progs", repo / "bld", repo / "scripts", repo / "qemu/gate", c_dir, kernel]:
        p.mkdir(parents=True)
    (repo / "progs/a.rs").write_text("rust source")
    (repo / "kernel-commit").write_text("pin\n")
    for name in ENV_FILES:
        (repo / name).write_text(f"# {name}\n")
    (c_dir / "a.bpf.o").write_text("C")
    (c_dir / "a.bpf.o.corig").write_text("C")
    (repo / "bld/a.bpf.o").write_text("Rust")
    monkeypatch.setattr(gate, "REPO", repo)
    monkeypatch.setattr(gate, "C_DIR", c_dir)
    monkeypatch.setattr(gate, "KERNEL", kernel)
    monkeypatch.setattr(gate, "kvm_available", lambda: True)
    monkeypatch.setattr(gate.paths, "BUILD_DIR", str(build))
    for key in ["FLAVOR", "KERNEL_SRC", "SELFTESTS_SRC", "SELFTESTS_OUTPUT", "VMLINUX_BTF",
                "QEMU_KERNEL", "TEST_RUNNER", "BUILD_DIR", "QEMU_ALLOW_TCG", "QEMU_CPUS"]:
        monkeypatch.delenv(key, raising=False)
    calls = []
    controls = dict(runtime=0, restore=0, interrupt=False, no_oracle=False, build=0)

    def fake_run(argv, log, env, timeout=None):
        argv = [str(a) for a in argv]
        calls.append((argv, dict(env)))
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("")
        if "restore-all" in argv:
            (c_dir / "a.bpf.o").write_bytes((c_dir / "a.bpf.o.corig").read_bytes())
        elif argv[-1] == "all":
            assert "-B" not in argv
            return controls["build"]
        elif argv[0] in ("scripts/swap-and-test.sh", "scripts/gate-overlay.sh"):
            shared = argv[0] == "scripts/swap-and-test.sh"
            if argv[-1] == "rust":
                if shared:
                    (c_dir / "a.bpf.o").write_text("Rust")
                if controls["interrupt"]:
                    raise KeyboardInterrupt
                if controls["no_oracle"]:
                    log.write_text("no prog_tests consume a\n")
                    return 1
                if "GATE_PREPARE" in env:
                    # gate-overlay.sh step 1 into a slot; the gate posts it
                    # as a job and the guest answers
                    if controls["runtime"]:
                        log.write_text("[swap] build failed\n")
                        return controls["runtime"]
                    log.write_text(f"[gate-overlay] prepared {argv[1]}/upper\n")
                    return 0
                log.write_text("Summary: 1/0 PASSED, 0 SKIPPED, 0/0 FAILED\n")
                return controls["runtime"]
            if shared:
                (c_dir / "a.bpf.o").write_text("C")
            if controls["no_oracle"]:
                log.write_text("no prog_tests consume a\n")
                return 1
            if not env.get("SWAP_ONLY"):
                log.write_text("Summary: 1/0 PASSED, 0 SKIPPED, 0/0 FAILED\n")
            return controls["restore"]
        return 0

    monkeypatch.setattr(gate, "run", fake_run)
    guests = []
    controls.update(job_rc=0, guest_dies=False, job_hangs=False, guests=guests)
    monkeypatch.setattr(qemu_gate, "spawn", fake_guest.fake_spawn(controls, guests))
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    yield repo, c_dir, calls, controls
    for sig, handler in handlers.items():
        signal.signal(sig, handler)


def current_env_hash(repo, c_dir):
    return qemu_gate.env_hash(repo, gate.KERNEL, c_dir,
                              dict(QEMU_KERNEL=str(gate.KERNEL / "arch/x86/boot/bzImage"),
                                   QEMU_CPUS="4"))


def seed(repo, c_dir, verdict="PASS", summary="Summary: 1/0 PASSED", **override):
    row = dict(r=md5(repo / "bld/a.bpf.o"), c=md5(c_dir / "a.bpf.o"),
               e=current_env_hash(repo, c_dir), verdict=verdict, seconds="", summary=summary)
    row.update(override)
    qemu_gate.save_baseline(repo / gate.BASELINE, {"a": row})
    return row


def baseline(repo):
    return qemu_gate.load_baseline(repo / gate.BASELINE)


def gate_runs(calls):
    return [(argv[0], argv[-1]) for argv, _ in calls
            if argv[0] in ("scripts/swap-and-test.sh", "scripts/gate-overlay.sh")]


def test_unchanged_rows_are_cached_and_nothing_boots(stack, capsys):
    repo, c_dir, calls, _ = stack
    before = seed(repo, c_dir)
    assert gate.main([]) == 0
    assert gate_runs(calls) == []
    assert baseline(repo)["a"] == before
    out = capsys.readouterr().out
    assert "1 unchanged (cached), 0 to run" in out and "everything up to date" in out
    # the C tree is restored first and last, and bld/ brought up to date
    assert calls[0][0][-1] == "restore-all" and calls[-1][0][-1] == "restore-all"
    assert any(argv[-1] == "all" for argv, _ in calls)


@pytest.mark.parametrize("which", ["rust", "c"])
def test_object_change_regates_and_rewrites_row(stack, which):
    repo, c_dir, calls, _ = stack
    seed(repo, c_dir, summary="old")
    if which == "rust":
        (repo / "bld/a.bpf.o").write_text("new Rust")
    else:
        for name in ("a.bpf.o", "a.bpf.o.corig"):
            (c_dir / name).write_text("new C")
    assert gate.main([]) == 0
    assert gate_runs(calls) == [("scripts/gate-overlay.sh", "rust")]
    row = baseline(repo)["a"]
    assert row["verdict"] == "PASS" and row["summary"].startswith("Summary:")
    assert row["r"] == md5(repo / "bld/a.bpf.o") and row["c"] == md5(c_dir / "a.bpf.o")
    assert (c_dir / "a.bpf.o").read_text() == (c_dir / "a.bpf.o.corig").read_text()


def test_environment_change_refuses_without_all(stack, capsys):
    repo, c_dir, calls, _ = stack
    before = seed(repo, c_dir, e="other environment")
    assert gate.main([]) == 2
    assert gate_runs(calls) == []
    assert baseline(repo)["a"] == before
    assert "ENVIRONMENT CHANGED" in capsys.readouterr().out


def test_all_regates_after_environment_change(stack):
    repo, c_dir, calls, _ = stack
    seed(repo, c_dir, e="other environment")
    assert gate.main(["--all"]) == 0
    assert gate_runs(calls) == [("scripts/gate-overlay.sh", "rust")]
    assert baseline(repo)["a"]["e"] == current_env_hash(repo, c_dir)


def test_all_with_names_forces_unchanged_rows(stack):
    repo, c_dir, calls, _ = stack
    seed(repo, c_dir, summary="old")
    assert gate.main(["--all", "a"]) == 0
    assert gate_runs(calls) == [("scripts/gate-overlay.sh", "rust")]
    assert baseline(repo)["a"]["summary"].startswith("Summary:")


def test_env_hash_tracks_its_inputs(stack):
    repo, c_dir, _, _ = stack
    first = current_env_hash(repo, c_dir)
    (repo / "scripts/known-bad-tests").write_text("flaky_test\n")
    second = current_env_hash(repo, c_dir)
    assert second != first
    env = dict(QEMU_KERNEL=str(gate.KERNEL / "arch/x86/boot/bzImage"), QEMU_CPUS="2")
    assert qemu_gate.env_hash(repo, gate.KERNEL, c_dir, env) != second
    (repo / "scripts/gate-serial").write_text("a\n")
    assert current_env_hash(repo, c_dir) != second


def test_fail_runs_c_oracle_and_alarms(stack, capsys):
    repo, c_dir, calls, controls = stack
    controls["runtime"] = 1
    (repo / "bld/a.bpf.o").write_text("broken Rust")
    assert gate.main([]) == 1
    assert gate_runs(calls) == [("scripts/gate-overlay.sh", "rust"), ("scripts/gate-overlay.sh", "c")]
    row = baseline(repo)["a"]
    assert row["verdict"] == "FAIL" and row["summary"].endswith("; C-PASS")
    assert "<<< ALARM" in capsys.readouterr().out


def test_cached_fail_keeps_alarming(stack, capsys):
    repo, c_dir, calls, _ = stack
    seed(repo, c_dir, verdict="FAIL", summary="Summary: 0/0 PASSED, 0 SKIPPED, 1/1 FAILED; C-PASS")
    assert gate.main([]) == 1
    assert gate_runs(calls) == []
    assert "1 FAIL" in capsys.readouterr().out


def test_pass_to_no_oracle_downgrade_alarms(stack, capsys):
    repo, c_dir, _, controls = stack
    seed(repo, c_dir)
    (repo / "bld/a.bpf.o").write_text("Rust without consumers")
    controls["no_oracle"] = True
    assert gate.main([]) == 1
    assert baseline(repo)["a"]["verdict"] == "NO-ORACLE"
    assert "was PASS" in capsys.readouterr().out


def test_new_no_oracle_is_not_an_alarm(stack):
    repo, _, _, controls = stack
    controls["no_oracle"] = True
    assert gate.main([]) == 0
    row = baseline(repo)["a"]
    assert row["verdict"] == "NO-ORACLE" and row["summary"] == "no consuming prog_tests"


def test_reseed_from_nightly_tsv_checks_hashes(stack, capsys):
    repo, c_dir, calls, _ = stack
    nightly = repo / "nightly/run"
    nightly.mkdir(parents=True)
    row = dict(r=md5(repo / "bld/a.bpf.o"), c=md5(c_dir / "a.bpf.o"),
               e=current_env_hash(repo, c_dir), verdict="PASS", seconds="21",
               summary="Summary: 1/0 PASSED")
    qemu_gate.save_baseline(nightly / "runtime-after.tsv", {"a": row})
    assert gate.main(["--reseed", str(nightly / "runtime-after.tsv")]) == 0
    assert baseline(repo)["a"] == row and gate_runs(calls) == []
    (repo / "bld/a.bpf.o").write_text("rebuilt since")
    assert gate.main(["--reseed", str(nightly / "runtime-after.tsv")]) == 2
    out = capsys.readouterr().out
    assert "REFUSED" in out and "a (r)" in out
    assert baseline(repo)["a"] == row


def test_reseed_from_nightly_summary_takes_verdicts(stack):
    repo, c_dir, calls, _ = stack
    nightly = repo / "nightly/run"
    nightly.mkdir(parents=True)
    (nightly / "summary.json").write_text(json.dumps(dict(runtime=dict(a=dict(
        verdict="FAIL", summary="Summary: 0/0 PASSED, 0 SKIPPED, 1/1 FAILED",
        c_verdict="PASS")))))
    (nightly / "object-hashes.json").write_text(json.dumps(dict(a=dict(c=md5(c_dir / "a.bpf.o"), r="old"))))
    assert gate.main(["--reseed", str(nightly / "summary.json")]) == 0
    row = baseline(repo)["a"]
    assert row["verdict"] == "FAIL" and row["summary"].endswith("; C-PASS")
    assert row["r"] == md5(repo / "bld/a.bpf.o") and row["e"] == current_env_hash(repo, c_dir)
    assert gate_runs(calls) == []
    (nightly / "object-hashes.json").write_text(json.dumps(dict(a=dict(c="other C", r="old"))))
    assert gate.main(["--reseed", str(nightly / "summary.json")]) == 2


def test_serial_list_object_runs_in_the_shared_tree(stack):
    repo, c_dir, calls, _ = stack
    (repo / "scripts/gate-serial").write_text("# alone\na\n")
    assert gate.main([]) == 0
    runs = [(argv[0], argv[-1], env["SELFTESTS_OUTPUT"], "GATE_DIR" in env, env.get("SWAP_ONLY"))
            for argv, env in calls if argv[0] == "scripts/swap-and-test.sh"]
    assert runs == [("scripts/swap-and-test.sh", "rust", str(c_dir), False, None),
                    ("scripts/swap-and-test.sh", "c", str(c_dir), False, "1")]
    assert not any(argv[0] == "scripts/gate-overlay.sh" for argv, _ in calls)


def test_one_worker_runs_everything_in_the_shared_tree(stack):
    repo, c_dir, calls, _ = stack
    assert gate.main(["--workers", "1"]) == 0
    assert gate_runs(calls) == [("scripts/swap-and-test.sh", "rust"), ("scripts/swap-and-test.sh", "c")]


def test_interrupt_restores_active_shared_object(stack):
    repo, c_dir, calls, controls = stack
    (repo / "scripts/gate-serial").write_text("a\n")
    seed(repo, c_dir, summary="before")
    (repo / "bld/a.bpf.o").write_text("changed")
    controls["interrupt"] = True
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    assert gate.main([]) == 1
    tail = [(argv[0], argv[-1], env.get("SWAP_ONLY")) for argv, env in calls[-2:]]
    assert tail == [("scripts/swap-and-test.sh", "c", "1"), ("make", "restore-all", None)]
    assert (c_dir / "a.bpf.o").read_text() == "C"
    assert baseline(repo)["a"]["summary"] == "before"
    assert all(signal.getsignal(sig) == handler for sig, handler in handlers.items())


def test_failed_build_stops_before_any_guest_and_restores(stack):
    repo, c_dir, calls, controls = stack
    controls["build"] = 1
    assert gate.main([]) == 1
    assert gate_runs(calls) == [] and calls[-1][0][-1] == "restore-all"


def test_shared_output_lock_blocks_gate(stack):
    repo, c_dir, calls, _ = stack
    with (c_dir / ".ci-nightly.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(SystemExit) as error:
            gate.main([])
        assert error.value.code == 2
    assert calls == []


@pytest.mark.parametrize("allow_tcg", [False, True])
def test_missing_kvm_is_an_error_only_when_a_guest_is_needed(stack, monkeypatch, allow_tcg, capsys):
    repo, c_dir, calls, _ = stack
    monkeypatch.setattr(gate, "kvm_available", lambda: False)
    if allow_tcg:
        monkeypatch.setenv("QEMU_ALLOW_TCG", "1")
    seed(repo, c_dir)
    assert gate.main([]) == 0            # nothing to run: no guest, no complaint
    (repo / "bld/a.bpf.o").write_text("changed")
    rc = gate.main([])
    if allow_tcg:
        assert rc == 0 and gate_runs(calls) == [("scripts/gate-overlay.sh", "rust")]
    else:
        assert rc == 1 and gate_runs(calls) == []
        assert "/dev/kvm" in capsys.readouterr().out
        assert "a" in baseline(repo) and baseline(repo)["a"]["r"] != md5(repo / "bld/a.bpf.o")


def test_unknown_name_is_a_usage_error(stack):
    with pytest.raises(SystemExit) as error:
        gate.main(["nonexistent"])
    assert error.value.code == 2


def test_baseline_round_trips_seconds_and_reads_legacy_rows(tmp_path):
    path = tmp_path / "baseline.tsv"
    qemu_gate.save_baseline(path, {"a": dict(r="r", c="c", e="e", verdict="PASS", seconds="17",
                                             summary="Summary: 1/0 PASSED"),
                                   "b": dict(r="r", c="c", e="e", verdict="PASS",
                                             summary="no seconds yet")})
    rows = qemu_gate.parse_baseline(path.read_text())
    assert rows["a"]["seconds"] == "17" and rows["b"]["seconds"] == ""
    assert rows["a"]["summary"] == "Summary: 1/0 PASSED"
    legacy = qemu_gate.parse_baseline("x\tr\tc\te\tFAIL\tSummary: 0/1 PASSED; C-PASS\n")
    assert legacy["x"] == dict(r="r", c="c", e="e", verdict="FAIL", seconds="",
                               summary="Summary: 0/1 PASSED; C-PASS")
    assert qemu_gate.recorded_seconds(rows) == {"a": 17.0}


def test_parallel_queue_runs_unknown_then_longest_first():
    seconds = {"short": 10, "long": 200, "mid": 60}
    assert qemu_gate.longest_first(["short", "new1", "long", "mid", "new2"], seconds) == [
        "new1", "new2", "long", "mid", "short"]


def test_gate_records_seconds_and_orders_the_queue(stack, monkeypatch):
    repo, c_dir, calls, _ = stack
    order = []
    take = qemu_gate.Gate.take

    def recorded_take(self, queue):
        name = take(self, queue)
        if name is not None:
            order.append(name)
        return name

    def fake_prepare(self, name, wenv, slot):
        return dict(name=name, log=repo / gate.LOG_DIR / f"{name}.log", rc=0,
                    upper=Path(wenv["GATE_DIR"]) / f"s{slot}/upper", seconds=3.0)

    monkeypatch.setattr(qemu_gate.Gate, "take", recorded_take)
    monkeypatch.setattr(qemu_gate.Gate, "prepare", fake_prepare)
    for name in ("b", "c"):
        (repo / f"progs/{name}.rs").write_text("rust source")
        (c_dir / f"{name}.bpf.o").write_text("C")
        (c_dir / f"{name}.bpf.o.corig").write_text("C")
        (repo / f"bld/{name}.bpf.o").write_text("Rust")
    env_hash = current_env_hash(repo, c_dir)
    qemu_gate.save_baseline(repo / gate.BASELINE, {
        "a": dict(r="stale", c="stale", e=env_hash, verdict="PASS", seconds="10", summary=""),
        "b": dict(r="stale", c="stale", e=env_hash, verdict="PASS", seconds="40", summary="")})
    assert gate.main(["--workers", "2"]) == 0
    # unknown first, then longest first: the two workers take c and b (in
    # either order), then a
    assert sorted(order[:2]) == ["b", "c"] and order[2:] == ["a"]
    assert {n: row["seconds"] for n, row in baseline(repo).items()} == {"a": "3", "b": "3", "c": "3"}


def overlay_runs(calls):
    """(which, slot) of every gate-overlay.sh call: the worker's slot under
    GATE_PREPARE (a job of the worker's guest), None for a classic boot."""
    return [(argv[-1], Path(argv[1]).name if "GATE_PREPARE" in env else None)
            for argv, env in calls if argv[0] == "scripts/gate-overlay.sh"]


def classic_dirs(calls):
    """The <worker-dir> of every classic gate-overlay.sh run."""
    return [argv[1] for argv, env in calls
            if argv[0] == "scripts/gate-overlay.sh" and "GATE_PREPARE" not in env]


def one_worker(monkeypatch):
    """One overlay worker (two would split the queue): gate.py's minimum is
    2 workers for overlays, so build the worker list by hand."""
    overlay_envs = qemu_gate.overlay_envs
    monkeypatch.setattr(qemu_gate, "overlay_envs", lambda env, root, n: overlay_envs(env, root, 1))


def add_object(repo, c_dir, name):
    (repo / f"progs/{name}.rs").write_text("rust source")
    (c_dir / f"{name}.bpf.o").write_text("C")
    (c_dir / f"{name}.bpf.o.corig").write_text("C")
    (repo / f"bld/{name}.bpf.o").write_text("Rust")


def test_overlay_worker_runs_its_objects_in_one_guest(stack):
    repo, c_dir, calls, controls = stack
    add_object(repo, c_dir, "b")
    assert gate.main(["--workers", "2"]) == 0
    # two workers, two objects: each object is job 0 of its worker's guest
    assert overlay_runs(calls) == [("rust", "s0"), ("rust", "s0")]
    guests = controls["guests"]
    assert len(guests) == 2 and all(g.jobs == [0] for g in guests)
    assert all(g.uppers == [str(g.dir / "s0/upper")] for g in guests)
    assert all((g.dir / "stop").exists() and g.returncode == 0 for g in guests)
    assert {n: row["verdict"] for n, row in baseline(repo).items()} == {"a": "PASS", "b": "PASS"}
    log = (repo / gate.LOG_DIR / "a.log").read_text()
    assert "prepared" in log and "[gate] step 1 took" in log
    assert "[gate] job 0 of guest-w" in log and "Summary:" in log


def test_one_guest_takes_the_whole_queue_in_order(stack, monkeypatch):
    repo, c_dir, calls, controls = stack
    for name in ("b", "c"):
        add_object(repo, c_dir, name)
    # one overlay worker (two would split the queue): gate.py's minimum is
    # 2 workers for overlays, so build the worker list by hand
    overlay_envs = qemu_gate.overlay_envs
    monkeypatch.setattr(qemu_gate, "overlay_envs", lambda env, root, n: overlay_envs(env, root, 1))
    assert gate.main(["--workers", "2"]) == 0
    # the slots alternate; every job names the slot it was prepared in
    assert overlay_runs(calls) == [("rust", "s0"), ("rust", "s1"), ("rust", "s0")]
    guest = controls["guests"][0]
    assert len(controls["guests"]) == 1 and guest.jobs == [0, 1, 2]
    assert guest.uppers == [str(guest.dir / f"{s}/upper") for s in ("s0", "s1", "s0")]


def test_next_object_is_prepared_while_the_guest_runs(stack, monkeypatch):
    repo, c_dir, calls, controls = stack
    add_object(repo, c_dir, "b")
    one_worker(monkeypatch)
    hold = threading.Event()
    controls["hold"] = hold  # job 0 is not answered until set
    prepared_meanwhile = []

    def prepares():
        return sum(1 for _, env in calls if "GATE_PREPARE" in env)

    def release():
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and prepares() < 2:
            time.sleep(0.01)
        prepared_meanwhile.append(prepares())
        hold.set()

    threading.Thread(target=release, daemon=True).start()
    assert gate.main(["--workers", "2"]) == 0
    # b's step 1 ran while a's job was still outstanding
    assert prepared_meanwhile == [2]
    assert controls["guests"][0].jobs == [0, 1]
    assert {n: row["verdict"] for n, row in baseline(repo).items()} == {"a": "PASS", "b": "PASS"}
    assert all(row["seconds"] for row in baseline(repo).values())


def test_fail_keeps_the_prepared_next_object_for_a_fresh_guest(stack, monkeypatch, capsys):
    repo, c_dir, calls, controls = stack
    add_object(repo, c_dir, "b")
    one_worker(monkeypatch)
    controls["job_rc"] = 1  # every job FAILs; the classic reruns PASS
    assert gate.main(["--workers", "2"]) == 0
    runs = overlay_runs(calls)
    # a prepared in s0 and b in s1 (while a's job ran); a's FAIL stopped the
    # first guest and b, already prepared, became job 0 of a fresh one; both
    # classic reruns used <worker>/upper, never a slot
    assert sorted(runs, key=str) == [("rust", "s0"), ("rust", "s1"), ("rust", None), ("rust", None)]
    first, second = controls["guests"]
    assert first.jobs == [0] and second.jobs == [0]
    assert first.uppers == [str(first.dir / "s0/upper")]
    assert second.uppers == [str(second.dir / "s1/upper")]
    assert classic_dirs(calls) == [str(first.dir), str(first.dir)]
    assert all((g.dir / "stop").exists() for g in (first, second))
    assert {n: row["verdict"] for n, row in baseline(repo).items()} == {"a": "PASS", "b": "PASS"}
    assert "ALARM" not in capsys.readouterr().out


def test_job_fail_stops_the_guest_and_reruns_alone(stack, capsys):
    repo, c_dir, calls, controls = stack
    controls["job_rc"] = 1
    assert gate.main([]) == 0
    # job 0 FAILs -> the guest is stopped and the classic boot reruns the
    # Rust object alone, where it PASSes: no alarm, no C run
    assert overlay_runs(calls) == [("rust", "s0"), ("rust", None)]
    guest = controls["guests"][0]
    assert classic_dirs(calls) == [str(guest.dir)]  # <worker>/upper, not a slot
    assert (guest.dir / "stop").exists() and guest.returncode == 0
    assert baseline(repo)["a"]["verdict"] == "PASS"  # the isolated rerun decides
    assert (repo / gate.LOG_DIR / "a.loop.log").exists()
    assert "ALARM" not in capsys.readouterr().out


def test_job_fail_confirmed_alone_runs_the_c_oracle(stack, capsys):
    repo, c_dir, calls, controls = stack
    controls["job_rc"] = 1
    controls["runtime"] = 1
    assert gate.main([]) == 1
    # step 1 itself fails under GATE_JOB (runtime != 0 = build failure):
    # judged as a FAIL without a guest, then the C oracle
    assert overlay_runs(calls) == [("rust", "s0"), ("c", None)]
    assert baseline(repo)["a"]["verdict"] == "FAIL"
    assert "ALARM" in capsys.readouterr().out


def test_dead_guest_reruns_the_object_alone_and_boots_anew(stack):
    repo, c_dir, calls, controls = stack
    add_object(repo, c_dir, "b")
    controls["guest_dies"] = True

    assert gate.main(["--workers", "2"]) == 0
    runs = overlay_runs(calls)
    # every object: its job (the guest dies on it), then the classic boot
    assert sorted(runs, key=str) == [("rust", "s0"), ("rust", "s0"), ("rust", None), ("rust", None)]
    assert all(row["verdict"] == "PASS" for row in baseline(repo).values())


def test_hung_job_times_out_into_the_classic_rerun(stack):
    repo, c_dir, calls, controls = stack
    controls["job_hangs"] = True
    assert gate.main(["--runtime-timeout", "1"]) == 0
    assert overlay_runs(calls) == [("rust", "s0"), ("rust", None)]
    guest = controls["guests"][0]
    assert (guest.dir / "stop").exists()
    assert baseline(repo)["a"]["verdict"] == "PASS"


def test_no_oracle_is_judged_at_step_one_without_a_job(stack):
    repo, c_dir, calls, controls = stack
    controls["no_oracle"] = True
    assert gate.main([]) == 0
    assert overlay_runs(calls) == [("rust", "s0")]
    assert baseline(repo)["a"]["verdict"] == "NO-ORACLE"
    assert controls["guests"][0].jobs == []


@pytest.mark.parametrize("banner, error", [
    ("Linux version fake\n", "without KVM"),
    ("gate-guest-loop: job 0\n", "no kernel banner")])
def test_guest_without_kvm_banner_is_an_error(stack, capsys, banner, error):
    repo, c_dir, calls, controls = stack
    controls["banner"] = banner  # a TCG guest; a console log the loop overwrote
    assert gate.main([]) == 1
    assert error in capsys.readouterr().out
    assert "a" not in baseline(repo)


def test_guest_loop_script_is_part_of_the_environment(stack):
    repo, c_dir, _, _ = stack
    before = current_env_hash(repo, c_dir)
    (repo / "scripts/gate-guest-loop").write_text("# changed\n")
    assert current_env_hash(repo, c_dir) != before
