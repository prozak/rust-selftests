"""The incremental QEMU gate re-runs exactly what changed and keeps the C tree pristine."""
import fcntl
import hashlib
import json
from pathlib import Path
import signal
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import gate  # noqa: E402
import qemu_gate  # noqa: E402

ENV_FILES = ["scripts/swap-and-test.sh", "scripts/qemu-test-progs", "scripts/gate-overlay.sh",
             "scripts/gate-record-filter", "scripts/known-bad-tests"]


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
               e=current_env_hash(repo, c_dir), verdict=verdict, summary=summary)
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
               e=current_env_hash(repo, c_dir), verdict="PASS", summary="Summary: 1/0 PASSED")
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
