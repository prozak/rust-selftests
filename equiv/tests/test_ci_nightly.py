"""Nightly orchestration must preserve C oracles and expose failed/incomplete runs."""
import importlib.util
import json
from pathlib import Path
import signal
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import ci_nightly as nightly


@pytest.fixture
def stack(tmp_path, monkeypatch):
    repo = tmp_path / "repo with spaces"
    c_dir = tmp_path / "selftests"
    kernel = tmp_path / "kernel"
    for p in [repo / "progs", repo / "bld", repo / "scripts", c_dir, kernel]:
        p.mkdir(parents=True)
    (repo / "progs/a.rs").write_text("rust source")
    (repo / "kernel-commit").write_text("pin\n")
    (repo / "scripts/known-bad-tests").write_text("# existing exclusions\n")
    (c_dir / "a.bpf.o").write_text("contaminated Rust")
    (c_dir / "a.bpf.o.corig").write_text("C")
    (repo / "bld/a.bpf.o").write_text("old Rust")
    baseline = b"# baseline\na\tc\tr\tt\tEQUIV\told\n"
    tracked = repo / "baseline.tsv"
    tracked.write_bytes(baseline)
    monkeypatch.setattr(nightly, "REPO", repo)
    monkeypatch.setattr(nightly, "C_DIR", c_dir)
    monkeypatch.setattr(nightly, "KERNEL", kernel)
    monkeypatch.setattr(nightly.guard, "tool_hash", lambda: "tool")
    monkeypatch.setattr(nightly, "git", lambda *args:
                        baseline if "HEAD:equiv/results/baseline.tsv" in args else
                        b"| a | PASS | 1s | Summary: 1/0 PASSED |\n" if "HEAD:qemu/gate/results.md" in args else b"head\n")
    for key in ["FLAVOR", "KERNEL_SRC", "SELFTESTS_SRC", "SELFTESTS_OUTPUT", "VMLINUX_BTF", "QEMU_KERNEL", "TEST_RUNNER"]:
        monkeypatch.delenv(key, raising=False)
    calls = []
    controls = dict(proof="EQUIV", runtime=0, restore=0, interrupt=False, build=0)

    def fake_run(argv, log, env, timeout=None):
        argv = [str(a) for a in argv]
        calls.append(argv)
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("")
        if "restore-all" in argv:
            (c_dir / "a.bpf.o").write_bytes((c_dir / "a.bpf.o.corig").read_bytes())
        elif "all" in argv:
            assert (c_dir / "a.bpf.o").read_text() == "C"
            assert "-B" in argv
            (repo / "bld/a.bpf.o").write_text("fresh Rust")
            return controls["build"]
        elif "equiv/check.py" in argv:
            assert (c_dir / "a.bpf.o").read_text() == "C"
            assert (repo / "bld/a.bpf.o").read_text() == "fresh Rust"
            log.write_text(f"  {controls['proof']} a\na: 1/1 program(s) proved\n")
            if controls["proof"] == "TIMEOUT" or controls.get("timeout"):
                return 124
            return 0 if controls["proof"] == "EQUIV" else 1
        elif "scripts/swap-and-test.sh" in argv:
            if argv[-1] == "rust":
                (c_dir / "a.bpf.o").write_text("fresh Rust")
                if controls["interrupt"]:
                    raise KeyboardInterrupt
                if controls.get("no_oracle"):
                    log.write_text("no prog_tests consume a\n")
                    return 1
                log.write_text("Summary: 1/0 PASSED, 0 SKIPPED, 0/0 FAILED\n")
                return controls["runtime"]
            (c_dir / "a.bpf.o").write_text("C")
            if controls.get("no_oracle"):
                log.write_text("no prog_tests consume a\n")
                return 1
            if not env.get("SWAP_ONLY"):
                log.write_text("Summary: 1/0 PASSED, 0 SKIPPED, 0/0 FAILED\n")
            return controls["restore"]
        elif "codegen/compare.py" in argv:
            assert (c_dir / "a.bpf.o").read_text() == "C"
            current = Path(argv[argv.index("--baseline") + 1]).read_text()
            assert f"\t{controls['proof']}\t" in current
            assert tracked.read_bytes() == baseline
        return 0

    monkeypatch.setattr(nightly, "run", fake_run)
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    yield repo, c_dir, calls, controls
    for sig, handler in handlers.items():
        signal.signal(sig, handler)


def execute(stack):
    repo, c_dir, calls, controls = stack
    out = repo / "report"
    rc = nightly.main(["--out", str(out)])
    report = json.loads((out / "summary.json").read_text())
    assert (c_dir / "a.bpf.o").read_text() == "C"
    assert calls[0][-1] == calls[-1][-1] == "restore-all"
    return rc, report


def test_fresh_sweep_and_codegen_use_run_baseline(stack):
    rc, report = execute(stack)
    assert rc == 0 and report["status"] == "PASS"
    assert report["proof"]["a"]["verdict"] == "EQUIV"
    assert report["runtime"]["a"]["verdict"] == "PASS"
    assert report["runtime"]["a"]["c_verdict"] == "NOT-RUN"
    assert not report["proof_changes"]


def test_shared_output_lock_blocks_another_checkout(stack):
    import fcntl

    with (stack[1] / ".ci-nightly.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(SystemExit) as error:
            nightly.main(["--out", str(stack[0] / "blocked")])
        assert error.value.code == 2
    assert stack[2] == []


def test_alternate_boot_kernel_is_rejected_before_mutation(stack, monkeypatch):
    monkeypatch.setenv("QEMU_KERNEL", "/some/other/bzImage")
    with pytest.raises(SystemExit) as error:
        nightly.main(["--out", str(stack[0] / "blocked")])
    assert error.value.code == 2
    assert stack[2] == []


def test_boot_image_is_pinned_and_recorded(stack, monkeypatch):
    image = nightly.KERNEL / "arch/x86/boot/bzImage"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"pinned image")
    original_run = nightly.run

    def check_run(argv, log, env, timeout=None):
        assert env["QEMU_KERNEL"] == str(image)
        return original_run(argv, log, env, timeout)

    monkeypatch.setattr(nightly, "run", check_run)
    assert execute(stack)[0] == 0
    hashes = json.loads((stack[0] / "report/kernel-hashes.json").read_text())
    assert hashes[str(image)] == nightly.guard.md5(image)


@pytest.mark.parametrize("verdict", ["BAIL", "TIMEOUT", "UNKNOWN", "INEQUIV", "ERROR"])
def test_failed_proof_does_not_prevent_runtime_or_codegen(stack, verdict):
    stack[3]["proof"] = verdict
    rc, report = execute(stack)
    assert rc == 1 and report["status"] == "FAIL"
    assert report["proof_changes"][0]["regression"]
    assert report["runtime"]["a"]["verdict"] == "PASS"
    assert any("codegen/compare.py" in cmd for cmd in stack[2])


def test_runtime_failure_checks_c_and_returns_failure(stack):
    stack[3]["runtime"] = 1
    rc, report = execute(stack)
    assert rc == 1 and report["status"] == "FAIL"
    assert report["runtime"]["a"]["c_verdict"] == "PASS"
    assert report["runtime_changes"] == [dict(name="a", before="PASS", after="FAIL")]


def test_timeout_does_not_hide_an_already_reported_divergence(stack):
    stack[3].update(proof="INEQUIV", timeout=True)
    rc, report = execute(stack)
    assert rc == 1 and report["proof"]["a"]["verdict"] == "INEQUIV"
    assert report["proof"]["a"]["exit"] == 124


def test_losing_a_previously_passing_runtime_oracle_fails(stack):
    stack[3]["no_oracle"] = True
    rc, report = execute(stack)
    assert rc == 1 and report["status"] == "FAIL"
    assert report["runtime"]["a"]["verdict"] == "NO-ORACLE"


def test_matching_c_failure_is_not_waived_and_allows_codegen(stack):
    stack[3].update(runtime=1, restore=1)
    rc, report = execute(stack)
    assert rc == 1 and report["status"] == "FAIL"
    assert report["runtime"]["a"]["c_verdict"] == "FAIL"
    assert any("codegen/compare.py" in cmd for cmd in stack[2])


@pytest.mark.parametrize("failure", ["restore", "build"])
def test_infrastructure_failure_stops_dependent_work(stack, failure):
    stack[3][failure] = 1
    rc, report = execute(stack)
    assert rc == 1 and report["status"] == "ERROR"
    assert not any("codegen/compare.py" in cmd for cmd in stack[2])


def test_interruption_restores_active_object_and_reports_incomplete(stack):
    stack[3]["interrupt"] = True
    rc, report = execute(stack)
    assert rc == 1 and report["status"] == "INTERRUPTED"
    assert any(stage["name"] == "restore-active" for stage in report["stages"])


@pytest.mark.parametrize("mode", ["exception", "exit", "second_signal"])
def test_recovery_always_attempts_final_restore(stack, monkeypatch, mode):
    import os

    stack[3]["interrupt"] = True
    original_run = nightly.run
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

    def failing_recovery(argv, log, env, timeout=None):
        if log.name == "restore-active.log":
            if mode == "exception":
                raise OSError("cannot launch derived restore")
            if mode == "exit":
                return 1
            os.kill(os.getpid(), signal.SIGTERM)
        return original_run(argv, log, env, timeout)

    monkeypatch.setattr(nightly, "run", failing_recovery)
    rc, report = execute(stack)
    assert rc == 1
    assert report["status"] == ("INTERRUPTED" if mode == "second_signal" else "ERROR")
    assert report["stages"][-1]["name"] == "restore-final"
    if mode != "second_signal":
        assert "restore-active" in report["error"]
    assert all(signal.getsignal(sig) == handler for sig, handler in handlers.items())


def test_final_restore_exception_cannot_leave_pass_report(stack, monkeypatch):
    original_run = nightly.run

    def failing_final(argv, log, env, timeout=None):
        if log.name == "restore-final.log":
            raise OSError("cannot launch final restore")
        return original_run(argv, log, env, timeout)

    monkeypatch.setattr(nightly, "run", failing_final)
    rc = nightly.main(["--out", str(stack[0] / "report")])
    report = json.loads((stack[0] / "report/summary.json").read_text())
    assert rc == 1 and report["status"] == "ERROR"
    assert "cannot launch final restore" in report["error"]


def test_runtime_requires_a_summary_and_distinguishes_no_oracle():
    assert nightly.runtime_result("a", 0, "no tests ran")[0] == "FAIL"
    assert nightly.runtime_result("a", 1, "no prog_tests consume a")[0] == "NO-ORACLE"
    assert nightly.runtime_result("a", 124, "no prog_tests consume a")[0] == "FAIL"
    assert nightly.proof_diff({"a": {"verdict": "EQUIV"}}, {})[0]["regression"]


def test_prover_crash_is_not_noprogs():
    assert nightly.guard.classify("a: 0/0 program(s) proved\nTraceback: crash", 1)[0] == "ERROR"


def test_partial_checker_output_is_an_error_even_after_a_bail():
    assert nightly.guard.classify("  BAIL a\nTraceback (most recent call last):\ncrash", 1)[0] == "ERROR"
    assert nightly.guard.classify("  EQUIV a\n", 0)[0] == "ERROR"


def test_codegen_can_select_fresh_baseline(tmp_path):
    spec = importlib.util.spec_from_file_location("codegen_compare", ROOT / "codegen/compare.py")
    compare = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compare)
    baseline = tmp_path / "baseline.tsv"
    baseline.write_text("a\tc\tr\tt\tBAIL\t\nb\tc\tr\tt\tEQUIV\t\n")
    assert compare.proved_objects(baseline) == {"b"}


def test_timeout_kills_descendants(tmp_path):
    import os
    import time

    marker = tmp_path / "descendant survived"
    descendant = "import time; from pathlib import Path; time.sleep(0.8); Path(%r).touch()" % str(marker)
    parent = "import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', %r]); time.sleep(10)" % descendant
    rc = nightly.run([sys.executable, "-c", parent], tmp_path / "timeout.log", os.environ.copy(), 0.2)
    assert rc == 124
    time.sleep(0.8)
    assert not marker.exists()
    assert not nightly.CHILDREN
