"""A stand-in for a gate worker's guest (scripts/qemu-test-progs under
GATE_LOOP + scripts/gate-guest-loop), for the drivers' tests: answers every
job the host posts under <worker>/jobs/<n> with controls["job_rc"] and a
test summary, hangs on controls["job_hangs"], dies on
controls["guest_dies"]. A Popen look-alike for qemu_gate.Guest."""
from pathlib import Path
import subprocess
import threading
import time


class FakeGuest:
    def __init__(self, env, controls):
        self.dir = Path(env["GATE_LOOP"])
        self.env = env
        self.controls = controls
        self.jobs = []
        self.returncode = None
        self.pid = 0
        self.answer = threading.Thread(target=self.serve, daemon=True)
        self.answer.start()

    def serve(self):
        n = 0
        while not (self.dir / "stop").exists() and self.returncode is None:
            job = self.dir / "jobs" / str(n)
            if (job / "ready").exists():
                self.jobs.append(n)
                if self.controls.get("guest_dies"):
                    self.returncode = 137
                    return
                if not self.controls.get("job_hangs"):
                    (job / "log").write_text("Summary: 1/0 PASSED, 0 SKIPPED, 0/0 FAILED\n")
                    (job / "rc.tmp").write_text(str(self.controls.get("job_rc", 0)))
                    (job / "rc.tmp").rename(job / "rc")
                n += 1
            time.sleep(0.01)
        self.returncode = self.returncode or 0

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.answer.join(timeout)
        if self.answer.is_alive():
            raise subprocess.TimeoutExpired("guest", timeout)
        return self.returncode


def fake_spawn(controls, guests):
    """A qemu_gate.spawn substitute: boots a FakeGuest per call, records it
    in `guests`, writes a KVM boot banner to the guest log."""
    def spawn(argv, log, env, cwd=None):
        assert [str(a) for a in argv] == ["scripts/qemu-test-progs"]
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("Linux version fake\nHypervisor detected: KVM\n")
        guest = FakeGuest(env, controls)
        guests.append(guest)
        return guest
    return spawn


def post_job(env, log):
    """What gate-overlay.sh step 1 does under GATE_JOB: post the job dir."""
    job = Path(env["GATE_DIR"]) / "jobs" / env["GATE_JOB"]
    job.mkdir(parents=True)
    (job / "ready").touch()
    log.write_text(f"[gate-overlay] job {env['GATE_JOB']} posted\n")
