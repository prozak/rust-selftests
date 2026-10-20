#!/usr/bin/env python3
"""Where a gate run's time goes, from the logs it already writes.

For every baseline row with a Rust log under qemu/gate/logs, split the
object's recorded wall time (the `seconds` column of baseline.tsv: the
worker's time on the object, host side included) into phases from the
kernel printk timestamps vng's verbose log carries:

  host     seconds minus the guest's lifetime (the overlay build: skeleton
           regeneration and the test_progs relink; QEMU start and teardown;
           for a job, the polls and the gate's bookkeeping)
  boot     kernel start to virtme-ng-init running as init
  init     virtme-ng-init: systemd-tmpfiles, udev coldplug and settle
  pre      the gate's prelude (overlay mount, test_progs copy) and
           test_progs's own start, up to its first bpf_testmod load
  tests    from that load to the guest's power-off

A log without a boot (a job run in a guest that was booted once for several
objects: scripts/gate-guest-loop) carries the loop's own uptime stamps
instead, `job N start|run|done`: boot/init are 0, pre is start to run (the
overlay mount and the test_progs copy), tests is run to done (test_progs,
its start included), and the guest's lifetime is the job's own; the boots
are counted once per guest, from the workers' guest-*.log files, in a
separate line. Such a log also carries `[gate] step 1 took N s`, the
overlay build alone, reported as `build` (a part of host). A worker
builds the next object while its guest runs the current one, so the sum
of the baseline seconds (step 1 + the rest, per object) exceeds the
workers' wall time by the overlapped part.

Usage: scripts/gate_profile.py [--logs DIR] [--baseline FILE] [--tsv] [--top N]
"""
import argparse
import collections
from pathlib import Path
import re
import statistics
import sys

REPO = Path(__file__).resolve().parents[1]
TS = re.compile(r"^\[ *([0-9.]+)\]")
STAMP = re.compile(r"^\[gate-guest-loop\] job \d+ (start|run|done) ([0-9.]+)")
STEP1 = re.compile(r"^\[gate\] step 1 took ([0-9.]+) s")
PHASES = ("host", "boot", "init", "pre", "tests")
COLUMNS = PHASES + ("build",)
MARKS = (("init", "as init process"), ("basic", "basic initialization done"),
         ("udev", "udev is done"), ("script", "starting script"),
         ("testmod", "bpf_testmod: loading"), ("end", "reboot: Power down"))


def milestones(text):
    """Kernel-clock seconds of each marker line, first occurrence; `last` is
    the last timestamp seen, `first` the first (the guest's log starts at
    0.000000 only with a boot)."""
    m = {}
    for line in text.splitlines():
        st = STAMP.match(line)
        if st:
            m.setdefault("job_" + st.group(1), float(st.group(2)))
            continue
        s1 = STEP1.match(line)
        if s1:
            m["step1"] = float(s1.group(1))  # the last attempt's build
            continue
        t = TS.match(line)
        if not t:
            continue
        v = float(t.group(1))
        m.setdefault("first", v)
        m["last"] = v
        for key, mark in MARKS:
            if mark in line and key not in m:
                m[key] = v
    return m


def phases(seconds, m):
    """Phase lengths for one object's log; None without a guest run."""
    if "job_done" in m and "job_start" in m:
        run = m.get("job_run", m["job_done"])
        d = dict(boot=0.0, init=0.0, pre=run - m["job_start"], tests=m["job_done"] - run,
                 guest=m["job_done"] - m["job_start"], build=m.get("step1"))
        d["host"] = (seconds - d["guest"]) if seconds is not None else None
        return d
    if "end" not in m and "last" not in m:
        return None
    end = m.get("end", m["last"])
    booted = "init" in m
    start_script = m.get("script", m.get("first", 0.0))
    first_test = m.get("testmod", start_script)
    d = dict(boot=m["init"] - m["first"] if booted else 0.0,
             init=(m.get("udev", m.get("script", m["init"])) - m["init"]) if booted else 0.0,
             pre=first_test - start_script,
             tests=end - first_test,
             guest=end - m["first"], build=m.get("step1"))
    d["host"] = (seconds - d["guest"]) if seconds is not None else None
    return d


def read_baseline(path):
    rows = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        f = line.split("\t")
        if len(f) < 6:
            continue
        rows[f[0]] = (f[4], int(f[5]) if f[5] else None)
    return rows


def profile(log_dir, baseline):
    per = {}
    for name, (verdict, seconds) in baseline.items():
        log = log_dir / f"{name}.log"
        if not log.is_file():
            continue
        d = phases(seconds, milestones(log.read_text(errors="replace")))
        if d:
            per[name] = (verdict, seconds, d)
    guests = {}
    for log in sorted(log_dir.glob("guest-*.log")):
        m = milestones(log.read_text(errors="replace"))
        if "init" in m:
            guests[log.stem] = dict(boot=m["init"] - m["first"],
                                    init=m.get("script", m["init"]) - m["init"])
    return per, guests


def fmt_table(per, guests, top):
    out = []
    n = len(per)
    out.append(f"{n} objects with a guest run; worker-seconds per phase "
               f"(the wall time is about the sum over the number of workers):\n")
    out.append("| phase | median s | mean s | max s | sum s | share |")
    out.append("|---|---|---|---|---|---|")
    total = sum(sec for _, sec, _ in per.values() if sec is not None)
    for key in PHASES:
        xs = [d[key] for _, _, d in per.values() if d[key] is not None]
        if not xs:
            continue
        s = sum(xs)
        out.append(f"| {key} | {statistics.median(xs):.2f} | {statistics.mean(xs):.2f} | "
                   f"{max(xs):.1f} | {s:.0f} | {100 * s / total:.0f}% |")
    out.append(f"| total (baseline seconds) | | | | {total:.0f} | 100% |")
    builds = [d["build"] for _, _, d in per.values() if d.get("build") is not None]
    if builds:
        out.append(f"\nOf host, the overlay build alone (gate-overlay.sh step 1) over "
                   f"{len(builds)} objects: median {statistics.median(builds):.2f} s, "
                   f"sum {sum(builds):.0f} s. A worker builds the next object while its "
                   f"guest runs the current one, so the baseline seconds add up to more "
                   f"than the workers' wall time.")
    if guests:
        boots = sum(g["boot"] + g["init"] for g in guests.values())
        out.append(f"\n{len(guests)} guest boot(s) outside the objects' logs: "
                   f"{boots:.0f} s of boot + init in all "
                   f"(median boot {statistics.median(g['boot'] for g in guests.values()):.2f} s, "
                   f"init {statistics.median(g['init'] for g in guests.values()):.2f} s).")
    out.append(f"\nLongest {top} objects by test time:\n")
    out.append("| object | seconds | tests s | pre s | host s |")
    out.append("|---|---|---|---|---|")
    for name, (_, sec, d) in sorted(per.items(), key=lambda kv: -kv[1][2]["tests"])[:top]:
        host = "" if d["host"] is None else f"{d['host']:.1f}"
        out.append(f"| {name} | {sec} | {d['tests']:.1f} | {d['pre']:.1f} | {host} |")
    hist = collections.Counter(min(int(d["tests"]) // 5 * 5, 60) for _, _, d in per.values())
    out.append("\nTest time histogram (seconds, 5 s buckets, 60+ last):\n")
    out.append("| bucket | objects |")
    out.append("|---|---|")
    for k in sorted(hist):
        out.append(f"| {k}-{k + 4} | {hist[k]} |")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--logs", type=Path, default=REPO / "qemu/gate/logs")
    ap.add_argument("--baseline", type=Path, default=REPO / "qemu/gate/baseline.tsv")
    ap.add_argument("--tsv", action="store_true", help="per-object rows instead of the table")
    ap.add_argument("--top", type=int, default=12)
    args = ap.parse_args(argv)
    per, guests = profile(args.logs, read_baseline(args.baseline))
    if not per:
        print("no gate logs with a guest run", file=sys.stderr)
        return 1
    if args.tsv:
        print("name\tverdict\tseconds\t" + "\t".join(COLUMNS))
        for name, (verdict, sec, d) in sorted(per.items()):
            cells = ["" if d.get(k) is None else f"{d[k]:.2f}" for k in COLUMNS]
            print(f"{name}\t{verdict}\t{sec}\t" + "\t".join(cells))
        return 0
    print(fmt_table(per, guests, args.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
