# Where the gate's time goes

Issue #74 asked why a full gate (every translation after an environment
change) takes about 35 minutes when BPF CI runs the whole of `test_progs`
once, in minutes. This is the measured answer, from the logs the gate
already writes, and the ranked levers it leads to. `scripts/gate_profile.py`
regenerates the tables from `qemu/gate/baseline.tsv` and
`qemu/gate/logs/`; run it after any gate change to see what moved.

## Method

Every baseline row carries `seconds`, the wall time its worker spent on the
object (host-side build, guest, teardown; a C re-check included after a
FAIL). Every object's log is vng's verbose console log, so the kernel's
printk timestamps mark each in-guest milestone: `virtme-ng-init` taking
over as init, `udev is done`, `starting script` (the gate's command), the
first `bpf_testmod: loading` (test_progs has started and initialised) and
`reboot: Power down`. The host-side share is `seconds` minus the guest's
lifetime. Three by-hand runs filled in what the logs cannot split: a bare
boot, a prelude with `/proc/uptime` stamps between its steps, and the
overlay build timed by make target.

## Before: one guest per object (2026-10-19, 883 objects, 2069 s, 8 workers)

The sum of the `seconds` column was 16351 s; over 8 workers that is
2044 s against the 2069 s wall: the run was 98% parallel, and the
serialized stages (restore-all, build, the kernel pin check, the two
`gate-serial` objects) cost under 30 s. The cost is per object, and it is
not the tests:

| phase | median s | sum s | share | what it is |
|---|---|---|---|---|
| host | 2.75 | 2297 | 14% | gate-overlay.sh step 1: skeleton regeneration (0.4 s), test object recompile and `test_progs` relink (1.1 s), swap-and-test.sh's own greps and the namespace setup (1.3 s); QEMU start and teardown (under 1 s) |
| boot | 2.68 | 2301 | 14% | kernel start to `virtme-ng-init` as init (2.3 s solo) |
| init | 6.90 | 5881 | 36% | `virtme-ng-init`: systemd-tmpfiles ~1.6 s, udev coldplug and settle ~5.0 s (4292 s in all); 5.2 s solo, 6.9 s with 8 guests up |
| pre | 3.55 | 2924 | 18% | the gate's prelude and test_progs's start: overlay mount 0.16 s, whiteout replay 0.07 s, the 33 MB `test_progs` copy to tmpfs over 9p 1.2 s solo, bpffs 0.06 s, test_progs to its `bpf_testmod` load 0.07 s |
| tests | 0.52 | 2905 | 18% | `bpf_testmod` load to power-off; 741 objects under 5 s; the 12 longest (test_lwt_ip_encap 180 s, test_tunnel_kern 126 s, test_xdp 122 s, xdp_dummy 72 s, test_tc_link 68 s, ...) are ~1000 s |

851 objects with a guest run; the rest are NO-ORACLE at step 1. A typical
object therefore paid ~15.8 s of boot, init and setup for 0.5 s of tests.
A bare `vng --run bzImage --cpus 4 -- true` takes 7.6-8.4 s wall on this
host (32 CPUs; eight 4-vCPU guests fill it, which is the ~2 s of
contention in the boot and init medians above).

### The CI floor on this host

What BPF CI pays per run, measured here the same day: one 4-vCPU guest,
`test_progs -d @known-bad-tests` over the whole suite.

| run | wall | result |
|---|---|---|
| serial (CI's way) | 777 s | 816/7607 PASSED, 0 FAILED |
| `test_progs -j` (4 workers in the guest) | 299 s | 815/7606 PASSED, 1 FAILED (task_work, a known parallel flake) |

The gate ran 850 oracles in 2069 s wall on eight workers: 2.7x the serial
suite, for one boot against 883. The sum of the gate's test phases
(2905 s) is above the serial suite's 777 s because a swap runs every
test of its consumer file when the per-test set is uncertain
(`scripts/affected_tests.py`) and because eight guests contend for the
host; the per-boot overhead, not the tests, is what the gate adds.

## Levers, ranked by worker-seconds removed

1. **One guest per worker, objects in sequence** (done, below): removes
   boot, init and most of the prelude, ~11000 of 16300 worker-seconds;
   keeps the tests and the host-side build. The guest runs
   `scripts/gate-guest-loop`; the host posts `jobs/<n>` after step 1
   (`gate-overlay.sh` under `GATE_JOB`) and reads `rc`. Verdicts stay
   per object and anything but a PASS (a FAIL, a guest that died, a
   timeout) is rerun the classic way, alone in a fresh guest, then the C
   oracle as before; the guest is stopped after a FAIL so nothing a
   failing test left behind reaches the next object. The `test_progs`
   copy to tmpfs is made only for the consumers that resolve their own
   executable's path (bpf_iter, d_path, the uprobe family, ...).
2. **Trim virtme-ng-init** (udev coldplug and settle, tmpfiles): 5881 s
   when every object boots; after lever 1 it is ~7 s per guest, eight
   guests per gate. Not worth a custom init now.
3. **Host side** (2297 s): the `test_progs` relink dominates what make
   does; swap-and-test.sh's discovery greps are as much again. After
   lever 1 it is the per-object floor; it could overlap with the guest's
   previous job (two uppers per worker), or the greps could be cached.
4. **Tests** (2905 s): a dozen network objects are a third of it, and CI
   pays them too. Nothing to do.
5. **Union-filter batching** (#67): the same saving as lever 1 with a
   merged test list and attribution by test name; superseded by 1, which
   keeps one test_progs run per object.

## After: one guest per worker

Same day, same 883 objects, same host, `scripts/gate.py --workers 8 --all`
after the change: **730 s wall** (871 objects in that run; the 12 objects
of the trial run, gated 48 s earlier under the same environment, were
cached), against 2069 s before. Every verdict and every test summary
in `qemu/gate/baseline.tsv` is identical to the previous baseline's:
850 PASS, 33 NO-ORACLE. Eight guests booted, one per worker; no object
needed the classic rerun. Worker-seconds fell from 16351 to 5809:

| phase | median s | sum s | share | what it is now |
|---|---|---|---|---|
| host | 2.17 | 2051 | 36% | the overlay build as before (the first object of each worker also carries its guest's boot wait, ~12 s, here) |
| boot + init | 0 | 81 in all | 1% | eight boots, 2.9 s + 7.3 s each |
| pre | 0.34 | 559 | 10% | overlay mount and whiteout replay; the test_progs copy only for the path-sensitive consumers |
| tests | 0.82 | 3147 | 55% | test_progs start to exit (its own start, ~0.3 s, is in here now) |

The wall time is close to the serial CI floor (777 s): what the gate
still adds over one `test_progs` run, it adds in parallel. The next
levers, in order: the host-side build (2051 s; overlap it with the
guest's previous job, or cache swap-and-test.sh's consumer discovery),
then the tail (the dozen network objects, 1000 s of tests, bound the
wall time at 8 workers: ~190 s for test_lwt_ip_encap alone).
