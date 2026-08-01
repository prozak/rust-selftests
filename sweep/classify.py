#!/usr/bin/env python3
"""Classify kernel BPF selftest programs for the stratified sweep sample."""
import os, re, sys, glob, json

KSRC = os.path.expanduser("~/sources/heimdall_experiment/uml-harness/.build/bpf-next")
PROGS = os.path.join(KSRC, "tools/testing/selftests/bpf/progs")
PROG_TESTS = os.path.join(KSRC, "tools/testing/selftests/bpf/prog_tests")
DONE = {"fentry_test","htab_update","test_core_retro","test_global_func1",
        "test_lookup_and_delete","test_perf_buffer","test_pinning",
        "test_pkt_md_access","test_ringbuf","test_skb_ctx","stacktrace_map"}

# concat all prog_tests sources once for consumer detection
tests_blob = ""
for f in glob.glob(os.path.join(PROG_TESTS, "*.c")):
    tests_blob += open(f, errors="ignore").read()

SEC_RE = re.compile(r'SEC\(\s*"([^"]+)"')

rows = []
for path in sorted(glob.glob(os.path.join(PROGS, "*.c"))):
    name = os.path.basename(path)[:-2]
    if name in DONE:
        continue
    src = open(path, errors="ignore").read()
    loc = src.count("\n")
    secs = sorted(set(SEC_RE.findall(src)))
    sec_kinds = sorted(set(s.split("/")[0].rstrip("?").lstrip("?") for s in secs))
    feats = []
    if re.search(r'__failure\b|__msg\b', src): feats.append("negtest")
    if re.search(r'bpf_get_stackid|bpf_get_stack\b', src): feats.append("stacktrace")
    if re.search(r'\.maps', src) or "__uint(type," in src: feats.append("maps")
    if re.search(r'BPF_CORE_READ|__builtin_preserve|bpf_core_', src): feats.append("core")
    if "vmlinux.h" in src: feats.append("vmlinux")
    if re.search(r'__sync_|__atomic_', src): feats.append("atomics")
    if "__noinline" in src or "noinline" in src: feats.append("bpf2bpf")
    if "__ksym" in src: feats.append("kfunc")
    if "bpf_tail_call" in src: feats.append("tailcall")
    if "bpf_loop" in src or "bpf_for" in src or "can_loop" in src: feats.append("iters")
    if re.search(r'\bbpf_spin_lock\b', src): feats.append("spinlock")
    if "bpf_timer" in src: feats.append("timer")
    if "bpf_arena" in src or "arena" in secs.__str__(): feats.append("arena")
    if "bpf_rdonly_cast" in src or "bpf_cast_to_kern_ctx" in src: feats.append("cast_kfunc")
    # consumer detection: skeleton include or object/name reference
    consumed = (f"{name}.skel.h" in tests_blob or f"{name}.bpf.o" in tests_blob
                or f'"{name}"' in tests_blob)
    rows.append(dict(name=name, loc=loc, secs=sec_kinds, feats=feats,
                     consumed=consumed))

print(json.dumps(rows))
print(f"total candidates: {len(rows)}", file=sys.stderr)
excl_neg = sum(1 for r in rows if "negtest" in r["feats"])
excl_st = sum(1 for r in rows if "stacktrace" in r["feats"])
excl_nc = sum(1 for r in rows if not r["consumed"])
elig = [r for r in rows if "negtest" not in r["feats"]
        and "stacktrace" not in r["feats"] and r["consumed"]]
print(f"excluded: negtest={excl_neg} stacktrace={excl_st} no-consumer={excl_nc}",
      file=sys.stderr)
print(f"eligible: {len(elig)}", file=sys.stderr)
