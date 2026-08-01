#!/usr/bin/env python3
"""Stratified sample: bucket by primary SEC kind, spread across feature
combos and size within buckets. Deterministic (sorted + stride), no RNG."""
import json, sys, collections

rows = json.load(open("classified.json"))
elig = [r for r in rows if "negtest" not in r["feats"]
        and "stacktrace" not in r["feats"] and r["consumed"]]

TARGET = 60
by_kind = collections.defaultdict(list)
for r in elig:
    kind = r["secs"][0] if r["secs"] else "(none)"
    by_kind[kind].append(r)

# proportional allocation, min 1 per kind, capped
kinds = sorted(by_kind, key=lambda k: -len(by_kind[k]))
alloc = {}
remaining = TARGET
for k in kinds:
    alloc[k] = 1
    remaining -= 1
total = sum(len(v) for v in by_kind.values())
for k in kinds:
    extra = round(remaining * len(by_kind[k]) / total)
    alloc[k] += extra
# trim/expand to exactly TARGET
while sum(alloc.values()) > TARGET:
    k = max(alloc, key=lambda k: alloc[k])
    alloc[k] -= 1
while sum(alloc.values()) < TARGET:
    k = max(kinds, key=lambda k: len(by_kind[k]) - alloc[k])
    alloc[k] += 1

sample = []
for k in kinds:
    pool = by_kind[k]
    n = min(alloc[k], len(pool))
    # sort by (feature signature, loc) then stride-sample for spread
    pool = sorted(pool, key=lambda r: (",".join(sorted(r["feats"])), r["loc"]))
    if n >= len(pool):
        chosen = pool
    else:
        stride = len(pool) / n
        chosen = [pool[int(i * stride)] for i in range(n)]
    sample.extend(chosen)

sample.sort(key=lambda r: r["loc"])
for r in sample:
    print(f"{r['name']}\t{r['loc']}\t{'+'.join(r['secs'])}\t{','.join(r['feats']) or '-'}")
print(f"sample: {len(sample)} programs, kinds: {len(kinds)}", file=sys.stderr)
print(f"loc: min={sample[0]['loc']} median={sample[len(sample)//2]['loc']} "
      f"max={sample[-1]['loc']}", file=sys.stderr)
