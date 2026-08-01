# Model benchmark — 2026-08-01

Re-translation of all 10 verified programs from scratch under the identical
automated loop (`scripts/bench.sh <model>`, max 3 attempts, gates = compile +
`make test-<name>` UML test_progs oracle). Runs were serial; the C objects
were restored and re-validated between and after runs.

## Results

| program | Fable 5 (baseline) | opus-5 | opus wall / cost | sonnet-5 | sonnet wall / cost |
|---|---|---|---|---|---|
| fentry_test | interactive¹ | PASS @1 | 150s / $0.90 | PASS @1 | 108s / $0.44 |
| htab_update | PASS @1 | PASS @1 | 203s / $1.12 | PASS @1 | 66s / $0.35 |
| test_core_retro | PASS @1 | PASS @1 | 106s / $0.70 | PASS @1 | 43s / $0.27 |
| test_global_func1 | PASS @1 | PASS @1 | 261s / $1.26 | PASS @1 | 235s / $0.95 |
| test_lookup_and_delete | interactive¹ | PASS @1 | 80s / $0.57 | PASS @1 | 38s / $0.33 |
| test_perf_buffer | PASS @1 | PASS @1 | 71s / $0.50 | PASS @1 | 35s / $0.26 |
| test_pinning | PASS @1 | PASS @1 | 124s / $0.90 | PASS @1 | 47s / $0.39 |
| test_pkt_md_access | interactive¹ | PASS @1 | 113s / $0.77 | PASS @1 | 50s / $0.30 |
| test_ringbuf | PASS @1 | PASS @1 | 188s / $1.11 | PASS @1 | 127s / $0.67 |
| test_skb_ctx | PASS @1 | PASS @1 | 100s / $0.64 | PASS @1 | 129s / $0.57 |
| **total** | 7/7 @1 | **10/10 @1** | 23.3 min / **$8.47** | **10/10 @1** | 14.6 min / **$4.53** |

"@1" = passed on the first attempt, no controller re-prompt. Wall time is the
full loop (agent + independent gate re-run); cost is the agent's
`total_cost_usd` summed over attempts.

¹ Fable 5 baseline: 7 programs ran unattended through the loop (all
first-attempt passes); fentry_test, test_pkt_md_access and
test_lookup_and_delete predate the loop and were translated interactively, so
they have no comparable loop metrics. Fable runs predate TRANSLATE_JSON, so
baseline cost/wall were not captured.

## Caveats

- The bench measures "translate program X given the other 9 verified
  translations as reference idiom" — easier than the conditions under which
  the Fable baseline was set (corpus grew from 3 to 10 references as it ran,
  and Fable's runs debugged harness issues along the way). This is a
  model-capability comparison under today's mature prompt/reference set, not
  a strict apples-to-apples with the baseline column.
- Per-program agent transcripts and raw per-attempt cost JSONs are under
  `bench/<model>/` (`<name>.log`, `agent-<name>-attempt*.json`); the model's
  translations are archived as `bench/<model>/<name>.rs`.
- Restore logs for the opus run exist twice (`.restore.log` from the in-run
  attempt, which failed on a since-fixed env bug in bench.sh, and
  `.restore2.log` from the post-run restore that succeeded).

## Recommendation

Sonnet-5 fully suffices for the current easy/medium tier **with the existing
prompts — no tweaks were needed**: 10/10 unattended first-attempt passes at
~half the opus cost ($4.53 vs $8.47 total) and ~60% of the wall time, with
fewer agent turns on most programs. Opus-5 also went 10/10 @1 but buys
nothing here.

Suggested policy going forward: default the translation loop to
`MODEL=claude-sonnet-5` for new programs of comparable difficulty, and use
the controller's retry ladder for escalation — if sonnet fails its
max-attempts budget, re-run the program with opus-5/Fable rather than
raising max-attempts. Revisit when the corpus reaches genuinely hard
programs (verifier-adversarial loops, heavy CO-RE relocations, bpf2bpf +
tail-call mixes), where first-attempt rates may finally separate the models.
