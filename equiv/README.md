# Z3 semantic equivalence checker (Heimdall stages 4–5 analog)

Proves, per BPF program, that the Rust translation's object code is
observationally equivalent to the kernel's C-compiled object: for every input
(symbolic context, symbolic kernel memory, symbolic initial globals), both
produce the same return value and the same final contents of every named
global and of the context.

## Usage

```sh
# one program (venv: ../../z3-venv)
../z3-venv/bin/python equiv/check.py fentry_test

# whole corpus, 10-way parallel
equiv/sweep.sh <names-file> <out-dir> 10
```

`check.py` exits 0 iff every paired program is proved EQUIV (or EQUIV32).

## Files

- `bpfelf.py` — standalone ELF64-LE reader: sections, symbols, RELs, and
  `.BTF.ext` CO-RE relocation coverage (per-section).
- `bpfcore.py` — CO-RE relocation engine: full-fidelity BTF parser
  (bitfields, enums, split/distilled-base module BTF) plus libbpf's
  candidate-search / spec-match / patch algorithm (relo_core.c) applied
  against the target kernel's BTF before lifting.
- `bpfsym.py` — BPF ISA → Z3 lifter with path-enumerating symbolic execution.
  Anything unmodeled raises `Bail` (never guesses).
- `check.py` — pairs programs by (section, func) across the two objects,
  builds ITE path summaries, asks Z3 for a distinguishing input.
- `sweep.sh` — parallel driver + verdict histogram.

## Model

- Registers hold 64-bit bitvectors or `Ptr(region, offset)` values.
- Regions: shared symbolic `ctx`; shared symbolic `kmem` (backs probe-reads
  through scalar pointers, read-only); one shared symbolic array per named
  writable global (`g:<sym>` — the observables); per-object concrete-initialized
  read-only sections; per-run 512-byte stack; opaque `map:<name>` pointers.
- Paths are enumerated with Z3 feasibility pruning; per-path summaries are
  ITE-folded, so the final query covers all executions at once.
- Void-return programs (r0 never assigned — verifier-enforced BTF void) skip
  the return-value comparison.
- `EQUIV32`: return values agree in the low 32 bits only; benign when the BTF
  return type is ≤32 bits (not yet checked automatically).
- CO-RE relocations are APPLIED before lifting (no more `CORESKIP`): both
  objects are relocated against the same target BTF — the qemu-flavor
  kernel's vmlinux (`bld/vmlinux.btf`, extracted from
  `uml-harness/.build/bpf-next-x86/vmlinux`) plus the split BTFs of the
  selftest modules (`*.ko`, distilled-base aware) — exactly as libbpf would
  at load time. All 13 relocation kinds are implemented per relo_core.c:
  field byte offset/size/exists/signed and the bitfield lshift/rshift pair,
  type id/exists/size/matches, enumval exists/value. libbpf's failure
  semantics are preserved: an unresolvable field/enumval-value relocation
  poisons that instruction (`call 0xbad2310`), and the executor BAILs only
  if a poisoned instruction is actually reachable — EXISTS-guarded dead
  branches (kernel-version flavors like `kernfs_node___52`) stay provable.
  `TYPE_ID_LOCAL` values are patched faithfully but marked
  poison-for-equivalence: they are each object's own BTF id, incomparable
  across objects by construction. `--kernel-btf none` restores the old
  CORESKIP behavior.
- The implementation is validated instruction-for-instruction against
  libbpf itself: a `bpf_object__prepare()` harness runs in the qemu guest
  (same kernel, modules insmoded) and dumps every program's relocated
  stream; across 550 objects (2975 programs, 296 relo-carrying objects)
  our patched sections are byte-identical to libbpf's on every instruction
  that doesn't carry an ELF relocation (map fds / subprog offsets / kfunc
  ids, which the lifter resolves symbolically instead).

Helper calls (tier 1):

- probe_read/_kernel/_user: byte copy from the shared `kmem` (or source
  region) — deterministic, no oracle; concrete size ≤ 512 required.
- probe_read_*_str: NUL position abstracted as a shared per-call-index oracle
  length clamped to [1, size]; bytes past it keep prior contents.
- Argument-free environment reads (ktime, pid_tgid, smp_processor_id, ...):
  shared oracle streams at the helper's true return width; pid_tgid is
  additionally masked to kernel-possible values (both halves < 2^31), since
  C sign-extends `int` pid compares where Rust compares 32-bit.

Helper calls (tier 2) — observable call trace:

- Side-effecting helpers (map_update/delete/push/pop/peek,
  perf_event_output, ringbuf_output, get_stackid, trace_printk) append an
  event `[helper id][len][payload]` to a shared `trace` region that is
  compared like any other observable: equivalence requires the same call
  sequence with the same arguments. Key/value pointer args are compared by
  pointed-to bytes, sizes taken from each object's own `.maps` BTF def (so a
  key/value-size mismatch between C and Rust surfaces as INEQUIV). The
  concrete trace cursor makes encodings prefix-comparable: the first
  diverging event differs in place, and a missing trailing event leaves
  symbolic `trace_init` residue some input distinguishes.
- Their environment-determined errno return is a shared per-call-index
  oracle sign-extended from 32 bits (real returns fit in an int; full-width
  freedom would fake divergences between C `long` and Rust `i32` compares).
  Per-index sharing is sound *because* traces are compared: equal traces
  imply equal map/env state at the nth call.
- map_pop/peek produce value bytes from a shared per-call-index oracle,
  written only when the shared errno says success.
- trace_printk requires a concrete format string (rodata/stack); numeric
  conversions compare at the width the kernel reads (%d → 4 bytes,
  %ld/%lld → 8); `%s`/`%p` bail.
- Pure environment reads keyed by their question, not by call order:
  get_current_comm bytes are `oracle(size, k)` (kernel NUL-pads per size, so
  different sizes must not alias); skb_load_bytes reads a shared symbolic
  `skbdata` packet array with success `oracle(offset, len)`; both zero-fill
  the destination on error, as the kernel does.
- bswap (BPF_END) and atomics (add/or/and/xor ± fetch, xchg, cmpxchg,
  load-acquire/store-release) are modeled exactly; atomics get sequential
  semantics, consistent with the model's single-threaded stance.

Helper calls (tier 3) — nullable pointer returns:

- map_lookup_elem (and _percpu_elem, sk/inode/task/cgrp storage_get) emits
  a trace event with its question (map, key bytes / object+flags), then
  FORKS the path on a shared per-call-index NULL oracle: in any one model
  both programs' nth call takes the same branch. The non-null side returns
  a pointer into a per-call-index `mapval:` region with shared initial
  contents; writes through it are map state, compared as observables.
  Sharing per index is justified exactly as in tier 2: the trace pins the
  question and the mutation order. get_local_storage is verifier-typed
  non-null, so it gets the region without the fork.
- Same-key aliasing between separate lookups is NOT modeled (each call gets
  a fresh region); this cannot fake equivalence — a value written via one
  pointer and reread via another shows up as a mapval observable diff — and
  adds no false INEQUIVs beyond what trace equality already demands.
- map-in-map lookups return a dynamic inner-map handle whose key/value
  sizes come from the outer def's `values` BTF member.
- ringbuf_reserve forks NULL/pointer into a shared-residue `rbuf:` region;
  submit's trace event captures the buffer bytes — publication is the
  observable moment — while discarded buffers stay unobservable, as in the
  kernel. ringbuf_query is a per-index oracle read with a trace event.
- spin_lock/unlock are no-ops under sequential semantics, kept as trace
  events (region + offset) so lock placement must match.
- Pointer spills to the stack live in a per-region shadow keyed by concrete
  offset: 8-byte reloads return the pointer, partial/overlapping reads bail
  rather than see garbage, and data overwrites invalidate the slot.

Tier 4 — bpf2bpf calls and tail calls:

- Subprog calls are executed inline: the callee's section is decoded on
  demand (CO-RE-carrying callee sections bail), a per-path return stack
  tracks (section, pc, caller r10), and each call instance gets a fresh
  stack frame region. Callee r6-r9 save/restore happens naturally by
  executing the callee's own code; r1-r5 flow through as real values.
  Call targets resolve uniformly as `sym.value/8 + imm + 1` for
  FUNC/SECTION relocs and `pc + 1 + imm` for same-section calls (verified
  against both compilers' encodings). Depth capped at the verifier's 8.
  ld_imm64 of a function (callback helpers: bpf_loop, for_each_map_elem,
  timer callbacks) still bails.
- tail_call emits a trace event (prog-array map + index), then forks on a
  shared per-call-index success oracle: the success side ends the path with
  the target program's return modeled as a shared oracle (the target also
  mutates state identically for both programs, so leaving it unmodeled is
  consistent); the failure side continues with an errno oracle.

Tier 5 — kfuncs, arena, may_goto, and the helper tail:

- kfunc calls (call insns whose relocation names an undefined symbol, in
  both objects) dispatch by name onto the tier-2/3 patterns:
  rcu_read_lock/unlock and preempt toggles are no-ops with a trace event;
  release-style kfuncs (task/cgroup/cpumask release, key_put) are events
  pinning the object identity; acquire-style kfuncs (task_from_pid,
  cgroup_from_id, cpumask_create, lookup_user_key, ...) return a shared
  per-index oracle *address* — derefs read the shared kmem and the
  program's own NULL check is the fork; bpf_cast_to_kern_ctx is identity.
  Every cpumask operation is an event + shared per-index oracle result
  (equal traces imply equal object state at the nth op). Iterators
  (bpf_iter_<kind>_new/next/destroy, generically) put their args in the
  trace and fork each next() on a shared NULL oracle whose non-null side
  is a shared per-index element region. Unknown kfuncs still bail.
- Pure string kfuncs (bpf_strcmp/strstr/strlen family) are functions of
  their contents: the event captures the actual bytes (exactly up to NUL
  when concrete; a fixed symbolic window for shared-region contents), and
  the result is a shared per-index oracle.
- bpf_throw is modeled exactly, not through an oracle: it unwinds the
  frame stack and transfers to the program's `exception_callback:` BTF
  decl-tagged callback with the cookie as argument (or returns the cookie
  when untagged), so a translation that reaches the same state without
  throwing (rustc cannot emit decl tags) proves equivalent.
- Arena: `addr_space_cast` is a provenance-preserving identity; arena
  globals in `.addr_space.1` are ordinary named observables;
  bpf_arena_alloc_pages forks NULL/pointer into a per-index zero-
  initialized observable region (kernel pages are zeroed), free is an
  event. Pointer values stored into observable regions (arena/global data
  structures) keep a spill-shadow entry AND write a canonical
  (region, offset) identity encoding into the byte array, so storing
  different abstract pointers stays distinguishable.
- may_goto (JCOND) is modeled as never taken: its escape branch fires
  after ~8M iterations, far beyond any enumerable path (deliberate,
  documented assumption).
- Helper-tail coverage, all on tier-2 rationale: a data-driven
  side-effect table (redirect family, skb_adjust_room/change_head/
  pull_data, set_tunnel_key, setsockopt, bind, lwt_push_encap, sk_assign,
  sk_release, the four *_storage_delete helpers) emits events with
  value/memory/map/pointer-identity args and an errno oracle;
  buffer-writing env reads (get_stack, skb_get_tunnel_key, getsockopt,
  check_mtu) write shared per-index oracle bytes on success;
  copy_from_user reads shared user memory with an (addr, len)-keyed
  success oracle and kernel-faithful zero-fill on failure; seq_printf/
  seq_write events carry the format and raw data bytes (the bpf_iter
  observable); sk_lookup_tcp/udp fork into per-index socket-state
  regions; sk_fullsock returns its argument or NULL; tcp_sock derives a
  per-index view region; get_socket_cookie is an oracle keyed by the
  socket identity; get_func_ip/arg_cnt, get_attach_cookie and
  xdp_get_buff_len are per-index oracle streams.

Rust v0-mangled static names are normalized to their source identifier so the
same logical global maps to the same region in both objects. The C object's
BTF is ground truth for return contracts: void functions skip the return
comparison, ≤32-bit return types compare low 32 bits.

`equiv/waivers.tsv` records accepted semantic divergences (verdict WAIVED,
non-failing, reason required). Two classes: kernel-impossible-input
divergences (test_stack_var_off, test_global_func16 — C deliberately reads
uninit stack residue where Rust zero-inits; bpf_flow/flow_dissector_4 —
LLVM folds `!(data + thoff)` to `!data`; test_tc_dtime — Rust masks
skb->protocol to 16 bits) and deliberate, documented translation
divergences (lru_bug — Rust reconstructs the kernel's LRU node-reuse race
by probe-reading stale bytes instead of relying on allocator internals;
test_xdp_devmap_tailcall — Rust establishes PROG_ARRAY ownership with a
never-taken tail_call because the C `.values` flexible-array reloc isn't
expressible; test_core_reloc_type_based — the translation is the C
source's own no-builtin `#else` skip branch, since rustc has no
`__builtin_preserve_type_info`).

Soundness stance: unsupported constructs BAIL rather than being approximated,
so EQUIV verdicts only rest on modeled semantics. Known deliberate
assumptions: probe-reads never fault; LD_IMM64 global/map pointers are
non-NULL; both programs see the same kernel memory snapshot and the same
initial (uninit) stack residue; the nth call to a given helper observes the
same environment value in both programs.

## Verdict sweeps (2026-08-05)

550-object corpus, per-program totals:

- v1 (no helpers): 335 EQUIV / 0 INEQUIV; all 26 initial INEQUIVs were
  model artifacts (void rets, .text subprogs, .struct_ops data, CO-RE).
- tier 1 (probe_read family + pure oracles): **366 EQUIV / 0 INEQUIV /
  1 WAIVED** (83 objects fully proved). The tier-1 triage surfaced and fixed:
  oracle return widths, pid_tgid range refinement, Rust static demangling,
  BTF-based return contracts, shared stack residue — and found one genuine
  divergence (test_stack_var_off, waived).
- tier 2 (2026-08-10; call trace + bswap + atomics + retval state):
  **456 EQUIV / 0 INEQUIV / 2 WAIVED** (106 objects fully proved; object
  verdicts 106 EQUIV / 268 BAIL / 164 CORESKIP / 11 NOPROGS / 1 TIMEOUT).
  Negative controls: mutated map_update flags and key offset both flagged
  INEQUIV through the trace observable. **Second true finding**:
  cgroup_getset_retval_getsockopt compared `optlen > page_size` signed where
  C (with `__u32 page_size`, unlike its sibling files' `__s32`) compares
  unsigned — the Rust translation misbehaved for negative optlen, invisible
  to the test oracle; fixed in progs/ and re-proved + QEMU-verified.

- tier 3 (2026-08-10; nullable-pointer helpers + pointer spills +
  map-in-map): **495 EQUIV / 0 INEQUIV / 2 WAIVED / 4 UNKNOWN** (128
  objects fully proved; object verdicts 128 EQUIV / 237 BAIL /
  164 CORESKIP / 11 NOPROGS / 9 TIMEOUT / 1 UNKNOWN). Negative controls:
  mutated lookup key, value flowing through the looked-up pointer, and a
  store offset through it — all flagged INEQUIV (the last via the mapval
  region observable). The 9 TIMEOUTs are the pyperf/strobemeta
  verifier-stress class: single-side path enumeration alone exceeds 300 s
  (50+-iteration unrolled loops; would need join-point path merging).
  access_map_in_map is UNKNOWN — Z3 gives up on its equality query even at
  a 5-minute budget. strobemeta_nounroll1 bails on a symbolic-size
  probe_read (bounded symbolic copies are future work).

- tier 4 (2026-08-10; bpf2bpf inlining + tail_call): **541 EQUIV /
  0 INEQUIV / 4 WAIVED / 5 UNKNOWN** (157 objects fully proved; object
  verdicts 157 EQUIV / 207 BAIL / 164 CORESKIP / 11 NOPROGS / 10 TIMEOUT /
  1 UNKNOWN). Control: a mutated load offset inside a .text subprog
  propagates through the inlined chain to an INEQUIV with a concrete
  counterexample (a first control attempt hit genuinely dead code, which
  the prover rightly called EQUIV). New waivers, both kernel-impossible
  inputs: test_global_func16 (C returns uninit stack residue by design;
  Rust zero-inits) and test_tc_dtime/ingress_host (Rust masks
  skb->protocol to 16 bits; C compares the full 32-bit ctx word the kernel
  always zero-extends). The TIMEOUT class grew to the whole pyperf family
  (subprog variants now execute instead of bailing, and blow up the same
  way).

- CO-RE application (2026-08-11): **665 EQUIV / 0 INEQUIV / 7 WAIVED /
  3 UNKNOWN** (197 objects fully proved; object verdicts 197 EQUIV /
  327 BAIL / 14 TIMEOUT / 11 NOPROGS / 1 UNKNOWN). The CORESKIP class
  (164 objects / 504 programs) is gone: both objects are relocated
  against the qemu kernel's vmlinux + module BTFs before lifting, with
  the implementation validated byte-for-byte against libbpf's own
  `bpf_object__prepare()` output across the whole corpus (the validation
  itself caught four bugs: typedef-rooted candidate search, type-relos
  resolving to 0 when the target type is absent, TYPE_MATCHES offset
  over-strictness, and distilled-base module split BTF). Negative
  control: skewing the Rust side's applied field offsets by +8 flips
  kfree_skb to INEQUIV. **True findings #3–#6, all fixed and
  QEMU-verified**: bpf_smc returned the raw `default_ip_strat_value`
  byte where C's `bool` return normalizes to 0/1;
  task_local_storage did 64-bit arithmetic where C's unsigned-int
  `0xabcd1234 + cnt` wraps at 32 bits before widening; test_overhead
  stubbed prog1–3 returns that C computes from pt_regs/raw_tp args;
  test_sock_fields logged line 293 where C's RET_LOG() records 294;
  test_core_reloc_module read task comm with size 12 where C uses
  `sizeof("test_progs")` = 11. The TIMEOUT class (pyperf/strobemeta ×9,
  rhash, access_map_in_map, and now the newly-unlocked loop3,
  test_verif_scale2, test_core_reloc_kernel, test_parse_tcp_hdr_opt)
  still needs join-point path merging; 3 UNKNOWNs are Z3 giving up on
  very large single programs (bpf_flow _dissect, cls_redirect
  balancer_ingress, cgroup_hierarchical_stats flusher).

- tier 5 (2026-08-11; kfuncs + arena + may_goto + helper tail):
  **1020 EQUIV / 0 INEQUIV / 8 WAIVED / 6 UNKNOWN** (254 objects fully
  proved; object verdicts 254 EQUIV / 260 BAIL / 21 TIMEOUT /
  11 NOPROGS / 4 UNKNOWN). Negative controls: a mutated string-kfunc
  rodata literal and a mutated seq_write length both flag INEQUIV
  through the trace. **True findings #7–#15, all fixed and
  QEMU-gated**: the `0xabcd1234` unsigned-int wrap again in
  cgrp_ls_tp_btf; the `_Bool`-byte compare class (clang emits `!= 0` at
  some sites and `== 1` at others — even within one file) in three
  cgrp_ls files and vrf_socket_lookup; a struct-padding residue leak
  into a map value in lsm_bdev; C pointer-arithmetic scaling kept
  unfaithfully in test_sk_lookup_kern (`tuple + sizeof *tuple` = +1296
  bytes; `sk += 1` = +80); a 4-byte store through a `__u64*` value in
  test_skmsg_load_helpers; an unsigned-promotion compare in
  test_sockmap_strp; copy_from_user result discarded in
  test_spin_lock_fail; int sign-extension into a u64 helper arg in
  xdp_redirect_multi_kern; and 62 dropped bpf_printk error/success-log
  sites restored across test_tunnel_kern and test_sk_lookup. Model
  fixes surfaced by the same triage: per-run region tags neutralized in
  pointer-identity captures, clang/rustc function-local static names
  canonicalized to one region, and the buffer-helper errno oracle
  clamped to the kernel's 0-or-negative contract. The TIMEOUT class
  (21) now also includes fork-heavy iterator/cpumask objects.

Results tables: `results/`. Remaining bail classes after tier 5:
unmodeled helper tail ×192 program-sites and kfunc tail ×181 (dynptr
family, timers/wq, fou encap, testmod/struct_ops kfuncs, ...); stores
through kernel-pointer windows ×60; callback-function ld_imm64 ×70;
oversized copies (get_stack 2048, probe_read 2880 > MAX_COPY) ×12;
pointer-compare/symbolic-size/spill tail.

## Roadmap

1. **Rust collections follow-up** (user-requested): arena-backed
   GlobalAlloc + real `alloc` collections in a separate test folder —
   new Rust-native programs, outside the equivalence corpus.
2. **Tier 6 candidates**: dynptr family, timers/wq (needs callback
   identity), remaining kfunc tail, ctx pointer-field windows
   (optval/pkt data), larger bounded copies.
3. **Path-merging at join points** for the pyperf/strobemeta/iterator
   TIMEOUT class (21 objects).
4. **Regression guard**: bytecode-hash fast path; re-prove after
   quality-layer edits, alarm on equivalence break.
