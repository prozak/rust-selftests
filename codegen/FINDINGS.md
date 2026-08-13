# Findings

Analysis of `REPORT.md`. Numbers from the 2026-08-12 run: 1099 proved-
equivalent program pairs.

## Headline: the totals hide the difference

```
1099 program pairs, 1.041x total instruction count (clang 25,709 -> rustc 26,765)
identical size: 603 (55%);  rustc smaller: 327 (30%);  rustc larger: 169 (15%)
```

Aggregate parity, and a majority of programs match exactly. So "rustc emits
bigger BPF" is not true as a general statement, and 30% of the time rustc
emits *fewer* instructions than clang.

The composition tells a different story:

| kind | clang | rustc | delta |
|---|---:|---:|---:|
| `stx_stack` | 1,538 | 2,789 | **+1,251 (+81%)** |
| `ldx_stack` | 542 | 991 | **+449 (+83%)** |
| `alu64` | 5,090 | 4,169 | -921 (-18%) |
| `ldx_mem` | 2,659 | 2,979 | +320 (+12%) |
| `call_bpf2bpf` | 532 | 592 | +60 (+11%) |

rustc emits **~1,700 more frame-traffic instructions** and ~1,000 fewer ALU
instructions. The near-1.0x total is two large effects cancelling, not two
compilers agreeing.

## Finding 1: byte-wise memory traffic, from three causes with one root

This is the whole story, and it is bigger than the net regression:

| access | clang | rustc | delta |
|---|---:|---:|---:|
| `ldx_1B` | 478 | 1,661 | **+1,183 (+247%)** |
| `st_1B` | 553 | 1,687 | **+1,134 (+205%)** |
| `ldx_2B` | 305 | 215 | -90 (-30%) |
| `ldx_4B` | 1,397 | 1,149 | -248 (-18%) |
| `ldx_8B` | 1,021 | 945 | -76 (-7%) |
| `st_8B` | 1,376 | 1,345 | -31 (-2%) |

Single-byte accesses are **17% of clang's memory traffic and 41% of
rustc's**: +2,317 of them. Wide accesses fall by roughly the amount the
byte accesses rise, which is what a copy being done one byte at a time
instead of eight looks like.

Note the size: +2,317 excess byte accesses against a **net delta of only
+1,056 instructions** for the whole corpus. This one effect is larger than
the total regression — rustc's ALU wins (Finding 3) are currently masking
it. Fixing it plausibly makes rustc net *smaller* than clang.

Three distinct causes feed it. Two are translation-side; all three trace
back to the pipeline not lowering `memcpy`/`memset` for BPF the way clang
does.

### 1a. Hand-rolled volatile byte loops

`test_xdp:_xdp_tx_iptunnel` (+137 instructions, the largest absolute
excess). C writes `memcpy(new_eth->h_source, old_eth->h_dest, 6)`; the
translation calls `vcopy`, a `read_volatile`/`write_volatile` byte loop.
The emitted code is an `ldxb`/`stxb` pair per byte at consecutive offsets
where clang uses word-wide loads and stores.

`bpf-rs-core` documents exactly why: a plain array copy gets
MemCpyOpt-recognized and rewritten into an unresolvable `bpf_arena_memcpy`
kfunc call, and volatile access is the one pattern the optimizer will not
merge back into a memcpy. So the workaround has this cost *by
construction* — volatile stores are unmergeable by definition.

**This is the root fix**: make `memcpy`/`memset` lower to inline wide
stores for BPF. It retires the workaround, and with it 1a entirely.

### 1b. `#[repr(C, packed)]` blocks widening

`test_lwt_ip_encap:encap_gre6` — clang zeroes a 48-byte local with **6 wide
stores**, rustc with **42 one-byte stores** (41 vs 72 instructions):

```
clang                                   rustc
stx_stack  op=0x7b [r10-16], r2   (8B)  stx_stack  op=0x72 [r10-4],  0   (1B)
stx_stack  op=0x7b [r10-24], r2   (8B)  stx_stack  op=0x72 [r10-5],  0   (1B)
stx_stack  op=0x7b [r10-32], r2   (8B)  ... 42 single-byte stores total
```

The C declares a plain local and `memset`s it; the translation declares
`#[repr(C, packed)]` and uses `core::mem::zeroed()`. `packed` drops
alignment to 1, so memset expansion can only assume byte alignment — though
the BPF stack is always 8-byte aligned and clang exploits exactly that.

43 translated files declare `repr(C, packed)` where the C struct carries no
packed attribute at all (204 declarations corpus-wide). Where the C layout
has no padding, `#[repr(C)]` is byte-identical and keeps the alignment.
Each needs the C layout checked first — dropping `packed` where C really is
packed changes layout, which the prover would catch but which is a real bug
to introduce.

### 1c. Dead zero-init of helper output buffers

The `test_tc_tunnel` family (+52 to +87 across nine programs, one idiom).
C declares the buffer uninitialized and lets the helper fill it:

```c
struct ipv6hdr iph_inner;                                  /* no init */
if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph_inner, sizeof(iph_inner)) < 0)
```

Rust has no uninitialized locals, so the translation writes out a
fully-zeroed struct literal first. Those stores are dead — the helper
overwrites the whole buffer — but LLVM cannot prove it, because the helper
call is opaque and nothing says it fully initializes the pointee.

Translation-side fix: `MaybeUninit` for helper output buffers, which is
precisely what it is for. This also removes a real semantic divergence, not
just instructions: the "C leaves it uninit, Rust zero-inits" pattern is why
the tier-9 prover model had to treat never-stored bytes as zero.

## Finding 2: no way to express "do not unroll this loop"

`loop4:combinations` is the largest ratio in the corpus — 14 clang
instructions against 139 rustc ones (9.9x). The C source says so
explicitly:

```c
__pragma_loop_no_unroll
for (i = 0; i < 20; i++)
        if (skb->len)
                ret |= 1 << i;
```

rustc has no equivalent, so it fully unrolled a 20-iteration loop. This is
worse than a size regression: `loop4` exists to test the verifier against a
*rolled* loop, so the translation quietly stops testing what the selftest
is for.

12 translated files use loop pragmas, and they are 1.39x overall against
the corpus-wide 1.04x. Splitting by pragma direction:

| `__pragma_loop_no_unroll` (C stays rolled) | ratio |
|---|---:|
| loop4 | 9.93x |
| test_xdp_loop | 1.46x |
| test_sysctl_loop1 | 1.27x |
| test_sysctl_loop2 | 1.19x |
| test_seg6_loop | 1.08x |

**All five are larger in rustc**, which is exactly the predicted direction.
The seven `__pragma_loop_unroll_full` files are mixed (0.89x–1.76x), so
those regressions have some other cause and should not be attributed here.

Compiler-side: the pipeline needs a way to attach LLVM loop metadata
(`llvm.loop.unroll.disable`) — Rust has no stable attribute for it, so this
is a rust-bpf pipeline feature, not something a translation can express.

Cross-workstream note: unrolling multiplies the paths the prover must
enumerate, and three of these files (`test_cls_redirect`, `test_seg6_loop`,
`test_xdp_noinline`) are currently prover TIMEOUTs. Loop control may buy
coverage in `equiv/` as well as size here — worth testing rather than
assuming.

## Finding 3: rustc wins on ALU

`alu64` -18%, `alu32` -3%, `ld_imm64` -2%, `endian` -8%, `atomic` -11%.
rustc's arithmetic codegen is consistently *tighter* than clang's here.
Worth understanding rather than only celebrating: some of it is likely
rustc materializing constants differently, and some may be the translation
expressing an operation more directly than the C source did.

## Finding 4: inlining disagreement

`call_bpf2bpf` +11%, and `exit` +5% (one per inlined-vs-not function).
Already seen concretely in tier 9: clang inlined `clobber_regs_stack` where
rustc left it a bpf2bpf callee. This costs instructions but also changes
the verifier's job, so it is worth a look independent of size.

## Finding 5: stack frames are level in aggregate

Total frame bytes clang 8,436 vs rustc 8,464 (1.00x). Given the verifier's
512-byte frame cap this is the reassuring result. Individual regressions
exist (`loop4:combinations` 0 -> 128 bytes, `test_global_data` 4 -> 88) and
are worth checking for headroom, but there is no systemic frame growth.

## Ranked work items

Two are compiler changes and two are mechanical translation sweeps. The
prover validates each change and this report measures it, so every item
below is a closed loop.

| # | change | where | evidence |
|---|---|---|---|
| 1 | lower `memcpy`/`memset` to inline wide stores for BPF | rust-bpf pipeline | 1a — retires the `vcopy`/`vzero` workaround; largest single cause |
| 2 | `MaybeUninit` for helper output buffers | translations | 1c — nine `test_tc_tunnel` programs, and removes a semantic divergence |
| 3 | drop `repr(C, packed)` where the C struct is not packed | translations | 1b — 43 candidate files, each needs its C layout checked |
| 4 | attach `llvm.loop.unroll.disable` metadata | rust-bpf pipeline | 2 — no Rust attribute exists; also a test-fidelity bug |

## Open leads

- Finding 3 (rustc's ALU win, -921 `alu64`) is unexplained and currently
  masking Finding 1 in the totals. Worth understanding before item 1 lands,
  or the improvement will be hard to read.
