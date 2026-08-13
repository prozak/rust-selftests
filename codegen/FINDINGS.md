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

## Finding 1: byte-wise initialization of packed structs

The single largest contributor to the frame-traffic gap. `--show
test_lwt_ip_encap:encap_gre6`:

```
clang                                   rustc
stx_stack  op=0x63 [r10-8],  r2   (4B)  stx_stack  op=0x72 [r10-3],  0   (1B)
stx_stack  op=0x7b [r10-16], r2   (8B)  stx_stack  op=0x72 [r10-4],  0   (1B)
stx_stack  op=0x7b [r10-24], r2   (8B)  stx_stack  op=0x72 [r10-5],  0   (1B)
stx_stack  op=0x7b [r10-32], r2   (8B)  ... 42 single-byte stores total
stx_stack  op=0x7b [r10-40], r2   (8B)
stx_stack  op=0x7b [r10-48], r2   (8B)
```

clang zeroes a 48-byte local with **6 wide stores**; rustc zeroes the same
local with **42 one-byte stores**. Whole program: 41 vs 72 instructions.

Cause: the C declares a plain local struct and `memset()`s it. The
translation declares `#[repr(C, packed)]` and uses `core::mem::zeroed()`.
`packed` drops the struct's alignment to 1, so LLVM's memset expansion can
only assume byte alignment — even though the BPF stack is always 8-byte
aligned and clang exploits exactly that.

Two separable fixes, and they are worth separating:

1. **Translation-side, mechanical.** 43 translated files declare
   `#[repr(C, packed)]` where the C struct carries no packed attribute at
   all (204 `repr(C, packed)` declarations across the corpus). Where the C
   layout has no padding, `#[repr(C)]` is byte-identical and keeps the
   alignment information. Candidates include `test_cls_redirect`,
   `test_l4lb`, `bpf_flow`, `fib_lookup`, `test_assign_reuse`. Each needs
   the C layout checked before changing — dropping `packed` where the C
   struct really is packed would change layout, which the prover would
   catch but which is a real bug to introduce.
2. **Compiler-side.** For genuinely packed structs the stores are still
   over-conservative on BPF, where the stack is 8-byte aligned and
   unaligned access is not a fault. Teaching the pipeline to widen
   stack-slot initialization would fix the residue that (1) cannot.

Note the interaction with an existing workaround: `bpf-rs-core` uses
volatile byte loops (`vcopy`/`vzero`) in places specifically because a
plain array copy gets MemCpyOpt-rewritten into an unresolvable
`bpf_arena_memcpy` kfunc call. Volatile stores are by definition
unmergeable, so that workaround has the same cost by construction. Fixing
memcpy/memset lowering for BPF would let those idioms go away too.

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

## Open leads

- `test_xdp:_xdp_tx_iptunnel` is the largest absolute excess (+137) with
  `ldx_mem` +49 / `stx_mem` +41 — memory traffic, not frame traffic, so a
  different cause from Finding 1.
- The `test_tc_tunnel` family clusters tightly (+52 to +87, dominated by
  `stx_stack`), which suggests one shared idiom rather than nine problems.
