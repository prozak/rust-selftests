# Translating a BPF selftest C program to Rust (rust2bpf idiom)

Rules for translating `tools/testing/selftests/bpf/progs/<name>.c` to
`progs/<name>.rs` in this repo. The Rust is compiled **directly to BPF by
upstream rustc/LLVM** — there is NO aya, NO libbpf-rs, NO bpf crate. Every
kernel-facing construct is expressed with core Rust + `#[link_section]` +
BTF emitted from debuginfo, through the local support crate
`bpf-rs-core/` (`use bpf_rs_core::...` — linked automatically by the
Makefile). The compiled object must be a drop-in replacement for the
clang-built one: same section names, same global symbol names/types, same
BTF shape — the kernel's unmodified test harness (skeletons, prog_tests)
is the acceptance oracle.

## Crate skeleton

```rust
#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;

// ... programs ...

bpf_object!("GPL");   // license static (strlen+NUL, same as C) + panic handler
```

Panics must be unreachable (no unwrap/indexing that can panic); the
`loop {}` handler `bpf_object!` emits is dead code removed by DCE.
Edition 2021, builds as rlib.

## Programs

One `extern "C" fn` per BPF program:

```rust
#[link_section = "<same SEC() string as the C source>"]
#[no_mangle]
extern "C" fn <same_function_name_as_C>(ctx: *const CTX) -> i32 { ... 0 }
```

- Function name and section string must match the C source exactly.
- tracing programs (fentry/fexit/tp_btf/...): ctx is `*const u64`, one slot
  per target-function argument. `bpf_rs_core::progs::fentry_arg(ctx, i)`
  reads arg i; truncate with `as i32` / `as i8` etc. to the target arg's C
  type (this is what C's BPF_PROG macro does).
- tracepoint ("tp/..."): ctx points at the tracepoint record; if the body
  never dereferences it use `*const core::ffi::c_void`.
- tc/XDP/socket: ctx is a pointer to the UAPI context struct.
  `bpf_rs_core::ctx` provides the full UAPI `__sk_buff` (and TC_ACT_*).
  CRITICAL if you declare a ctx struct yourself: it must carry the exact C
  name (`__sk_buff`, `xdp_md`, ...) — the kernel matches BTF struct types
  BY NAME for freplace/fexit attach compatibility and global-function ctx
  args; a differently-named struct loads but breaks C extension programs
  attaching to yours.
- BTF-typed pointer args (fentry arg that is a struct pointer): the loaded
  value may be dereferenced directly (`*(p as *const u64)` for first
  field); the verifier converts these to fault-tolerant PROBE_MEM loads,
  no null check needed unless the C code checks.

## Globals

C globals the harness reads/writes (`__u64 test1_result = 0;`):

```rust
#[no_mangle]
static mut test1_result: u64 = 0;    // zero-init => .bss, same as C
```

Same names, same types, same zero/nonzero init (nonzero => .data). This
representation is FORCED by the ABI: the regenerated skeleton must see a
plain primitive-typed member, so no wrapper type (UnsafeCell, newtype) is
possible — any wrapper adds a struct layer in BTF and breaks harness C.

Access rule (keeps the pattern sound and edition-2024-clean): NEVER create
a reference to a `static mut`. Copy-read (`unsafe { pid }`), place-write
(`unsafe { update_err = e }`), and read-modify-write of the place
(`unsafe { seq += 1 }`) are all fine; for pointers use
`core::ptr::addr_of_mut!`. C's `__sync_fetch_and_add` on a global becomes
`helpers::sync_fetch_and_add(core::ptr::addr_of_mut!(total), 1)` — the
global stays a plain int in BTF, the atomicity lives at the access site.

Do NOT invent extra global statics: some harnesses iterate the whole bss
section and assert every slot.

Read-only config globals (`const volatile` in C) go to .rodata:
`#[link_section = ".rodata"] #[no_mangle] static tgt_pid: u32 = 0;` and are
read with `core::ptr::read_volatile` (prevents constant folding — the
loader patches the value before load).

## Maps

libbpf reads map definitions purely from BTF: a VAR in DATASEC ".maps"
whose struct type encodes parameters as pointer members (`__uint(type, V)`
= `int (*type)[V]`, `__type(key, T)` = `T *key`). The common shape is one
line:

```rust
use bpf_rs_core::maps::{self, BpfMap};

#[link_section = ".maps"]
#[no_mangle]
static hash_map: BpfMap<u64, u64, { maps::HASH }, 2> = BpfMap::new();
//                key  value  type            max_entries
```

Map-type constants live in `bpf_rs_core::maps` (HASH, ARRAY, PROG_ARRAY,
PERF_EVENT_ARRAY, PERCPU_HASH, PERCPU_ARRAY, STACK_TRACE, LRU_HASH,
RINGBUF, ...; values = enum bpf_map_type).

Any other member set (pinning, key_size/value_size, absent max_entries,
...) uses the escape hatch, which encodes members exactly like the
hand-written C-equivalent struct:

```rust
bpf_map! {
    perf_buf_map {
        r#type: *const [i32; 4], // BPF_MAP_TYPE_PERF_EVENT_ARRAY
        key: *const i32,
        value: *const i32,      // no max_entries: libbpf sizes to nr_cpus
    }
}
```

(Generic instantiations reach BTF with names like `BpfMap<u64, u64, 1, 2>`;
the kernel rejects non-identifier chars in type names, and
`scripts/btf_rename.py` sanitizes them post-build. Map def struct names
are not load-bearing for libbpf — only the VAR name and member layout
are.)

## Helper calls

All helpers live in `bpf_rs_core::helpers` as `#[inline(always)]` thunks
(fn pointer whose value is the helper ID — same mechanism as C's
bpf_helpers.h; LLVM folds it into the direct helper-call insn). Map
arguments are generic over the map-def type:

```rust
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_map_update_elem};

let v = bpf_map_lookup_elem(&hash_map, &key);   // *mut c_void — check null!
bpf_map_update_elem(&hash_map, &key, &value, BPF_NOEXIST);
```

If a helper you need is missing, ADD it to `bpf-rs-core/src/helpers.rs`
following the existing `thunk!` pattern (IDs: include/uapi/linux/bpf.h FN
macros) — append-only; never change existing signatures.

## kfuncs

Declare as extern and call; the pipeline's add_ksyms step emits the ksym
relocation libbpf resolves via BTF:

```rust
extern "C" { fn bpf_task_from_pid(pid: i32) -> *mut task_struct; }
```

## Kernel-struct field access (CO-RE)

Only when the C source reads kernel struct fields via BTF pointers /
BPF_CORE_READ: use the `#[btf]` proc-macro from the rust-bpf btf crate
(`use btf_macros::btf;` — the crate is linked automatically):

```rust
#[btf]
struct task_struct { pid: i32 }
// tsk: *mut task_struct
let pid = *unsafe { &*tsk }.pid().get().unwrap();
```

## Volatile / ctx field access

Where C uses `volatile` (narrow ctx loads, cb[] stepping), use the crate's
place-expression macros — they keep every access separate and
correctly-sized (the verifier rewrites each ctx load individually):

```rust
use bpf_rs_core::{vload, vload_as, vstore};

let full = vload!((*skb).len);            // volatile u32 load
let low  = vload_as!((*skb).len, u8);     // volatile narrow load
vstore!((*skb).mark, v.wrapping_add(1));  // volatile store
```

C's `__sink(x)` compiler barriers: `helpers::sink(&mut ptr)` (forces a
stack buffer to materialize), `helpers::sink_val(v)` (consumes a value in
a register, keeps dead-arg-elim from dropping a function argument).

## Things that break and why

- Wrong int types in comparisons: C promotes/truncates implicitly; be
  explicit with `as` casts, matching C semantics bit-for-bit.
- LLVM merging loads the C kept separate: use `vload!`/`vstore!` wherever
  C used `volatile`.
- Reachable panics (slice indexing, unwrap): verifier sees the loop{} —
  rejected. Use get()/pointer arithmetic.
- Extra/missing global symbols vs the C object: the build derives the
  internalize keep-list from the C object's global FUNC/OBJECT symbols;
  your Rust must define all of them with matching names.
- Never name a helper wrapper the same as a real kfunc/extern unless you
  mean a relocated call.
- `__failure`/`__msg` negative verifier tests are untranslatable as
  negative tests: rustc cannot emit BTF_KIND_DECL_TAG, so test_loader
  defaults to expect-success. Keep the program structure but make it load
  (see test_global_func1.rs), or classify the program as blocked.

## Build & validate

```sh
make                     # bld/<name>.bpf.o  (compile gate)
make verify              # kernel verifier gate for all objects (UML)
make test-<name>         # swap in + kernel-Makefile skeleton regen +
                         # affected test_progs tests in UML (oracle gate)
make restore-<name>      # reinstate the clang-built object
```

## Divergence classes the equivalence prover has caught (lint before submitting)

`python3 scripts/translint.py <name>` checks a translation mechanically;
`../z3-venv/bin/python equiv/guard.py <name>` re-proves it after a rebuild
(hash-gated, seconds when nothing else changed). The classes, each found
as a real bug at least once (equiv/README.md "true findings"):

- **Dropped logging** [lint: printk-count]: every C `bpf_printk`/`log_err`
  site must exist in the Rust — 62 real INEQUIV sites came from omitted
  error/success logs. `__LINE__`-style args must carry the C source's
  line numbers.
- **Bool globals** [lint: bool-global]: clang compiles `if (_Bool)` as
  `jne 0` at some sites and `jne 1` at others, in the same file. Store the
  global as `u8` and mirror each site's compare after disassembling the C
  object. Bool RETURNS normalize too (`(x != 0) as i32`, not `x as i32`).
- **Hex-literal typing** [lint: big-hex]: a hex literal that doesn't fit
  `int` is UNSIGNED int in C — `0xabcd1234 + cnt` wraps at 32 bits before
  widening. Use `u32` + `wrapping_add`, then extend.
- **Struct padding** [lint: padding]: C's `= {}` zeroes padding bytes; a
  Rust struct literal leaves them undefined. Make padding explicit
  (`_pad: [u8; N]`) for anything reaching a map value or trace.
- **Pointer-arithmetic scaling** [lint: ptr-scaling]: C scales by element
  size — `tuple + sizeof *tuple` advances 36*36 bytes; `sk += 1` advances
  `sizeof(struct bpf_sock)`. Mirror the object, not the intuition.
- **Store width** [lint: narrow-cast]: match the C pointee exactly; a u32
  store through what C types `__u64 *` leaves 4 residue bytes in the map.
- **Promotions & extensions**: `u32 > int` compares UNSIGNED in C;
  `int` args to u64 helper params SIGN-extend (`x as i64 as u64`).
- **Usual-int arithmetic**: C `int` intermediates truncate/sign-extend at
  32 bits; keep Rust arithmetic at the same width as the C expression.

After any translation edit: `make <obj>` + `equiv/guard.py <name>` +
`make test-<name>` (runtime oracle). The guard alarms on INEQUIV and on
verdict downgrades; its baseline (equiv/results/baseline.tsv) is
committed and updated by the run.
