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

A program that reads the kernel's map object through the map pointer
(`struct bpf_map *map = (void *)&m_hash; map->max_entries`, a `#[btf]`
view of `bpf_map` over `addr_of!(m_hash)`) must declare that map
`static mut`: a `static` is an LLVM constant whose initializer is all
null pointers, so every load from it folds to zero before the CO-RE
relocation exists, and the check silently fails. The C map is a writable
global; `scripts/maps_section.py` makes the section writable either way.
`map_ptr_kern.rs` declares all of its maps so.

### Statically-initialized `values` slots (prog-array, map-in-map)

C's `__array(values, void (void))` with `.values = { [0] = &prog }` asks the
map's BTF to call `values` a **zero-length** array (`parse_btf_map_def`
rejects anything else: *"prog-array value spec is not a zero-sized array"*)
while its `.maps` storage is one pointer per slot — `bpf_object__collect_map_relos`
derives the slot index from the **relocation offset** against that storage,
not from the BTF. clang gets both by widening the LLVM global's codegen type
past its debuginfo type; a Rust static's IR type and DIType always come from
the same declaration, so neither `[Fn; 0]` (valid BTF, no storage, no
relocation) nor `[Fn; N]` (storage libbpf refuses to parse) works alone.

Declare the real thing and let the post-build pass fix the BTF:

```rust
type ClassifierFn = extern "C" fn(*const __sk_buff) -> i32;

#[repr(C)]
struct jmp_table {
    r#type: *const [i32; maps::PROG_ARRAY],
    max_entries: *const [i32; 2],
    key_size: *const [i32; 4],
    values: [ClassifierFn; 2],   // must be the LAST member, named `values`
}
```

rustc then emits `.maps` bytes and `.rel.maps` entries identical to clang's,
and `scripts/btf_map_slots.py` repoints the `values` member at an appended
zero-length ARRAY. Slots are live: a `__retval` that depends on the tail
call actually runs it. Before this pass the slots stayed empty and such
tests passed vacuously.

A map-in-map slot is the same with a pointer to the inner map's definition
as the element; a hole in a C designated initializer is a null:

```rust
#[repr(C)]
struct outer_arr_def {
    r#type: *const [i32; ARRAY_OF_MAPS],
    max_entries: *const [i32; 2],
    key_size: *const [i32; 4],
    value_size: *const [i32; 4],
    values: [*const InnerMap; 2],   // C: .values = { [1] = &inner_htab }
}
// ...
    values: [core::ptr::null(), &inner_htab],
```

Where the C casts a target to `void *` because its type is not the declared
inner type, cast the pointer (`&m as *const m_type as *const Declared`).

`scripts/maps_section.py` does the rest for such objects before llc. A map
with relocated slots would otherwise land in a second, writable `.maps`
section apart from the read-only one holding its targets, and rustc orders
statics by symbol name, while libbpf fills an outer map's slots when it
creates it and so needs the inner maps earlier in the section. The pass
makes every map writable, as in C, and moves inner maps ahead of the maps
that name them.

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

For an external **data** symbol, retain its Rust `extern` declaration and
add `// BTF_KSYM: symbol_name` on its own line. `scripts/ksym_vars.py`
supplies the missing `.ksyms` debug declaration before the pipeline's
internalization/optimization step. The pristine C object's undefined
`.ksyms` variable is the ABI source for its type, const qualifiers, and
weak linkage. A missing symbol, an existing Rust definition, or an
unsupported type is an error; the pass never imports C instructions.

Integer descriptors preserve width and signedness. Struct/union
descriptors preserve the kernel type's name and size, with no copied
fields; translated field accesses still need their own `#[btf]` CO-RE
types. Kfunc prototypes get the same empty descriptors; for the graph
types the kernel resolves by name (`bpf_list_node`, `bpf_rb_root`, ...)
`scripts/btf_graph_types.py` folds them into the translation's own
definition, or a node type declared after the first kfunc call would lose
its kernel metadata and the map holding its head would fail to load. An address-only Rust `c_void` extern can therefore represent a
typed kernel symbol, as in `test_ksyms_btf_null_check`. `test_ksyms`
also demonstrates the C oracle's weak, typeless symbol resolving to zero.

A kfunc's prototype is otherwise mirrored from the running kernel's BTF by
exact name (rust-bpf's add_ksyms.py), which types the pointers of a name
the kernel lacks `void *`. For a kfunc whose prototype must be the C
declaration's, a `___flavor` (libbpf strips the suffix for the lookup and
then checks the declared prototype against the kernel's; whether that
check passes is what such a test is about), add `// BTF_KSYM: name` for
the function as well: the C object's extern prototype is mirrored instead.
`task_kfunc_success.rs` declares its three bpf_task_acquire flavors so.

## kconfig externs

C's `extern int CONFIG_HZ __kconfig;` is a `.kconfig` extern: libbpf fills
it from the running kernel's config at load time (`LINUX_KERNEL_VERSION`,
`LINUX_HAS_SYSCALL_WRAPPER` and `LINUX_HAS_BPF_COOKIE` are virtual ones) and
the program reads it through a `.kconfig` map value. Declare it as a Rust
extern static and select it with `// BTF_KCONFIG: NAME`:

```rust
// BTF_KCONFIG: CONFIG_HZ
extern "C" {
    static CONFIG_HZ: u32;
}
let hz = unsafe { CONFIG_HZ };
```

`scripts/ksym_vars.py` mirrors the C object's `.kconfig` declaration (type
and weakness) onto the Rust extern as it does for `.ksyms`, so llc emits the
`VAR` with `linkage=extern` inside `DATASEC '.kconfig'` and the skeleton
gets its `kconfig` struct. libbpf accepts only `int`-sized integers, `bool`,
`char`, `char[]` and the `libbpf_tristate` enum; the Rust width must match
the C declaration (`unsigned long` -> `u64`, `_Bool` -> `u8`, `enum` ->
`i32`/`u32`, `char[N]` -> `[u8; N]`). A plain read is the C's load (a
declaration has no initializer to fold); write the branch the C writes
rather than hardcoding one arm, and compare like clang does (`== 1` where
the C object tests a `_Bool` against 1). A `__weak` extern stays a plain
Rust extern; the weakness comes from the C object. The `kconfig` translint
class checks that both objects declare the same externs with the same types;
a translation that declares none while the C object does gets a WARN,
silenced with `// translint: allow(kconfig)` plus the reason (e.g. the C
object's only readers are usdt.bpf.h library functions its programs never
call).

## Statically linked objects (extern variables, maps and functions)

Some C objects are halves of a multi-object skeleton: Makefile.skel's
`<skel>.skel.h-deps` lists them (linked_vars1/2, test_subskeleton and its
two libraries, test_usdt with test_usdt_multispec, ...) and bpftool's
static linker (libbpf's linker.c) merges them. Such a C file refers to the
other half's globals with plain externs; the translation declares them the
same way and selects each with `// BTF_EXTERN: NAME`:

```rust
// BTF_EXTERN: my_pid
// BTF_EXTERN: map2
// BTF_EXTERN: lib_routine
extern "C" {
    static my_pid: i32;
    static map2: BpfMap<u32, u32, { maps::HASH }, 16>;
    fn lib_routine() -> i32;
}
```

`scripts/ksym_vars.py` mirrors the C object's extern VAR or FUNC (type,
weakness, and the DATASEC the C keeps it in: `.maps` for an extern map,
`.addr_space.1` for an extern `__arena_global`, none for a plain variable
or function). The linker matches the extern against the definition it
resolves it with exactly (aggregates member by member, a map definition's
key and value types too, a pointer only by its pointee's kind and name),
so the mirrored types carry their members down to the first pointer,
including a named key or value struct, which the Rust side then defines
under the C's name (linked_maps1.rs). An extern function goes into the
`.extern` section libbpf's linker reserves for externs it resolves, which
also keeps rust-bpf's add_ksyms.py from declaring it a kfunc; the C's
`__hidden extern` function (one the kernel could not verify as a global
function, so libbpf makes it static after linking) adds
`core::arch::global_asm!(".hidden name")` (tracing_multi_attach.rs,
linked_funcs1.rs). Weak definitions (`__weak int x`) are
`#[linkage = "weak"]` statics (`#![feature(linkage)]`), weak functions
`#[linkage = "weak"]` functions; a weak global the C forces into `.data`
keeps `#[link_section = ".data"]`. An extern `__arena_global` is
dereferenced through the hand-encoded `cast_kern` like the object's own
(linked_arena1.rs).

The build gives a linked object the C object's ELF section flags
(`scripts/section_flags.py`, for every object in Makefile.skel's deps):
clang's `license` and `.maps` are writable sections, rustc's immutable
statics make them read-only, and the linker merges same-named sections
only with equal flags. A weak map both halves define (usdt.bpf.h's
`__bpf_usdt_specs`) is matched member by member down to its value struct,
so the Rust struct must carry the C's name and members; where the C has
bitfields or enum members, declare the C's members in the C's order with
the integers the code reads through, and add `// BTF_C_MEMBERS: name`:
`scripts/btf_c_members.py` gives the struct the C object's member BTF
(bitfield offsets and sizes, a copy of the enum). See test_usdt.rs.

The gate swaps one object at a time: `scripts/swap-and-test.sh` reads
Makefile.skel, regenerates every linked skeleton the object is a half of
(with the C other halves as installed) and runs the skeleton's consumer,
so each half has its own verdict. To test a pair of translations
together, install the other half with `SWAP_ONLY=1
scripts/swap-and-test.sh <other> rust`, run `make test-<main>`, then
`make restore-all` and `make restore-<main>` (restore-all puts the C
objects back but relinks nothing).

## Kernel type IDs and program load order

For C's `bpf_core_type_id_kernel(T)`, declare an `extern "C"` function
returning `u64` with no arguments and annotate its C type identity:

```rust
// BTF_TYPE_ID: tid_sock struct mptcp_sock
extern "C" {
    fn tid_sock() -> u64;
}
```

Use `unsafe { tid_sock() as u32 }` at the original type-ID use site.
`scripts/type_id.py` requires that the pristine C object has a
TYPE_ID_TARGET relocation for that exact kind/name, then lowers the call
to LLVM's `llvm.bpf.btf.type.id` intrinsic. libbpf resolves the emitted
CO-RE relocation at load time. Supported roots are `struct`, `union`,
`enum` (32-bit), `typedef`, and `int`; unsupported shapes fail the build.
Only type identity is imported from C, never program instructions or a
resolved kernel ID. Field accesses still use the Rust CO-RE paths below.
See `mptcp_subflow.rs` for `bpf_rdonly_cast` plus field relocations.

C's `bpf_obj_new(typeof(*n))` passes `bpf_core_type_id_local(T)`, the id of
the object's OWN struct. Declare it with `local`:

```rust
// BTF_TYPE_ID: node_data_id local struct node_data
extern "C" {
    fn node_data_id() -> u64;
}
let n = unsafe { bpf_obj_new(node_data_id()) } as *mut node_data;
```

The C object must carry a TYPE_ID_LOCAL relocation for that struct. The
lowered call points at rustc's own debug info for it, so llc emits the
struct with its real members, which the kernel reads to size and lay out
the allocation. Never hardcode the id. `normal_map_btf.rs` is the example.

When the consumer depends on program load order (libbpf stops at the first
rejection), add `// BPF_PROGRAM_ORDER: first_prog second_prog`.
`scripts/program_order.py` reorders whole LLVM definitions immediately
before code generation, preserving their bodies and debug info. List
every program in each selected section. `test_log_buf.rs` uses this to
load its valid program before its deliberately invalid one.

### Type existence, size, match and enum values

C's `bpf_core_type_exists(T)` / `bpf_core_type_size(T)` /
`bpf_core_type_matches(T)` are `// BTF_TYPE_INFO:` externs returning
`u32`, and `bpf_core_enum_value_exists(E, V)` / `bpf_core_enum_value(E, V)`
are `// BTF_ENUM_VALUE:` externs returning `u64`:

```rust
// BTF_TYPE_INFO: struct_sz size struct a_struct
// BTF_TYPE_INFO: typedef_func_proto_matches matches typedef func_proto_typedef
// BTF_ENUM_VALUE: named_val2_exists exists enum named_enum NAMED_ENUM_VAL2
// BTF_ENUM_VALUE: anon_val1 value typedef anon_enum ANON_ENUM_VAL1
extern "C" {
    fn struct_sz() -> u32;
    fn typedef_func_proto_matches() -> u32;
    fn named_val2_exists() -> u64;
    fn anon_val1() -> u64;
}
```

`scripts/type_id.py` lowers them to `llvm.bpf.preserve.type.info` /
`llvm.bpf.preserve.enum.value` (TYPE_EXISTS / TYPE_SIZE / TYPE_MATCHES /
ENUMVAL_EXISTS / ENUMVAL_VALUE relocations). libbpf answers these by
walking INTO the local type (member names, func-proto arity, enum
members), so unlike the shallow TYPE_ID descriptors the local type is a
full copy of the pristine C object's BTF type, which must carry a
relocation of the same kind on a type of that kind and name (and on that
enumerator). `enum` covers BTF ENUM64; a typedef'd anonymous enum is named
through its typedef. Compare the two objects' relocations with
`equiv/bpfcore.py core_relo_records` when in doubt.
`test_core_reloc_type_based.rs`, `test_core_reloc_enumval.rs` and
`core_kern.rs` are the examples; the prover's `--kernel-btf` option takes
a core_reloc test's own `btf__core_reloc_*.bpf.o` as the target.

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
- Negative verifier tests require `test_tags!` to preserve their rejection
  assertions; see "Test-loader expectations" below. Never change the body
  to make a must-fail program load successfully.
- `bpf_for(i, start, end)` is the open-coded `bpf_iter_num_*` loop whose
  condition also tests `i >= start && i < end` (that is what bounds the
  index for the verifier), and the iterator's `cleanup` attribute destroys
  it exactly once on every exit from the loop's scope: after a plain
  `break` or the last iteration, and before a `return` or a jump out of an
  enclosing block. Destroying it before a plain `break` as well is a
  second destroy, which the verifier rejects as an uninitialized iterator
  (`dynptr_success.rs` has the macro).
- A kfunc returning `bool` (`bpf_dynptr_is_null`, `bpf_dynptr_is_rdonly`)
  is tested on the low bit of its result, as clang does (`w0 &= 1`):
  declare it `-> u8` and compare `& 1`, not a Rust `bool`.

## Build & validate

```sh
make                     # bld/<name>.bpf.o  (compile gate)
FLAVOR=uml make verify   # kernel verifier gate (UML flavor only); skips __failure objects
make test-<name>         # swap in + kernel-Makefile skeleton regen +
                         # affected test_progs tests in the QEMU guest (oracle gate)
make restore-<name>      # reinstate the clang-built object
```

## Test-loader expectations (`__failure`, `__msg`, `__retval`, ...)

Many selftests carry their assertions IN THE OBJECT, as BTF decl tags the
kernel's `test_loader` reads off each program's FUNC: whether the program
must load, must be REJECTED, what the verifier log has to contain, what
`bpf_prog_test_run` must return. clang emits them from `bpf_misc.h`'s
`__failure` / `__msg(...)` / `__retval(...)` attributes; **rustc emits no
decl tags at all**, and a tag-less object makes the loader default to
expect-success — which silently inverts every negative test.

So mirror the C object's tags with `test_tags!`, which expands to nothing;
`scripts/btf_test_tags.py` appends the real DECL_TAGs to the built object:

```rust
use bpf_rs_core::test_tags;

test_tags! {
    global_func1: __failure, __msg("combined stack size of 3 calls is");
    other_prog:   __success, __retval(0);
}
```

Rules:

- **Copy the C object's tags, in order, one entry per program.** The C
  object is the ground truth; `translint.py` reads its BTF and errors on any
  divergence. A missing declaration where the C object says `__failure` is
  an error (the test inverts); a missing one for positive tags is a warning
  (the translation is simply tested more weakly).
- **A message may be relaxed only where the verifier log depends on
  register allocation** — register numbers, `fp-` slots, `off=`, insn
  indices — using the matcher's own regex brackets:
  `__msg("{{R[0-9]}} type=scalar expected=fp")`. Widening a wildcard past
  those tokens is an error; the rest of the message IS the assertion.
- **Arguments are written as the C macro expands them**, since bpf_misc.h
  stringizes after macro expansion: `__caps_unpriv("39|12")`, not
  `CAP_BPF|CAP_NET_ADMIN`. Comments belong outside the macro body.
- `make verify` skips objects declaring a privileged `__failure` — the
  verifier rejecting them is the assertion, not a regression. The prover
  says nothing meaningful about them either: both objects are rejected, so
  the load-time test is the whole oracle.

## Raw assembly and C character storage

For instruction-level tests whose complete function body is BPF assembly,
use an ordinary named Rust function with the real return type and one
`asm!(..., options(noreturn))` body. Put `// BPF_NAKED: function_name` on
its own line. `scripts/naked_abi.py` retains the debug signature, removes
Rust's unused hidden aggregate-return parameter, and emits LLVM's naked
form. It rejects bodies containing generated instructions or real arguments.
The assembly must include its own `exit` and supply every return register.
Use `sym` operands for calls so definitions survive optimization and receive
relocations. `aggregate_ret_target.rs` is the minimal example. A naked
function may declare the C's parameters (the BTF prototype keeps them)
as long as the asm never names them.

### Generated verifier_* translations

Most `verifier_*.c` selftests are nothing but `__naked` functions, so
`scripts/naked_gen.py <name>` writes the whole translation: it preprocesses
the C file with the selftests' own clang flags, resolves every `"i"`
operand the way clang does (by compiling a probe: a helper id becomes
`call 1`, a map, subprogram or kfunc address `sym`, a constant or an
encoded instruction its value), suffixes the `%=` labels with the
function name, and takes maps, globals, kfunc externs, the license and
the test_tags! from the C object's BTF and ELF, verbatim. Regenerate
such a file rather than editing it; `scripts/naked_gen.py --survey` says
which files the generator cannot do (a C body, a kfunc variable, ...)
and why. A file that mixes naked programs with a few C functions is
generated with `--with-c-bodies`: the generated file include!s
`progs/hand/<name>.rs`, written once with a stub and the C text for each
such function and never overwritten, where those bodies are translated by
hand (a function that only references kfuncs for their BTF prototypes,
`__kfunc_btf_root`, is generated regardless of its name). The hand file
can steer the generated one: `// GEN_SKIP_TYPE: name` keeps the
generator's copy of a type out (the hand file defines it, as a `#[btf]`
view, say); `// GEN_TAGS: name:` followed by `//     tag,` lines replaces
one program's test_tags! entry (the C object was built for one BPF CPU
version, and a test whose messages count instructions carries
`#if __BPF_CPU_VERSION__` branches), with the matching
`// translint: allow(test-tags:name)`; `// BTF_TYPE_ID:` and the other
marker lines, `// BPF_NAKED: name` (a hand file may carry a function
verbatim, like a subprogram returning an aggregate in R0:R2 that no Rust
call can consume; verifier_arena's arena_word_pair) and
`// translint: allow(...)` lines, are carried over to the generated file,
which is the one the scripts read; a type reached only through a skipped
one (the kernel structs behind a CO-RE view's pointer) is left out with it. A `.struct_ops`
map in the C becomes the Rust struct of the kernel type's name whose set
members carry the program's fn type and the unset ones are null
`*const c_void`, plus a `static mut` in that section. The `naked-verbatim` class of `scripts/translint.py`
(`scripts/naked_verbatim.py`) then checks every `// BPF_NAKED:` function
of the built object against the C object instruction by instruction,
relocation symbols included, which is the real assertion for a verbatim
translation: the prover only sees the programs that load.

C's `__kptr` (and `__kptr_untrusted`, `__percpu_kptr`, `__uptr`) is a BTF
type tag on a pointer, which rustc cannot emit. Declare the field as a
plain pointer and list it in `btf_type_tags!`; `scripts/btf_type_tags.py`
adds the tag to the built object. A struct member is named
`struct.member`, a global variable by its name alone, a function's
parameter or return type `fn.<index>` or `fn.ret` (C's
`u32 __arena *f(u32 __arena *p)`, the arena annotation the verifier reads
on a global subprogram's arguments and aggregate returns; the generator
writes these from the C object), and an array of pointers (of any depth)
is tagged like a single pointer:

```rust
btf_type_tags! {
    __cpumask_map_value.cpumask: kptr;   // map value member
    global_mask: kptr;                    // static struct bpf_cpumask __kptr *global_mask;
    global_mask_array_l2: kptr;           // ... __kptr *global_mask_array_l2[2][1];
}
```

A C `static` global in a `private(NAME)` section is a Rust `static mut`
with `#[link_section = ".bss.NAME"]` and no `#[no_mangle]`.
`scripts/private_sections.py` lays the section out as the C object has it
(same names at the same offsets), so a lock keeps the offset the verifier's
messages name ("bpf_spin_lock at off=32 must be held"). That layout is not
C's declaration order: clang emits the variables in the order the code
first refers to them (refcounted_kptr.c declares lock, root, head and gets
head 0, root 16, lock 32), so declaring them in the C object's order
(`llvm-readelf -s <name>.bpf.o`) keeps the source honest even though the
pass does not need it. translint's `private-layout` class compares the two
objects; it fails when a static is missing (rustc drops an unreferenced
private static, see linked_list.rs's glock2), has another size or is more
aligned than C's. A plain section can be laid out the C way too, with
`// C_LAYOUT: .data .bss` in the translation: rustc orders those statics by
symbol name, and data_in_arena's harness compares the skeleton's `struct
data` with the section (`bpf_map__initial_value()`'s size against
`sizeof(*skel->data)`), which needs clang's order and a section that ends
8-byte aligned; translint then compares those sections as well. `.rodata`
works the same (strncmp_test: the verifier accepts a bpf_strncmp target
only when a NUL follows it before the end of .rodata, so the target
without one must be last, as in the C object), for statics placed by
their kind and for ones that already say `#[link_section = ".rodata"]`. With the tags
in place, `bpf_kptr_xchg` into the field loads as it does for the C
object, so translate the kptr round trip as written; do not replace it
with a release of the local pointer. `cpumask_success.rs` has every form.

`btf_type_tags!` also supports `arena` on pointer members and arrays of
pointers, including void pointees. This preserves the aggregate-return
types exercised by `aggregate_ret_func.rs`.

Other C decl tags come from rust-bpf's `#[btf_tag(decl_tag = "...")]`
(4ast/rust-bpf#6), on a static, a struct field, or a function. The ones the
kernel acts on are `__contains(type, field)` on a `bpf_rb_root` /
`bpf_list_head` and `__exception_cb(cb)` on a program:

```rust
use btf_macros::btf_tag;

#[btf_tag]
#[repr(C)]
struct map_value {
    #[btf_tag(decl_tag = "contains:node_data:node")]
    head: bpf_list_head,
    lock: bpf_spin_lock,
}

#[btf_tag(decl_tag = "contains:node_data:node")]
#[link_section = ".data.A"]
static mut groot: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

#[btf_tag(decl_tag = "exception_callback:exception_cb")]
#[link_section = "?freplace"]
#[no_mangle]
extern "C" fn throwing_extension(_ctx: *const __sk_buff) -> i32 { ... }
```

translint's `decl-tags` class compares these with the C object's: a
missing `contains:` or `exception_callback:` is an error.

A tagged `private(A)` root or head stays a private static (no
`#[no_mangle]`, as above): the tag targets the debug-info name, which a
private static keeps. C's `__hidden` makes the variable BTF_VAR_STATIC, so
libbpf does not mmap `.data.A`; a `#[no_mangle]` static is a global
variable instead, and once the kernel accepts the graph-root record the
mmap of a map holding a `bpf_list_head`/`bpf_rb_root` fails with
-ENOTSUPP at load (`test_spin_lock.rs` explains the `__hidden` rule).
`bpf_rbtree_add` returns `int` in the kernel; declare it `-> i32`.

When the C consumer requires a plain `char` array (for example a string
assertion compiled with `-Werror=pointer-sign`), declare byte storage with
`u8` and add `// BTF_C_CHAR: u8` on its own line. The BTF normalizer then
names that object's `u8` type `char` with the pinned x86 C signed-char
encoding. This applies to all `u8` uses in the object, so use it only when
that matches the object's C ABI. It does not change storage or code.
For a C anonymous struct stored in a global, declare its Rust layout and
add `// BTF_ANON: RustTypeName`. This removes only the BTF struct's name so
the generated skeleton embeds its definition instead of referring to an
undefined named C type. Members, offsets and references stay unchanged.

For a C incomplete type (`struct S;`, a BTF FWD) declare an `extern type`
(`#![feature(extern_types)]`, `extern "C" { type S; }`) and add
`// BTF_FWD: S`. rustc emits the extern type as a memberless STRUCT of size
0; the normalizer rewrites that type's kind to FWD in place (a union's
kind flag included). A verifier message that names the kind, such as
`test_global_func14`'s "reference type('FWD S') size cannot be
determined", needs this; a type the program only points at does not.

For C `void *` globals, use a `*mut c_void` declaration and add
`// BTF_C_VOID: c_void`. Rust emits `c_void` as an enum; the annotation
repoints pointers to that enum to BTF type ID zero (void), allowing the
generated C skeleton to accept arbitrary pointer values. Other pointers
and uses of the enum by value are unchanged. Use this only when every
pointer to `c_void` in the object represents C `void *`.

## Divergence classes the equivalence prover has caught (lint before submitting)

`python3 scripts/translint.py <name>` checks a translation mechanically;
`.venv/bin/python equiv/guard.py <name>` (any Python with `requirements.txt`) re-proves it after a rebuild
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
