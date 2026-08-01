# Translating a BPF selftest C program to Rust (rust2bpf idiom)

Rules for translating `tools/testing/selftests/bpf/progs/<name>.c` to
`progs/<name>.rs` in this repo. The Rust is compiled **directly to BPF by
upstream rustc/LLVM** — there is NO aya, NO libbpf-rs, NO bpf crate. Every
kernel-facing construct is expressed with core Rust + `#[link_section]` +
BTF emitted from debuginfo. The compiled object must be a drop-in
replacement for the clang-built one: same section names, same global
symbol names/types, same BTF shape — the kernel's unmodified test harness
(skeletons, prog_tests) is the acceptance oracle.

## Crate skeleton

```rust
#![no_std]
#![no_main]

// ... programs ...

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";   // size = strlen + NUL, match C

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
```

Panics must be unreachable (no unwrap/indexing that can panic); the loop{}
handler is dead code removed by DCE. Edition 2021, builds as rlib.

## Programs

One `extern "C" fn` per BPF program:

```rust
#[link_section = "<same SEC() string as the C source>"]
#[no_mangle]
extern "C" fn <same_function_name_as_C>(ctx: *const CTX) -> i32 { ... 0 }
```

- Function name and section string must match the C source exactly.
- tracing programs (fentry/fexit/tp_btf/...): ctx is `*const u64`, one slot
  per target-function argument. `unsafe { *ctx.add(i) }` reads arg i;
  truncate with `as i32` / `as i8` etc. to the target arg's C type (this is
  what C's BPF_PROG macro does).
- tracepoint ("tp/..."): ctx points at the tracepoint record; if the body
  never dereferences it use `*const core::ffi::c_void`.
- tc/XDP/socket: ctx is a pointer to the UAPI context struct. Declare the
  needed prefix of it yourself, `#[repr(C)]`, and — CRITICAL — give it the
  exact C name (`__sk_buff`, `xdp_md`, ...) with
  `#[allow(non_camel_case_types)]`. The kernel matches BTF struct types BY
  NAME for freplace/fexit attach compatibility; a differently-named struct
  loads but breaks C extension programs attaching to yours.
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

Same names, same types, same zero/nonzero init (nonzero => .data). Access
with `unsafe { test1_result = ... }`. Do NOT invent extra global statics:
some harnesses iterate the whole bss section and assert every slot.

Read-only config globals (`const volatile` in C) go to .rodata:
`#[link_section = ".rodata"] #[no_mangle] static tgt_pid: u32 = 0;` and are
read with `core::ptr::read_volatile` (prevents constant folding — the
loader patches the value before load).

## Maps

libbpf reads map definitions purely from BTF: a VAR in DATASEC ".maps"
whose struct type encodes parameters as pointer members. C's
`__uint(type, V)` becomes `*const [i32; V]`; `__type(key, T)` becomes
`*const T`. Example — translation of:

```c
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 2);
         __type(key, __u64); __type(value, __u64); } hash_map SEC(".maps");
```

```rust
#[allow(non_camel_case_types)]
#[repr(C)]
struct hash_map_def {
    r#type: *const [i32; 1],      // BPF_MAP_TYPE_HASH = 1
    max_entries: *const [i32; 2],
    key: *const u64,
    value: *const u64,
}
unsafe impl Sync for hash_map_def {}

#[link_section = ".maps"]
#[no_mangle]
static hash_map: hash_map_def = hash_map_def {
    r#type: core::ptr::null(), max_entries: core::ptr::null(),
    key: core::ptr::null(), value: core::ptr::null(),
};
```

Map type values (enum bpf_map_type): HASH=1 ARRAY=2 PROG_ARRAY=3
PERF_EVENT_ARRAY=4 PERCPU_HASH=5 PERCPU_ARRAY=6 STACK_TRACE=7 ...
RINGBUF=27. Other C map attrs map the same way: `__uint(key_size, N)` ->
`key_size: *const [i32; N]`, `__uint(map_flags, F)` -> `map_flags:
*const [i32; F]`.

## Helper calls

Like C's bpf_helpers.h: call through a fn pointer whose value is the
helper ID constant; LLVM folds it into the direct BPF helper-call insn.

```rust
#[inline(always)]
fn bpf_get_current_pid_tgid() -> u64 {
    let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(14usize) };
    f()
}
```

Common helper IDs: map_lookup_elem=1 map_update_elem=2 map_delete_elem=3
probe_read=4 ktime_get_ns=5 trace_printk=6 get_prandom_u32=7
get_smp_processor_id=8 tail_call=12 get_current_pid_tgid=14
get_current_uid_gid=15 get_current_comm=16 perf_event_output=25
probe_read_str=45 probe_read_user=112 probe_read_kernel=113
probe_read_user_str=114 probe_read_kernel_str=115 ringbuf_output=130
ringbuf_reserve=131 ringbuf_submit=132 ringbuf_discard=133
ktime_get_boot_ns=125. (Full list: include/uapi/linux/bpf.h FN macros.)

Map-helper signatures take `*const <map_def_struct>` as the map argument
and `*const c_void` key/value pointers; lookup returns `*mut c_void`
(check for null!).

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

## Things that break and why

- Wrong int types in comparisons: C promotes/truncates implicitly; be
  explicit with `as` casts, matching C semantics bit-for-bit.
- LLVM merging loads the C kept separate: use `core::ptr::read_volatile`
  wherever C used `volatile`.
- Reachable panics (slice indexing, unwrap): verifier sees the loop{} —
  rejected. Use get()/pointer arithmetic.
- Extra/missing global symbols vs the C object: the build derives the
  internalize keep-list from the C object's global FUNC/OBJECT symbols;
  your Rust must define all of them with matching names.
- Never name a helper wrapper the same as a real kfunc/extern unless you
  mean a relocated call.

## Build & validate

```sh
make                     # bld/<name>.bpf.o  (compile gate)
make verify              # kernel verifier gate for all objects (UML)
make test-<name>         # swap in + kernel-Makefile skeleton regen +
                         # affected test_progs tests in UML (oracle gate)
make restore-<name>      # reinstate the clang-built object
```
