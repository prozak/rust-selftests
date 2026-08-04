#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/stream.c
// (bpf-rs-core idiom).
//
// prog_tests/stream.c drives this object three ways:
//  - test_stream_success() -> RUN_TESTS(stream): per-program isolated load
//    (test_loader.c). Since rustc can't emit BTF_KIND_DECL_TAG, none of the
//    __success/__retval/__stderr/__stdout decl tags on the C source parse;
//    parse_test_spec() finds zero tags, mode_mask defaults to PRIV with
//    expect_failure=false and execute=false (see
//    [[negative-verifier-tests-need-loadable-translation]] for the general
//    shape of this default). So every program below just needs to load
//    (pass the verifier) under RUN_TESTS - no actual execution/output is
//    checked there.
//  - test_stream_syscall() and test_stream_arena_fault_address() instead
//    call stream__open_and_load() directly (the *whole* object, every
//    program autoloaded together) and then bpf_prog_test_run_opts +
//    bpf_prog_stream_read on specific programs (stream_syscall,
//    stream_arena_read_fault, stream_arena_write_fault), asserting real
//    retval/stdout/stderr content. Those three programs' behavior must
//    match the C original exactly; everything else just needs to load
//    alongside them in the same object.
//
// bpf_stream_vprintk/bpf_stream_print_stack are KF_IMPLICIT_ARGS kfuncs
// (kernel/bpf/stream.c, kernel/bpf/helpers.c): the verifier auto-appends
// the trailing `struct bpf_prog_aux *aux` argument, so the call-site
// signature (and the C headers, which declare neither - bpf_helpers.h's
// bpf_stream_printk() macro calls bpf_stream_vprintk with an implicit,
// undeclared prototype) omits it.
//
// The arena fault programs reuse the exact hand-encoded-instruction
// techniques already proven on arena_atomics.rs/verifier_arena_globals2.rs:
//  - `cast_kern`: BPF_ADDR_SPACE_CAST(dst_as=0,src_as=1) via inline asm
//    (upstream's bpf_addr_space_cast() macro's own workaround for
//    compilers lacking the feature). Confirmed via
//    `llvm-objdump -d stream.bpf.o` that the pristine clang object emits
//    this *exact* instruction (`bf 11 01 00 01 00 00 00`) both for
//    `bpf_addr_space_cast(user_vm_start, 0, 1)` (arena_write_fault/
//    arena_read_fault) and for the compile-time-constant
//    `(int __arena *)0xdeadbeef` (subprog/timer_cb) - same direction,
//    same bytes, reused verbatim by both.
//  - `arena_base_ldx`: single BPF_LDX|BPF_MEM|BPF_DW with the field's byte
//    offset baked into the insn (no separate pointer-arithmetic ALU op),
//    the only shape check_ptr_to_map_access() in the verifier permits for
//    a CONST_PTR_TO_MAP register - reads `((struct bpf_arena *)&arena)->
//    user_vm_start` (offset 280, confirmed via bpftool btf dump).
// The actual page fault (kernel/bpf/arena.c's bpf_arena_handle_page_fault)
// is real VMA fault-handling triggered by any out-of-range access through
// a properly arena-cast pointer - not tied to the raw-asm store/load shape
// the C source happens to use - so plain volatile read/write through the
// cast pointer reproduces it faithfully.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_spin_lock, bpf_spin_unlock, bpf_timer_init, bpf_timer_set_callback,
    bpf_timer_start,
};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

const BPF_STDOUT: i32 = 1;
const BPF_STDERR: i32 = 2;
const ENOSPC: i32 = 28;
const BPF_MAX_LOOPS: i32 = 8 * 1024 * 1024;
// byte offset of `struct bpf_arena.user_vm_start` in *this* kernel build's
// vmlinux BTF (`bpftool btf dump file vmlinux -j`: bits_offset=3904 / 8 =
// 488) - NOT the 280 verifier_arena_globals2.rs's memory note recorded for
// a different lane's kernel build; struct bpf_arena's layout isn't ABI, so
// this offset must be re-checked per kernel checkout, not copied.
const USER_VM_START_OFFSET: i16 = 488;

// #define _STR "xxx...53 x's" (54 chars, no macro-level global - a literal
// string constant materialized locally wherever the C source used it).
const STR_LEN: usize = 54;
const STR: [u8; STR_LEN + 1] = *b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\0";

// struct bpf_res_spin_lock { u32 val; } __aligned(alignof(struct rqspinlock))
// (asm-generic/rqspinlock.h) - matched by BTF struct name in
// btf_get_field_type() (kernel/bpf/btf.c), same rule as bpf_spin_lock/
// bpf_timer. alignof(rqspinlock) == alignof(u32) == 4, already the natural
// alignment of a lone u32 field.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_res_spin_lock {
    val: u32,
}

// struct bpf_spin_lock { __u32 val; } (UAPI linux/bpf.h) - matched by name.
// Same identifier as the `bpf_spin_lock` helper fn imported above: distinct
// Rust namespaces (type vs value), same pattern as test_spin_lock.rs.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: i32,
}

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8))) -
// matched by name, same shape as free_timer.rs/wq.rs.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct arr_elem {
    lock: bpf_res_spin_lock,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct elem {
    timer: bpf_timer,
}

#[link_section = ".maps"]
#[no_mangle]
static arrmap: BpfMap<i32, arr_elem, { maps::ARRAY }, 1> = BpfMap::new();

bpf_map! {
    arena {
        r#type: *const [i32; 33],       // BPF_MAP_TYPE_ARENA
        map_flags: *const [i32; 1024],  // BPF_F_MMAPABLE
        max_entries: *const [i32; 1],   // number of pages
    }
}

#[link_section = ".maps"]
#[no_mangle]
static array: BpfMap<i32, elem, { maps::ARRAY }, 1> = BpfMap::new();

// int size; -> .bss
#[no_mangle]
static mut size: i32 = 0;
// u64 fault_addr; -> .bss. `u64` in vmlinux.h/kernel BTF is `unsigned long`
// (not `unsigned long long`) on 64-bit - btf_rename.py maps Rust `usize` to
// that C spelling (see [[c-long-globals-need-isize]]), which is what the
// regenerated skeleton's `unsigned long *fault_addr_p` parameter requires.
#[no_mangle]
static mut fault_addr: usize = 0;
// void *arena_ptr; -> .bss
#[no_mangle]
static mut arena_ptr: *mut c_void = core::ptr::null_mut();

// private(STREAM) struct bpf_spin_lock block; ==
// SEC(".bss.STREAM") __hidden __attribute__((aligned(8))) - __hidden has no
// ELF-visibility equivalent in Rust (see
// [[rust-no-elf-visibility-use-private-static]]); `block` is never touched
// from prog_tests/stream.c, so a plain private static in the same section
// reaches the closest equivalent (natural internal linkage).
#[link_section = ".bss.STREAM"]
static mut block: bpf_spin_lock = bpf_spin_lock { val: 0 };

extern "C" {
    fn bpf_stream_vprintk(stream_id: i32, fmt: *const u8, args: *const c_void, len: u32) -> i32;
    fn bpf_stream_print_stack(stream_id: i32) -> i32;
    fn bpf_res_spin_lock(lock: *mut bpf_res_spin_lock) -> i32;
    fn bpf_res_spin_unlock(lock: *mut bpf_res_spin_lock);
}

/// `bpf_stream_printk(stream_id, fmt)` with zero varargs: the C macro's
/// `___param` is a real (if zero-length) stack array, so its address is a
/// valid non-null PTR_TO_STACK; a literal null constant for `args` gets
/// rejected by the verifier ("Possibly NULL pointer passed to trusted R3")
/// even though `len == 0` means the kfunc never dereferences it. Route
/// every no-varargs call site through one stack slot instead.
#[inline(always)]
unsafe fn stream_printk0(stream_id: i32, fmt: *const u8) -> i32 {
    let no_args: u64 = 0;
    bpf_stream_vprintk(stream_id, fmt, core::ptr::addr_of!(no_args) as *const c_void, 0)
}

#[repr(C)]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

extern "C" {
    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32) -> i32;
    fn bpf_iter_num_next(it: *mut bpf_iter_num) -> *mut i32;
    fn bpf_iter_num_destroy(it: *mut bpf_iter_num);
}

/// `bpf_addr_space_cast(ptr, 0, 1)`: converts an arena-relative address
/// (address space 1) into the kernel-usable pointer (address space 0) the
/// verifier/JIT type as PTR_TO_ARENA - same in-place register encoding as
/// arena_atomics.rs's `cast_kern` (confirmed byte-identical against this
/// object's own disassembly, see module doc comment above).
#[inline(always)]
unsafe fn cast_kern<T>(p: *mut T) -> *mut T {
    let mut p = p;
    core::arch::asm!(
        ".byte 0xBF",
        ".ifc {0}, r0", ".byte 0x00", ".endif",
        ".ifc {0}, r1", ".byte 0x11", ".endif",
        ".ifc {0}, r2", ".byte 0x22", ".endif",
        ".ifc {0}, r3", ".byte 0x33", ".endif",
        ".ifc {0}, r4", ".byte 0x44", ".endif",
        ".ifc {0}, r5", ".byte 0x55", ".endif",
        ".ifc {0}, r6", ".byte 0x66", ".endif",
        ".ifc {0}, r7", ".byte 0x77", ".endif",
        ".ifc {0}, r8", ".byte 0x88", ".endif",
        ".ifc {0}, r9", ".byte 0x99", ".endif",
        ".short 1",
        ".long 1",
        inout(reg) p,
        options(nostack, preserves_flags),
    );
    p
}

/// In-place `r = *(u64 *)(r + USER_VM_START_OFFSET)`: single
/// BPF_LDX|BPF_MEM|BPF_DW insn, offset baked in (no separate ALU op) -
/// the only shape the verifier permits for a CONST_PTR_TO_MAP register.
/// Reads `((struct bpf_arena *)&arena)->user_vm_start`, matching the C
/// source's `barrier_var(ptr); user_vm_start = ptr->user_vm_start;`.
#[inline(always)]
unsafe fn arena_base_ldx(map: u64) -> u64 {
    let mut p = map;
    core::arch::asm!(
        ".byte 0x79",
        ".ifc {0}, r0", ".byte 0x00", ".endif",
        ".ifc {0}, r1", ".byte 0x11", ".endif",
        ".ifc {0}, r2", ".byte 0x22", ".endif",
        ".ifc {0}, r3", ".byte 0x33", ".endif",
        ".ifc {0}, r4", ".byte 0x44", ".endif",
        ".ifc {0}, r5", ".byte 0x55", ".endif",
        ".ifc {0}, r6", ".byte 0x66", ".endif",
        ".ifc {0}, r7", ".byte 0x77", ".endif",
        ".ifc {0}, r8", ".byte 0x88", ".endif",
        ".ifc {0}, r9", ".byte 0x99", ".endif",
        ".short {off}",
        ".long 0",
        inout(reg) p,
        off = const USER_VM_START_OFFSET,
        options(nostack, preserves_flags),
    );
    p
}

/// bpf_may_goto.h's `can_loop` (non-`__BPF_FEATURE_MAY_GOTO` hand-encoding,
/// same trick as arena_strsearch.rs's `should_break`): a real `may_goto`
/// (BPF_JMP|BPF_JCOND, opcode 0xe5) instruction. Returns `true` once the
/// budget it guards is exhausted, i.e. the call site should stop looping -
/// the logical negation of `can_loop`.
#[inline(always)]
unsafe fn should_break() -> bool {
    let mut r: u64 = 0;
    core::arch::asm!(
        "1:",
        ".byte 0xe5",
        ".byte 0",
        ".long ((2f - 1b - 8) / 8) & 0xffff",
        ".short 0",
        "goto 3f",
        "2:",
        "{r} = 1",
        "3:",
        r = inout(reg) r,
        options(nostack, preserves_flags),
    );
    r != 0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stream_exhaust(_ctx: *const c_void) -> i32 {
    unsafe {
        size = 0;
    }
    let mut it = bpf_iter_num { __opaque: [0; 1] };
    unsafe { bpf_iter_num_new(&mut it, 0, BPF_MAX_LOOPS) };
    let mut ret: i32 = 1;
    loop {
        let v = unsafe { bpf_iter_num_next(&mut it) };
        if v.is_null() {
            break;
        }
        let r = unsafe { stream_printk0(BPF_STDOUT, STR.as_ptr()) };
        if r == -ENOSPC && unsafe { size } == 99954 {
            ret = 0;
            break;
        }
        unsafe {
            size += STR_LEN as i32;
        }
    }
    unsafe { bpf_iter_num_destroy(&mut it) };
    ret
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stream_cond_break(_ctx: *const c_void) -> i32 {
    while unsafe { !should_break() } {}
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stream_deadlock(_ctx: *const c_void) -> i32 {
    let key: i32 = 0;
    let lock = bpf_map_lookup_elem(&arrmap, &key) as *mut arr_elem;
    if lock.is_null() {
        return 1;
    }
    let nlock = bpf_map_lookup_elem(&arrmap, &key) as *mut arr_elem;
    if nlock.is_null() {
        return 1;
    }
    unsafe {
        if bpf_res_spin_lock(core::ptr::addr_of_mut!((*lock).lock)) != 0 {
            return 1;
        }
        if bpf_res_spin_lock(core::ptr::addr_of_mut!((*nlock).lock)) != 0 {
            bpf_res_spin_unlock(core::ptr::addr_of_mut!((*lock).lock));
            return 0;
        }
        bpf_res_spin_unlock(core::ptr::addr_of_mut!((*nlock).lock));
        bpf_res_spin_unlock(core::ptr::addr_of_mut!((*lock).lock));
    }
    1
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stream_syscall(_ctx: *const c_void) -> i32 {
    const FOO: [u8; 4] = *b"foo\0";
    unsafe {
        stream_printk0(BPF_STDOUT, FOO.as_ptr());
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stream_arena_write_fault(_ctx: *const c_void) -> i32 {
    unsafe {
        let map_addr = core::ptr::addr_of!(arena) as u64;
        let user_vm_start = arena_base_ldx(map_addr);
        fault_addr = (user_vm_start + 0x7fff) as usize;

        let kptr = cast_kern(user_vm_start as *mut u8);
        let target = kptr.add(0x7fff) as *mut u32;
        core::ptr::write_volatile(target, 1);
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stream_arena_read_fault(_ctx: *const c_void) -> i32 {
    unsafe {
        let map_addr = core::ptr::addr_of!(arena) as u64;
        let user_vm_start = arena_base_ldx(map_addr);
        fault_addr = (user_vm_start + 0x7fff) as usize;

        let kptr = cast_kern(user_vm_start as *mut u8);
        let target = kptr.add(0x7fff) as *mut u32;
        core::ptr::read_volatile(target);
    }
    0
}

#[inline(never)]
unsafe fn subprog() {
    arena_ptr = core::ptr::addr_of!(arena) as *mut c_void;
    let addr = cast_kern(0xdeadbeef_usize as *mut u32);
    core::ptr::write_volatile(addr, 1);
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stream_arena_subprog_fault(_ctx: *const c_void) -> i32 {
    unsafe {
        subprog();
    }
    0
}

extern "C" fn timer_cb(_map: *mut c_void, _key: *mut i32, _timer: *mut bpf_timer) -> i64 {
    unsafe {
        arena_ptr = core::ptr::addr_of!(arena) as *mut c_void;
        let addr = cast_kern(0xdeadbeef_usize as *mut u32);
        core::ptr::write_volatile(addr, 1);
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stream_arena_callback_fault(_ctx: *const c_void) -> i32 {
    let key: i32 = 0;
    let arr_timer = bpf_map_lookup_elem(&array, &key) as *mut elem;
    if arr_timer.is_null() {
        return 0;
    }
    unsafe {
        bpf_timer_init(core::ptr::addr_of_mut!((*arr_timer).timer), &array, 1);
        bpf_timer_set_callback(core::ptr::addr_of_mut!((*arr_timer).timer), timer_cb);
        bpf_timer_start(core::ptr::addr_of_mut!((*arr_timer).timer), 0, 0);
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stream_print_stack_kfunc(_ctx: *const c_void) -> i32 {
    unsafe { bpf_stream_print_stack(BPF_STDERR) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stream_print_stack_invalid_id(_ctx: *const c_void) -> i32 {
    unsafe { bpf_stream_print_stack(0x0badcafe_i32) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stream_print_kfuncs_locked(_ctx: *const c_void) -> i32 {
    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!(block));

        let mut ret = stream_printk0(BPF_STDOUT, STR.as_ptr());
        if ret == 0 {
            ret = bpf_stream_print_stack(BPF_STDERR);
        }

        bpf_spin_unlock(core::ptr::addr_of_mut!(block));
        ret
    }
}

bpf_object!("GPL");
