#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of
// tools/testing/selftests/bpf/progs/tailcall_bpf2bpf_hierarchy3.c
// (bpf-rs-core idiom).
//
// jmp_table0/jmp_table1 statically pre-populate their single prog-array slot
// via a designated initializer on a flexible array member
// (`__array(values, void (void))`, `.values = { [0] = (void *)&classifier_0 }`).
// This is the same shape confirmed unfixable in progs/test_prog_array_init.rs
// and progs/epilogue_tailcall.rs: libbpf's parse_btf_map_def requires the
// "values" field's BTF ARRAY type to have nr_elems==0, but the real slot
// storage in the C object comes from Clang widening the LLVM IR global's
// *codegen* type past its debuginfo type -- a frontend-only divergence with
// no rustc equivalent (a Rust static's IR type and DIType always come from
// the same declaration). A `[ClassifierFn; 1]` field round-trips as
// nr_elems=1 and libbpf rejects the map outright; `[ClassifierFn; 0]`
// satisfies nr_elems==0 and loads, but is then genuinely 0 bytes, leaving no
// room for a relocation to classifier_0, so both maps load with slot 0
// permanently empty -- confirmed by `llvm-readelf -r`: no `.rel.maps`
// section exists in the built object at all.
//
// This does NOT surface as a test failure here, though: `__success`/
// `__retval(33)` are BTF decl tags (`btf_decl_tag("comment:...")`), which
// rustc cannot emit (see TRANSLATING.md's `__failure`/`__msg` note -- the
// same limitation applies to every `bpf_misc.h` decl-tag annotation, not
// just negative-test ones). test_loader.c's `should_do_test_run()` only
// runs `bpf_prog_test_run_opts()`/checks retval when a `test_retval=` tag
// was actually parsed (see `spec->priv.execute = true` in the
// `test_retval=` branch of `parse_test_spec`); with no decl tags at all,
// `execute` stays false and the retval assertion is skipped entirely --
// `make test-tailcall_bpf2bpf_hierarchy3` only exercises "does classifier_0
// / tailcall_bpf2bpf_hierarchy_3 load", which succeeds regardless of the
// prog-array populate bug above. So the tail-call chaining logic below is
// never actually exercised; it exists to keep the translation's shape
// (and BTF/keep-list ABI) matching the C original as closely as possible.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::{bpf_object, maps};
use core::ffi::c_void;

#[no_mangle]
static mut count: i32 = 0;

// A zero-insn `sink_val`-style barrier collapses its .BTF.ext line_info
// onto the next real insn's offset and the kernel rejects the duplicate
// entry ("Invalid line_info[N].insn_off"); self-move (as `helpers::sink`
// does for pointers) emits exactly one real insn instead.
#[inline(always)]
fn barrier_i32(mut v: i32) -> i32 {
    unsafe {
        core::arch::asm!("{0} = {0}", inout(reg) v, options(nostack, preserves_flags));
    }
    v
}

#[inline(never)]
fn subprog_tail<M>(skb: *const __sk_buff, jmp_table: *const M) -> i32 {
    let ret: i32 = 0;
    bpf_tail_call(skb as *const c_void, jmp_table, 0);
    barrier_i32(ret)
}

type ClassifierFn = extern "C" fn(*const __sk_buff) -> i32;

#[repr(C)]
struct jmp_table0 {
    r#type: *const [i32; maps::PROG_ARRAY],
    max_entries: *const [i32; 1],
    key_size: *const [i32; 4],
    values: [ClassifierFn; 0],
}
unsafe impl Sync for jmp_table0 {}

#[link_section = ".maps"]
#[no_mangle]
static jmp_table0: jmp_table0 = jmp_table0 {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [],
};

#[repr(C)]
struct jmp_table1 {
    r#type: *const [i32; maps::PROG_ARRAY],
    max_entries: *const [i32; 1],
    key_size: *const [i32; 4],
    values: [ClassifierFn; 0],
}
unsafe impl Sync for jmp_table1 {}

#[link_section = ".maps"]
#[no_mangle]
static jmp_table1: jmp_table1 = jmp_table1 {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [],
};

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_0(skb: *const __sk_buff) -> i32 {
    unsafe { count += 1 };
    subprog_tail(skb, &jmp_table0);
    subprog_tail(skb, &jmp_table1);
    unsafe { count }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tailcall_bpf2bpf_hierarchy_3(skb: *const __sk_buff) -> i32 {
    let ret: i32 = 0;
    bpf_tail_call(skb as *const c_void, &jmp_table0, 0);
    barrier_i32(ret)
}

bpf_object!("GPL");
