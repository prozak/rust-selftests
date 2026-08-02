#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/kptr_xchg_inline.c
// (bpf-rs-core idiom).
//
// The C original hand-writes the body as `__naked` inline asm
// (r1 = &ptr ll; r2 = 0; call bpf_kptr_xchg; ...) purely to pin the exact
// instruction layout the userspace test inspects post-verifier-inlining
// (test_kptr_xchg_inline in prog_tests/kptr_xchg_inline.c memcmp's
// insn[3]/insn[4] of the *translated* program against a `mov r0,r2` +
// `atomic64_xchg` pair). That instruction-shape check is moot here: `ptr`
// is `struct bin_data __kptr * ptr` in C -- a global whose `__kptr` BTF
// type tag (`__attribute__((btf_type_tag("kptr")))`) is what makes the
// kernel's btf_find_kptr() classify this .bss slot as a referenced-kptr
// field at all. rustc has no mechanism to emit BTF_KIND_TYPE_TAG (Clang
// CodeGen-only debuginfo, consumed by LLVM's BPF BTF pass); without it the
// verifier's bpf_kptr_xchg() argument check never recognizes `ptr` as a
// kptr slot and the call is rejected outright, so open_and_load() itself
// fails before the xlated-instruction check ever runs. Kept as a plain
// (non-naked) safe-equivalent translation for structural/BTF-shape
// fidelity; see bpf_kptr_xchg's doc comment in bpf-rs-core/src/helpers.rs.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_kptr_xchg;
use core::ffi::c_void;
use core::ptr::addr_of_mut;

#[repr(C)]
struct bin_data {
    blob: [u8; 32],
}

#[link_section = ".bss.kptr"]
#[no_mangle]
static mut ptr: *mut bin_data = core::ptr::null_mut();

extern "C" {
    fn bpf_obj_drop(obj: *mut c_void);
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kptr_xchg_inline(_skb: *const __sk_buff) -> i32 {
    let old = bpf_kptr_xchg(
        unsafe { addr_of_mut!(ptr) as *mut c_void },
        core::ptr::null_mut(),
    );
    if !old.is_null() {
        unsafe { bpf_obj_drop(old) };
    }
    0
}

bpf_object!("GPL");
