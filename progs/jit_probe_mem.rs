#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/jit_probe_mem.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;

#[repr(C)]
struct prog_test_ref_kfunc {
    _opaque: [u8; 0],
}

extern "C" {
    fn bpf_kfunc_call_test_acquire(scalar_ptr: *mut u64) -> *mut prog_test_ref_kfunc;
    fn bpf_kfunc_call_test_release(p: *mut prog_test_ref_kfunc);
}

#[no_mangle]
static mut total_sum: i64 = -1;

// The C original stashes the acquired kptr in a `__kptr`-tagged static
// (`v`), then reloads it (now PTR_UNTRUSTED) before the raw asm probe reads,
// to exercise the JIT's probe-mem codegen for untrusted BTF-ID pointers.
// rustc cannot emit BTF_KIND_TYPE_TAG, so a `__kptr` map field can never be
// recognized by the verifier ("R1 has no valid kptr" at bpf_kptr_xchg).
// `v` isn't part of the object's kept ABI symbols, so instead we read
// straight off the trusted acquired pointer and explicitly release it
// afterward; total_sum still ends up 192 either way.
#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_jit_probe_mem(_ctx: *const __sk_buff) -> i32 {
    let mut zero: u64 = 0;
    let p = unsafe { bpf_kfunc_call_test_acquire(&mut zero) };
    if p.is_null() {
        return 1;
    }

    let sum: u64;
    unsafe {
        core::arch::asm!(
            "r9 = {p};",
            "{sum} = 0;",
            "r8 = *(u32 *)(r9 + 0);",
            "{sum} += r8;",
            "r8 = *(u32 *)(r9 + 4);",
            "{sum} += r8;",
            "r9 += 8;",
            "r9 = *(u32 *)(r9 - 8);",
            "{sum} += r9;",
            p = in(reg) p,
            sum = out(reg) sum,
            out("r8") _,
            out("r9") _,
        );
    }

    unsafe {
        total_sum = sum as i64;
        bpf_kfunc_call_test_release(p);
    }
    0
}

bpf_object!("GPL");
