#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/verifier_mtu.c
// (bpf-rs-core idiom). A single verifier test: bpf_check_mtu() is passed a
// pointer to a stack-local __u32 that is left uninitialized on purpose (the
// C source declares `__u32 mtu;` with no initializer) — the __msg_unpriv
// BTF decl tag on the C source ("invalid read from stack") documents that
// unprivileged loads reject this, but rustc cannot emit __failure_unpriv/
// __msg_unpriv decl tags, so test_loader falls back to its default
// expect-success behavior, matching the C source's own __success tag for
// the privileged case.

use core::ffi::c_void;
use core::mem::MaybeUninit;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_check_mtu;

const TCX_PASS: i32 = 0;

#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tc_uninit_mtu(ctx: *const __sk_buff) -> i32 {
    let mut mtu: MaybeUninit<u32> = MaybeUninit::uninit();

    bpf_check_mtu(ctx as *const c_void, 0, mtu.as_mut_ptr(), 0, 0);
    TCX_PASS
}

// The C source names its license global `LICENSE` (most selftests use
// `_license`, which is what bpf_rs_core::bpf_object! hardcodes) — the
// symbol name must match exactly for the internalize keep-list to retain
// it, so this is written out by hand instead of via the macro.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
