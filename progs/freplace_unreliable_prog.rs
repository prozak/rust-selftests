#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/freplace_unreliable_prog.c,
// bpf-rs-core idiom.
//
// context type is what BPF verifier expects for kprobe context, but target
// program has `struct whatever *ctx` argument, so freplace operation will be
// rejected with the following message:
//
// arg0 replace_btf_unreliable_kprobe(struct pt_regs *) doesn't match btf_unreliable_kprobe(struct whatever *)

use bpf_rs_core::bpf_object;

#[link_section = "freplace/btf_unreliable_kprobe"]
#[no_mangle]
extern "C" fn replace_btf_unreliable_kprobe(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

bpf_object!("GPL");
