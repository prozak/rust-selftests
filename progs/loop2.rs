#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/loop2.c
// bpf-rs-core idiom.
//
// SEC("raw_tracepoint/...") ctx access is unrestricted by the verifier
// (raw_tp_prog_is_valid_access places no offset/size limits), which is
// exactly what the C source exploits: it casts the raw_tracepoint args
// pointer straight to `volatile struct pt_regs*` and reads PT_REGS_RC
// (== ->rax on x86-64) purely as a data source to keep the verifier from
// proving the loop trivially -- same 21 x u64-slot pt_regs layout used in
// test_perf_skip.rs/test_probe_user.rs/test_uprobe.rs (ax at slot 10).
// The `volatile` on the C pointer forces a fresh load every iteration
// (defeats LICM), reproduced here with `vload!`.

use bpf_rs_core::bpf_object;
use bpf_rs_core::vload;

#[repr(C)]
struct pt_regs {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    bp: u64,
    bx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    ax: u64,
    cx: u64,
    dx: u64,
    si: u64,
    di: u64,
    orig_ax: u64,
    ip: u64,
    cs: u64,
    flags: u64,
    sp: u64,
    ss: u64,
}

#[link_section = "raw_tracepoint/consume_skb"]
#[no_mangle]
extern "C" fn while_true(ctx: *const pt_regs) -> i32 {
    let mut i: i32 = 0;

    loop {
        let rax = vload!((*ctx).ax);
        if rax & 1 != 0 {
            i += 3;
        } else {
            i += 7;
        }
        if i > 40 {
            break;
        }
    }

    i
}

bpf_object!("GPL");
