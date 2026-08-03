#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/loop3.c
// (bpf-rs-core idiom). SEC("raw_tracepoint/consume_skb") with a plain
// (non-BPF_PROG-wrapped) `struct pt_regs *ctx` parameter; raw_tracepoint
// ctx is carried as the `*const u64` register-slot array (libbpf's
// raw_tracepoint ctx convention), and PT_REGS_RC(ctx) on x86_64
// (`ctx->ax`) is a load at u64 slot 10 (byte offset 80) -- same pt_regs
// slot layout as test_uprobe.rs/uprobe_syscall.rs/test_probe_user.rs.
//
// prog_tests/bpf_verif_scale.c's test_verif_scale_loop3_fail() expects
// this program to FAIL verification (BPF_PROG_TYPE_RAW_TRACEPOINT load):
// the do-while runs up to 0x100000000 (4 billion) times while
// accumulating an unbounded scalar (`sum`) fed by the unknown ctx load,
// so the verifier's state never converges/prunes and it aborts on
// instruction-processing complexity, exactly like the clang-built
// object. `i`/`sum` are kept as real volatile memory locations (matching
// C's `volatile __u64 i = 0, sum = 0;`) so the loop can't be constant
// folded or unrolled away.

use bpf_rs_core::bpf_object;

#[link_section = "raw_tracepoint/consume_skb"]
#[no_mangle]
extern "C" fn while_true(ctx: *const u64) -> i32 {
    let mut i: u64 = 0;
    let mut sum: u64 = 0;
    unsafe {
        loop {
            core::ptr::write_volatile(&mut i, core::ptr::read_volatile(&i) + 1);
            let rc = *ctx.add(10);
            core::ptr::write_volatile(&mut sum, core::ptr::read_volatile(&sum) + rc);
            if !(core::ptr::read_volatile(&i) < 0x1_0000_0000u64) {
                break;
            }
        }
    }
    sum as i32
}

bpf_object!("GPL");
