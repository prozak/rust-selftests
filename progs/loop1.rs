#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/loop1.c.
//
// Consumed only by prog_tests/bpf_verif_scale.c's test_verif_scale_loop1 ->
// scale_test("loop1.bpf.o", BPF_PROG_TYPE_RAW_TRACEPOINT, false), which just
// bpf_object__load()s the program and asserts success -- it never attaches
// or runs it. So correctness here is "the verifier accepts this nested
// loop", not any particular return value.
//
// The C source declares its raw_tracepoint ctx as `volatile struct
// pt_regs*` (instead of the usual `u64*` args array) and reads
// PT_REGS_RC(ctx), i.e. ctx->ax -- on x86-64 that's u64 slot index 10 in
// the pt_regs register layout (r15,r14,r13,r12,bp,bx,r11,r10,r9,r8,ax,cx,
// dx,si,di,orig_ax,ip,cs,flags,sp,ss), same convention as profiler1.rs /
// test_probe_user.rs's REG_AX.

use bpf_rs_core::bpf_object;

const REG_AX: usize = 10; // PT_REGS_RC on x86-64

#[link_section = "raw_tracepoint/kfree_skb"]
#[no_mangle]
extern "C" fn nested_loops(ctx: *const u64) -> i32 {
    let mut sum: i32 = 0;
    let mut j: i32 = 0;
    while j < 300 {
        let mut i: i32 = 0;
        while i < j {
            let m: i32 = if j & 1 != 0 {
                (unsafe { *ctx.add(REG_AX) }) as i32
            } else {
                j
            };
            sum = sum.wrapping_add(i.wrapping_mul(m));
            i += 1;
        }
        j += 1;
    }
    sum
}

bpf_object!("GPL");
