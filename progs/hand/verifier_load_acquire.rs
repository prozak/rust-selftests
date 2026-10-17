// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_load_acquire.c, translated
// by hand; include!d by the generated progs/verifier_load_acquire.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: load_acquire_from_rdonly_untrusted_mem -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("load-acquire from rdonly_untrusted_mem pointer")
//   __failure __msg("BPF_ATOMIC loads from R{{[0-9]+}} rdonly_untrusted_mem is not allowed")
//   int load_acquire_from_rdonly_untrusted_mem(void *ctx)
//   {
//       __u64 val = 0;
//       void *p;
//
//       /*
//        * bpf_rdonly_cast(x, 0) yields PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED.
//        * A regular BPF_LDX from it is rewritten to BPF_PROBE_MEM, but a
//        * load-acquire is not, so it must be rejected, otherwise the JIT emits
//        * a plain load with no exception table entry and a fault would crash
//        * the kernel.
//        */
//       p = bpf_rdonly_cast(&val, 0);
//       asm volatile (
//       "r1 = %[p];"
//       ".8byte %[load_acquire_insn];" // r0 = load_acquire((u64 *)(r1 + 0));
//       :
//       : [p] "r" (p),
//         __imm_insn(load_acquire_insn,
//                BPF_ATOMIC_OP(BPF_DW, BPF_LOAD_ACQ, BPF_REG_0, BPF_REG_1, 0))
//       : "r0", "r1");
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn load_acquire_from_rdonly_untrusted_mem(_ctx: *mut c_void) -> i32 {
    let mut val: u64 = 0;
    // bpf_rdonly_cast(x, 0) yields PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED; a
    // load-acquire from it is not rewritten to BPF_PROBE_MEM and must be
    // rejected. The C's BPF_ATOMIC_OP(BPF_DW, BPF_LOAD_ACQ, BPF_REG_0,
    // BPF_REG_1, 0) is the raw instruction r0 = load_acquire((u64 *)(r1 + 0)).
    unsafe {
        let p = bpf_rdonly_cast(&mut val as *mut u64 as *mut c_void, 0);
        core::arch::asm!(
            "r1 = {p};",
            ".8byte {load_acquire_insn};",
            p = in(reg) p,
            load_acquire_insn = const 0x00000100000010dbu64,
            out("r0") _,
            out("r1") _,
            options(nostack)
        );
    }
    0
}
