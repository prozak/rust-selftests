// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_bpf_fastcall.c, translated
// by hand; include!d by the generated progs/verifier_bpf_fastcall.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// BTF_TYPE_ID: bpf_attr_type_id union bpf_attr
extern "C" {
    fn bpf_attr_type_id() -> u64;
}

// HAND: kfunc_bpf_rdonly_cast -- translate the C below (see the file comment)
//   SEC("raw_tp")
//   __xlated("3: r3 = 1")
//   /* bpf_rdonly_cast is replaced by a single assignment */
//   __xlated("4: r0 = r1")
//   __xlated("5: r0 = r3")
//   void kfunc_bpf_rdonly_cast(void)
//   {
//       asm volatile (
//       "r2 = %[btf_id];"
//       "r3 = 1;"
//       "*(u64 *)(r10 - 32) = r3;"
//       "call %[bpf_rdonly_cast];"
//       "r3 = *(u64 *)(r10 - 32);"
//       "r0 = r3;"
//       :
//       : __imm(bpf_rdonly_cast),
//        [btf_id]"r"(bpf_core_type_id_kernel(union bpf_attr))
//       : __clobber_common);
//   }
// The C's asm with a `"r"(bpf_core_type_id_kernel(union bpf_attr))` input:
// the type id is a CO-RE relocation (the BTF_TYPE_ID extern above), loaded
// into a register the asm's r0-r5 clobbers keep clear of, as clang does.
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn kfunc_bpf_rdonly_cast() {
    let btf_id = unsafe { bpf_attr_type_id() };
    unsafe {
        core::arch::asm!(
            "r2 = {btf_id};",
            "r3 = 1;",
            "*(u64 *)(r10 - 32) = r3;",
            "call {bpf_rdonly_cast};",
            "r3 = *(u64 *)(r10 - 32);",
            "r0 = r3;",
            btf_id = in(reg) btf_id,
            bpf_rdonly_cast = sym bpf_rdonly_cast,
            out("r0") _, out("r1") _, out("r2") _, out("r3") _, out("r4") _, out("r5") _,
            options(nostack)
        );
    }
}
