#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Each call is hand-encoded as in C; add_ksyms mirrors the actual kernel
// BTF prototypes, including aggregate returns, onto these declarations.
extern "C" {
    fn bpf_kfunc_call_test_i128() -> u64;
    fn bpf_kfunc_call_test_ret_fastcall() -> u64;
    fn bpf_kfunc_call_test_ret_ptr() -> u64;
    fn bpf_kfunc_call_test_ret_nested() -> u64;
    fn bpf_kfunc_call_test_ret_ptr_arr() -> u64;
    fn bpf_kfunc_call_test_ret_arr_struct() -> u64;
    fn bpf_kfunc_call_test_ret_arr2d() -> u64;
    fn bpf_kfunc_call_test_ret_deep() -> u64;
    fn bpf_kfunc_call_test_ret_ii() -> u64;
    fn bpf_kfunc_call_test_ret_big() -> u64;
}
#[no_mangle]
extern "C" fn __kfunc_btf_root() {
    unsafe { core::arch::asm!("{0} = {0}", in(reg) bpf_kfunc_call_test_i128 as usize); }
    unsafe { core::arch::asm!("{0} = {0}", in(reg) bpf_kfunc_call_test_ret_fastcall as usize); }
    unsafe { core::arch::asm!("{0} = {0}", in(reg) bpf_kfunc_call_test_ret_ptr as usize); }
    unsafe { core::arch::asm!("{0} = {0}", in(reg) bpf_kfunc_call_test_ret_nested as usize); }
    unsafe { core::arch::asm!("{0} = {0}", in(reg) bpf_kfunc_call_test_ret_ptr_arr as usize); }
    unsafe { core::arch::asm!("{0} = {0}", in(reg) bpf_kfunc_call_test_ret_arr_struct as usize); }
    unsafe { core::arch::asm!("{0} = {0}", in(reg) bpf_kfunc_call_test_ret_arr2d as usize); }
    unsafe { core::arch::asm!("{0} = {0}", in(reg) bpf_kfunc_call_test_ret_deep as usize); }
    unsafe { core::arch::asm!("{0} = {0}", in(reg) bpf_kfunc_call_test_ret_ii as usize); }
    unsafe { core::arch::asm!("{0} = {0}", in(reg) bpf_kfunc_call_test_ret_big as usize); }
}

#[no_mangle]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_kfunc_precise
extern "C" fn aggregate_ret_kfunc_precise() -> i32 {
    unsafe { core::arch::asm!("r1 = 1;r2 = 2;call {bpf_kfunc_call_test_i128};r6 = r2;r6 &= 7;r1 = r10;r1 += -8;r1 += r6;r0 = 0;*(u8 *)(r1 + 0) = r0;r0 = 0;exit;", bpf_kfunc_call_test_i128 = sym bpf_kfunc_call_test_i128, options(noreturn)); }
}

#[no_mangle]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_kfunc_fastcall_fail
extern "C" fn aggregate_ret_kfunc_fastcall_fail() -> i32 {
    unsafe { core::arch::asm!("r1 = 1;r2 = 2;call {bpf_kfunc_call_test_ret_fastcall};r0 = 0;exit;", bpf_kfunc_call_test_ret_fastcall = sym bpf_kfunc_call_test_ret_fastcall, options(noreturn)); }
}

#[no_mangle]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_kfunc_ptr_fail
extern "C" fn aggregate_ret_kfunc_ptr_fail() -> i32 {
    unsafe { core::arch::asm!("r1 = 0;call {bpf_kfunc_call_test_ret_ptr};r0 = 0;exit;", bpf_kfunc_call_test_ret_ptr = sym bpf_kfunc_call_test_ret_ptr, options(noreturn)); }
}

#[no_mangle]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_kfunc_nested_ptr_fail
extern "C" fn aggregate_ret_kfunc_nested_ptr_fail() -> i32 {
    unsafe { core::arch::asm!("r1 = 0;call {bpf_kfunc_call_test_ret_nested};r0 = 0;exit;", bpf_kfunc_call_test_ret_nested = sym bpf_kfunc_call_test_ret_nested, options(noreturn)); }
}

#[no_mangle]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_kfunc_ptr_arr_fail
extern "C" fn aggregate_ret_kfunc_ptr_arr_fail() -> i32 {
    unsafe { core::arch::asm!("call {bpf_kfunc_call_test_ret_ptr_arr};r0 = 0;exit;", bpf_kfunc_call_test_ret_ptr_arr = sym bpf_kfunc_call_test_ret_ptr_arr, options(noreturn)); }
}

#[no_mangle]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_kfunc_arr_struct_fail
extern "C" fn aggregate_ret_kfunc_arr_struct_fail() -> i32 {
    unsafe { core::arch::asm!("call {bpf_kfunc_call_test_ret_arr_struct};r0 = 0;exit;", bpf_kfunc_call_test_ret_arr_struct = sym bpf_kfunc_call_test_ret_arr_struct, options(noreturn)); }
}

#[no_mangle]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_kfunc_arr2d_fail
extern "C" fn aggregate_ret_kfunc_arr2d_fail() -> i32 {
    unsafe { core::arch::asm!("call {bpf_kfunc_call_test_ret_arr2d};r0 = 0;exit;", bpf_kfunc_call_test_ret_arr2d = sym bpf_kfunc_call_test_ret_arr2d, options(noreturn)); }
}

#[no_mangle]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_kfunc_too_deep_fail
extern "C" fn aggregate_ret_kfunc_too_deep_fail() -> i32 {
    unsafe { core::arch::asm!("r1 = 0;call {bpf_kfunc_call_test_ret_deep};r0 = 0;exit;", bpf_kfunc_call_test_ret_deep = sym bpf_kfunc_call_test_ret_deep, options(noreturn)); }
}

#[no_mangle]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_kfunc_small_no_r2
extern "C" fn aggregate_ret_kfunc_small_no_r2() -> i32 {
    unsafe { core::arch::asm!("r1 = 0;r2 = 0;call {bpf_kfunc_call_test_ret_ii};r0 = r2;exit;", bpf_kfunc_call_test_ret_ii = sym bpf_kfunc_call_test_ret_ii, options(noreturn)); }
}

#[no_mangle]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_kfunc_too_big_fail
extern "C" fn aggregate_ret_kfunc_too_big_fail() -> i32 {
    unsafe { core::arch::asm!("call {bpf_kfunc_call_test_ret_big};r0 = 0;exit;", bpf_kfunc_call_test_ret_big = sym bpf_kfunc_call_test_ret_big, options(noreturn)); }
}

bpf_rs_core::bpf_object!("GPL");
bpf_rs_core::test_tags! {
    aggregate_ret_kfunc_precise: __arch_x86_64, __arch_arm64, __load_if_JITed, __success, __retval("0"), __log_level("2"), __msg("mark_precise: frame0: last_idx 7 first_idx 0 subseq_idx -1"), __msg("mark_precise: frame0: regs=r6 stack= before 6: (07) r1 += -8"), __msg("mark_precise: frame0: regs=r6 stack= before 5: (bf) r1 = r10"), __msg("mark_precise: frame0: regs=r6 stack= before 4: (57) r6 &= 7"), __msg("mark_precise: frame0: regs=r6 stack= before 3: (bf) r6 = r2"), __msg("mark_precise: frame0: regs=r2 stack= before 2: (85) call bpf_kfunc_call_test_i128");
    aggregate_ret_kfunc_fastcall_fail: __arch_x86_64, __arch_arm64, __failure, __msg("kfunc bpf_kfunc_call_test_ret_fastcall with >8-byte return is not supported with KF_FASTCALL");
    aggregate_ret_kfunc_ptr_fail: __arch_x86_64, __arch_arm64, __failure, __msg("is not composed of scalars or arena pointers"), __msg("member 'p' has type PTR");
    aggregate_ret_kfunc_nested_ptr_fail: __arch_x86_64, __arch_arm64, __failure, __msg("is not composed of scalars or arena pointers"), __msg("member 'in.p' has type PTR");
    aggregate_ret_kfunc_ptr_arr_fail: __arch_x86_64, __arch_arm64, __failure, __msg("is not composed of scalars or arena pointers"), __msg("member 'p[]' has type PTR");
    aggregate_ret_kfunc_arr_struct_fail: __arch_x86_64, __arch_arm64, __failure, __msg("is not composed of scalars or arena pointers"), __msg("member 'in1[].in2.p' has type PTR");
    aggregate_ret_kfunc_arr2d_fail: __arch_x86_64, __arch_arm64, __failure, __msg("is not composed of scalars or arena pointers"), __msg("member 'a[].p' has type PTR");
    aggregate_ret_kfunc_too_deep_fail: __arch_x86_64, __arch_arm64, __failure, __msg("max struct nesting depth exceeded");
    aggregate_ret_kfunc_small_no_r2: __arch_x86_64, __arch_arm64, __failure, __msg("R2 !read_ok");
    aggregate_ret_kfunc_too_big_fail: __arch_x86_64, __arch_arm64, __failure, __msg("The function bpf_kfunc_call_test_ret_big return type STRUCT is unsupported");
}
