#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

#[no_mangle]
#[inline(never)]
// BPF_NAKED: agg_ret_target_func
extern "C" fn agg_ret_target_func() -> u128 {
    unsafe { core::arch::asm!("r0 = 0x1234; r2 = 0x5678; exit;", options(noreturn)); }
}

#[no_mangle]
#[link_section = "tc"]
// BPF_NAKED: agg_ret_target
extern "C" fn agg_ret_target() -> i32 {
    // Preserve the call even though the main program discards the pair.
    unsafe {
        core::arch::asm!("call {target}; r0 = 0; exit;", target = sym agg_ret_target_func, options(noreturn));
    }
}

bpf_rs_core::bpf_object!("GPL");
