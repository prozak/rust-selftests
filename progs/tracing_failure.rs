#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;

#[link_section = "?fentry/bpf_spin_lock"]
#[no_mangle]
extern "C" fn test_spin_lock(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "?fentry/bpf_spin_unlock"]
#[no_mangle]
extern "C" fn test_spin_unlock(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "?fentry/__rcu_read_lock"]
#[no_mangle]
extern "C" fn tracing_deny(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "?fexit/do_exit"]
#[no_mangle]
extern "C" fn fexit_noreturns(_ctx: *const u64) -> i32 {
    0
}

/// bpf_testmod_test_int128_ret returns a __int128, which x86_64 passes back
/// in a register pair; the verifier rejects an fexit on a >8 byte return
/// value, and prog_tests/tracing_failure.c asserts that rejection message.
#[link_section = "?fexit/bpf_testmod_test_int128_ret"]
#[no_mangle]
extern "C" fn fexit_int128_ret(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
