#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_perf_skip.c
// (bpf-rs-core idiom).
//
// SEC("perf_event") ctx is `struct bpf_perf_event_data *`. This is NOT a
// BTF-typed context: kernel/trace/bpf_trace.c's pe_prog_convert_ctx_access
// rewrites any offset that isn't sample_period/addr into a raw load off the
// real hardware `struct pt_regs *` at the same byte offset, so only the
// layout up to `regs.ip` needs to match — same 21 x u64-slot pt_regs layout
// used in test_uprobe.rs/test_probe_user.rs (r15..ss), `ip` at offset 128.

use bpf_rs_core::bpf_object;

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

#[repr(C)]
struct bpf_perf_event_data {
    regs: pt_regs,
    sample_period: u64,
    addr: u64,
}

#[no_mangle]
static mut ip: u64 = 0;

/// Skip events that have the correct ip.
#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn handler(data: *const bpf_perf_event_data) -> i32 {
    let regs_ip = unsafe { (*data).regs.ip };
    (unsafe { ip } != regs_ip) as i32
}

bpf_object!("GPL");
