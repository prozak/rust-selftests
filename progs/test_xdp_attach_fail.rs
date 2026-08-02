#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_xdp_attach_fail.c, bpf-rs-core
// idiom.
//
// xdp_errmsg_pb has no max_entries in the C source (libbpf sizes a
// PERF_EVENT_ARRAY to the number of CPUs when it is 0), so its BTF map
// struct carries only type/key/value members — bpf_map! escape hatch,
// same shape as test_perf_buffer.rs's perf_buf_map.
//
// The tracepoint ctx carries a __data_loc-encoded offset to the error
// message: the low 16 bits of the `msg` field are the byte offset from
// the start of the tracepoint record to the message text.

use bpf_rs_core::bpf_map;
use bpf_rs_core::helpers::{bpf_perf_event_output, bpf_probe_read_kernel_str};
use core::ffi::c_void;

const ERRMSG_LEN: usize = 64;

#[repr(C)]
struct XdpErrmsg {
    msg: [u8; ERRMSG_LEN],
}

#[repr(C)]
struct XdpAttachErrorCtx {
    unused: u64,
    msg: u32, // __data_loc char[] msg
}

bpf_map! {
    xdp_errmsg_pb {
        r#type: *const [i32; 4], // BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
        key: *const i32,
        value: *const i32,
    }
}

const BPF_F_CURRENT_CPU: u64 = 0xffffffff;

#[link_section = "tp/xdp/bpf_xdp_link_attach_failed"]
#[no_mangle]
extern "C" fn tp__xdp__bpf_xdp_link_attach_failed(ctx: *const XdpAttachErrorCtx) -> i32 {
    let data_loc = unsafe { (*ctx).msg };
    let msg_off = data_loc as u16 as usize;
    let msg = (ctx as usize + msg_off) as *const c_void;

    let mut errmsg = XdpErrmsg {
        msg: [0; ERRMSG_LEN],
    };

    bpf_probe_read_kernel_str(
        errmsg.msg.as_mut_ptr() as *mut c_void,
        ERRMSG_LEN as u32,
        msg,
    );
    bpf_perf_event_output(
        ctx as *const c_void,
        &xdp_errmsg_pb,
        BPF_F_CURRENT_CPU,
        &errmsg,
        ERRMSG_LEN as u64,
    );
    0
}

// The C source names its license global `LICENSE` (most selftests use
// `_license`, which is what bpf_rs_core::bpf_object! hardcodes) — the
// symbol name must match exactly for the internalize keep-list to retain
// it, so this is written out by hand instead of via the macro.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
