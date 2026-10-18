// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_sk_storage_tracing.c (bpf-rs-core
// idiom). Tracing programs record each socket's last non-CLOSE state, the
// pid and the comm of the task that listened/connected/accepted it in a
// socket-storage element, and delete the element of a second storage map;
// prog_tests/sk_storage_tracing.c looks the elements up by socket fd and
// compares the comm with the task_comm global. `task->comm` is a CO-RE read
// (bpf_core_read_str) through a #[btf] view of task_struct; the `sk`
// pointers of request_sock and sk_buff are plain CO-RE field loads.
// All the byte arrays are C `char` (the test strcmp()s them).
// BTF_C_CHAR: u8

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel_str,
    bpf_sk_storage_delete, bpf_sk_storage_get,
};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::bpf_map;
use btf_macros::btf;

const BPF_TCP_CLOSE: i32 = 7;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

#[allow(non_camel_case_types)]
#[repr(C)]
struct sk_stg {
    pid: u32,
    last_notclose_state: u32,
    comm: [u8; 16],
}

bpf_map! {
    sk_stg_map {
        r#type: *const [i32; 24], // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const sk_stg,
    }
}

/* Testing delete */
bpf_map! {
    del_sk_stg_map {
        r#type: *const [i32; 24], // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const i32,
    }
}

#[no_mangle]
static mut task_comm: [u8; 16] = [0; 16];

#[btf]
struct task_struct {
    comm: [u8; 16],
}

#[btf]
struct request_sock {
    sk: *const u8,
}

#[btf]
struct sk_buff {
    sk: *const u8,
}

// BPF_PROG(trace_inet_sock_set_state, struct sock *sk, int oldstate, int newstate)
#[link_section = "tp_btf/inet_sock_set_state"]
#[no_mangle]
extern "C" fn trace_inet_sock_set_state(ctx: *const u64) -> i32 {
    let sk = arg(ctx, 0) as *const c_void;
    let newstate = arg(ctx, 2) as i32;

    if newstate == BPF_TCP_CLOSE {
        return 0;
    }

    let stg = bpf_sk_storage_get(
        &sk_stg_map,
        sk,
        core::ptr::null(),
        BPF_SK_STORAGE_GET_F_CREATE,
    ) as *mut sk_stg;
    if stg.is_null() {
        return 0;
    }

    unsafe { (*stg).last_notclose_state = newstate as u32 };

    bpf_sk_storage_delete(&del_sk_stg_map, sk as *mut c_void);

    0
}

#[inline(always)]
fn set_task_info(sk: *const c_void) {
    let stg = bpf_sk_storage_get(
        &sk_stg_map,
        sk,
        core::ptr::null(),
        BPF_SK_STORAGE_GET_F_CREATE,
    ) as *mut sk_stg;
    if stg.is_null() {
        return;
    }

    unsafe {
        (*stg).pid = bpf_get_current_pid_tgid() as u32;

        let task = bpf_get_current_task() as *const task_struct;
        let comm_src = (&*task).comm().as_ptr() as *const c_void;
        bpf_probe_read_kernel_str(addr_of_mut!((*stg).comm) as *mut c_void, 16, comm_src);
        bpf_probe_read_kernel_str(addr_of_mut!(task_comm) as *mut c_void, 16, comm_src);
    }
}

// BPF_PROG(trace_inet_csk_listen_start, struct sock *sk)
#[link_section = "fentry/inet_csk_listen_start"]
#[no_mangle]
extern "C" fn trace_inet_csk_listen_start(ctx: *const u64) -> i32 {
    set_task_info(arg(ctx, 0) as *const c_void);

    0
}

// BPF_PROG(trace_tcp_connect, struct sock *sk)
#[link_section = "fentry/tcp_connect"]
#[no_mangle]
extern "C" fn trace_tcp_connect(ctx: *const u64) -> i32 {
    set_task_info(arg(ctx, 0) as *const c_void);

    0
}

// BPF_PROG(inet_csk_accept, struct sock *sk, struct proto_accept_arg *arg,
//          struct sock *accepted_sk)
#[link_section = "fexit/inet_csk_accept"]
#[no_mangle]
extern "C" fn inet_csk_accept(ctx: *const u64) -> i32 {
    set_task_info(arg(ctx, 2) as *const c_void);

    0
}

// BPF_PROG(tcp_retransmit_synack, struct sock *sk, struct request_sock *req)
#[link_section = "tp_btf/tcp_retransmit_synack"]
#[no_mangle]
extern "C" fn tcp_retransmit_synack(ctx: *const u64) -> i32 {
    let sk = arg(ctx, 0) as *const c_void;
    let req = arg(ctx, 1) as *const request_sock;

    /* load only test */
    bpf_sk_storage_get(&sk_stg_map, sk, core::ptr::null(), 0);
    let req_sk = unsafe { *(&*req).sk().as_ptr() } as *const c_void;
    bpf_sk_storage_get(&sk_stg_map, req_sk, core::ptr::null(), 0);
    0
}

// BPF_PROG(tcp_bad_csum, struct sk_buff *skb)
#[link_section = "tp_btf/tcp_bad_csum"]
#[no_mangle]
extern "C" fn tcp_bad_csum(ctx: *const u64) -> i32 {
    let skb = arg(ctx, 0) as *const sk_buff;

    let skb_sk = unsafe { *(&*skb).sk().as_ptr() } as *const c_void;
    bpf_sk_storage_get(&sk_stg_map, skb_sk, core::ptr::null(), 0);
    0
}

bpf_object!("GPL");
