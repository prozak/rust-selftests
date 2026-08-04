#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_skmsg_load_helpers.c
// (bpf-rs-core idiom).

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel, bpf_sk_storage_delete,
    bpf_sk_storage_get,
};
use bpf_rs_core::maps::BpfMap;
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;
use core::ffi::c_void;

const SK_DROP: i32 = 0;
const SK_PASS: i32 = 1;

/// enum bpf_map_type::BPF_MAP_TYPE_SOCKMAP (not in bpf-rs-core::maps yet).
const SOCKMAP: usize = 15;
/// enum bpf_map_type::BPF_MAP_TYPE_SOCKHASH (not in bpf-rs-core::maps yet).
const SOCKHASH: usize = 18;
/// enum bpf_map_type::BPF_MAP_TYPE_SK_STORAGE.
const BPF_MAP_TYPE_SK_STORAGE: usize = 24;
/// enum: BPF_F_NO_PREALLOC.
const BPF_F_NO_PREALLOC: usize = 1;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

/// UAPI struct sk_msg_md, full layout (bpf.h). data/data_end/sk are
/// pointer-typed unions, represented as u64 (same convention as
/// __sk_buff's flow_keys/sk fields).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct sk_msg_md {
    pub data: u64,
    pub data_end: u64,
    pub family: u32,
    pub remote_ip4: u32,
    pub local_ip4: u32,
    pub remote_ip6: [u32; 4],
    pub local_ip6: [u32; 4],
    pub remote_port: u32,
    pub local_port: u32,
    pub size: u32,
    pub sk: u64,
}

#[btf]
struct task_struct {
    tgid: i32,
}

#[link_section = ".maps"]
#[no_mangle]
static sock_map: BpfMap<u32, u64, SOCKMAP, 2> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static sock_hash: BpfMap<u32, u64, SOCKHASH, 2> = BpfMap::new();

bpf_map! {
    socket_storage {
        r#type: *const [i32; BPF_MAP_TYPE_SK_STORAGE],
        map_flags: *const [i32; BPF_F_NO_PREALLOC],
        key: *const u32,
        value: *const u64,
    }
}

fn prog_msg_verdict_common(msg: *const sk_msg_md) -> i32 {
    let task = bpf_get_current_task() as *const task_struct;
    let mut verdict = SK_PASS;

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let sk = unsafe { (*msg).sk } as *const c_void;

    let sk_stg = bpf_sk_storage_get(
        &socket_storage,
        sk,
        core::ptr::null(),
        BPF_SK_STORAGE_GET_F_CREATE,
    ) as *mut u32;
    if sk_stg.is_null() {
        return SK_DROP;
    }
    unsafe { *sk_stg = pid };

    let mut tpid: u32 = 0;
    let tgid_addr = unsafe { &*task }.tgid().as_ptr();
    bpf_probe_read_kernel(&mut tpid, core::mem::size_of::<u32>() as u32, tgid_addr as *const c_void);
    if pid != tpid {
        verdict = SK_DROP;
    }

    bpf_sk_storage_delete(&socket_storage, sk as *mut c_void);
    verdict
}

#[link_section = "sk_msg"]
#[no_mangle]
extern "C" fn prog_msg_verdict(msg: *const sk_msg_md) -> i32 {
    prog_msg_verdict_common(msg)
}

#[link_section = "sk_msg"]
#[no_mangle]
extern "C" fn prog_msg_verdict_clone(msg: *const sk_msg_md) -> i32 {
    prog_msg_verdict_common(msg)
}

#[link_section = "sk_msg"]
#[no_mangle]
extern "C" fn prog_msg_verdict_clone2(msg: *const sk_msg_md) -> i32 {
    prog_msg_verdict_common(msg)
}

#[link_section = "sk_skb/stream_verdict"]
#[no_mangle]
extern "C" fn prog_skb_verdict(_skb: *const __sk_buff) -> i32 {
    SK_PASS
}

bpf_object!("GPL");
