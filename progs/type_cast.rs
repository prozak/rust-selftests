// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/type_cast.c
// (bpf-rs-core idiom).
//
// bpf_core_cast(p, T) is bpf_rdonly_cast(p, bpf_core_type_id_kernel(T)); the
// type ids are the BTF_TYPE_ID declarations below (scripts/type_id.py), and
// the kernel struct fields are read through #[btf] views, CO-RE like the
// C's vmlinux.h. Parked until the LLVM 23 move: the faithful form crashed
// opt on an unused preserve.field.info call (#49).
//
// `untrusted_ptr` and `kctx_u64` are the test's negative programs: the
// verifier must reject them (an untrusted task pointer into
// bpf_task_storage_get, a cast to a non-struct type).

// `char name[IFNAMSIZ]` in C: BTF_C_CHAR makes this file's u8 a BTF `char`,
// so the skeleton's `name` is a `char[16]` the test's ASSERT_STREQ takes.
// BTF_C_CHAR: u8
// BTF_TYPE_ID: tid_skb_shared_info struct skb_shared_info
// BTF_TYPE_ID: tid_sk_buff struct sk_buff
// BTF_TYPE_ID: tid_task_struct struct task_struct
// BTF_TYPE_ID: tid_u64 typedef u64

use core::ffi::c_void;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_current_task_btf, bpf_task_storage_get, sink};
use core::ptr::read_volatile;
use bpf_rs_core::{bpf_map, bpf_object, vload};
use btf_macros::btf;

// UAPI struct xdp_md (linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
struct xdp_md {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

const BPF_MAP_TYPE_TASK_STORAGE: i32 = 29;
const XDP_PASS: i32 = 2;
const IFNAMSIZ: usize = 16;

bpf_map! {
    enter_id {
        r#type: *const [i32; BPF_MAP_TYPE_TASK_STORAGE as usize],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const i64,
    }
}

#[no_mangle]
static mut ifindex: i32 = 0;
#[no_mangle]
static mut ingress_ifindex: i32 = 0;
#[no_mangle]
static mut name: [u8; IFNAMSIZ] = [0; IFNAMSIZ];
#[no_mangle]
static mut inum: u32 = 0;
#[no_mangle]
static mut meta_len: u32 = 0;
#[no_mangle]
static mut frag0_len: u32 = 0;
#[no_mangle]
static mut kskb_len: u32 = 0;
#[no_mangle]
static mut kskb2_len: u32 = 0;

#[btf]
struct ns_common {
    inum: u32,
}

#[btf]
struct net {
    ns: ns_common,
}

#[btf]
struct possible_net_t {
    net: *mut net,
}

#[btf]
struct net_device {
    name: [u8; IFNAMSIZ],
    ifindex: i32,
    nd_net: possible_net_t,
}

#[btf]
struct xdp_rxq_info {
    dev: *mut net_device,
}

#[btf]
struct xdp_buff {
    rxq: *mut xdp_rxq_info,
}

#[btf]
struct sk_buff {
    len: u32,
    head: *mut u8,
    end: u32,
}

#[btf]
struct skb_shared_info {
    meta_len: u8,
    frag_list: *mut sk_buff,
}

struct task_struct;

extern "C" {
    fn bpf_cast_to_kern_ctx(obj: *const c_void) -> *mut c_void;
    fn bpf_rdonly_cast(obj: *const c_void, btf_id: u32) -> *mut c_void;
    fn tid_skb_shared_info() -> u64;
    fn tid_sk_buff() -> u64;
    fn tid_task_struct() -> u64;
    fn tid_u64() -> u64;
}

#[link_section = "?xdp"]
#[no_mangle]
extern "C" fn md_xdp(ctx: *mut xdp_md) -> i32 {
    let kctx = unsafe { bpf_cast_to_kern_ctx(ctx as *const c_void) } as *const xdp_buff;

    let rxq = *unsafe { &*kctx }.rxq().get().unwrap();
    let dev = *unsafe { &*rxq }.dev().get().unwrap();
    let dev_ref = unsafe { &*dev };
    unsafe {
        ifindex = *dev_ref.ifindex().get().unwrap();
        let net_ptr = *dev_ref.nd_net().net().get().unwrap();
        inum = *(&*net_ptr).ns().inum().get().unwrap();
        // __builtin_memcpy(name, dev->name, IFNAMSIZ): two 8-byte loads off
        // the CO-RE field pointer. The pointer goes through a barrier first
        // so the +8 is not folded into the relocated instruction, and the
        // loads are volatile so LLVM does not fuse them back into a memcpy
        // (which add_ksyms would turn into the bpf_arena_memcpy kfunc).
        let mut src = dev_ref.name().as_ptr() as *mut u64;
        sink(&mut src);
        let dst = core::ptr::addr_of_mut!(name) as *mut u64;
        *dst = read_volatile(src);
        *dst.add(1) = read_volatile(src.add(1));
        ingress_ifindex = vload!((*ctx).ingress_ifindex) as i32;
    }
    XDP_PASS
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn md_skb(skb: *mut __sk_buff) -> i32 {
    let kskb = unsafe { bpf_cast_to_kern_ctx(skb as *const c_void) } as *const sk_buff;
    let kskb_ref = unsafe { &*kskb };

    unsafe {
        kskb_len = *kskb_ref.len().get().unwrap();
    }

    // Simulate the following kernel macro:
    //   #define skb_shinfo(SKB) ((struct skb_shared_info *)(skb_end_pointer(SKB)))
    let head = *kskb_ref.head().get().unwrap();
    let end = *kskb_ref.end().get().unwrap();
    let shared_info = unsafe {
        bpf_rdonly_cast(head.add(end as usize) as *const c_void, tid_skb_shared_info() as u32)
    } as *const skb_shared_info;
    let shared_info_ref = unsafe { &*shared_info };
    unsafe {
        meta_len = *shared_info_ref.meta_len().get().unwrap() as u32;
        let frag_list = *shared_info_ref.frag_list().get().unwrap();
        frag0_len = *(&*frag_list).len().get().unwrap();
    }

    // kskb2 should be equal to kskb
    let kskb2 = unsafe { bpf_rdonly_cast(kskb as *const c_void, tid_sk_buff() as u32) } as *const sk_buff;
    unsafe {
        kskb2_len = *(&*kskb2).len().get().unwrap();
    }
    0
}

#[link_section = "?tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn untrusted_ptr(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    let task_dup =
        unsafe { bpf_rdonly_cast(task as *const c_void, tid_task_struct() as u32) } as *mut task_struct;
    bpf_task_storage_get(&enter_id, task_dup, core::ptr::null(), 0);
    0
}

#[link_section = "?tracepoint/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn kctx_u64(ctx: *mut c_void) -> i32 {
    let kctx = unsafe { bpf_rdonly_cast(ctx, tid_u64() as u32) } as *mut u64;

    let _ = kctx;
    0
}

bpf_object!("GPL");
