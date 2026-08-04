#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_check_mtu.c
// (bpf-rs-core idiom).

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_check_mtu;
use bpf_rs_core::{bpf_object, vload};
use core::ffi::c_void;

const XDP_ABORTED: i32 = 0;
const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

const BPF_OK: i32 = 0;
const BPF_DROP: i32 = 2;
const BPF_REDIRECT: i32 = 7;

const BPF_MTU_CHK_SEGS: u64 = 1 << 0;
const BPF_MTU_CHK_RET_FRAG_NEEDED: i64 = 1;

const ETH_HLEN: i32 = 14;
const EINVAL: i64 = 22;

/// UAPI struct xdp_md (linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

/* Userspace will update with MTU it can see on device */
#[link_section = ".rodata"]
#[no_mangle]
static GLOBAL_USER_MTU: i32 = 0;
#[link_section = ".rodata"]
#[no_mangle]
static GLOBAL_USER_IFINDEX: u32 = 0;

fn global_user_mtu() -> i32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GLOBAL_USER_MTU)) }
}

fn global_user_ifindex() -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GLOBAL_USER_IFINDEX)) }
}

/* BPF-prog will update these with MTU values it can see */
#[no_mangle]
static mut global_bpf_mtu_xdp: u32 = 0;
#[no_mangle]
static mut global_bpf_mtu_tc: u32 = 0;

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_use_helper_basic(ctx: *const xdp_md) -> i32 {
    let mut mtu_len: u32 = 0;

    if bpf_check_mtu(ctx as *const c_void, 0, &mut mtu_len, 0, 0) != 0 {
        return XDP_ABORTED;
    }

    XDP_PASS
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_use_helper(ctx: *const xdp_md) -> i32 {
    let mut retval = XDP_PASS; /* Expected retval on successful test */
    let mut mtu_len: u32 = 0;
    let mut ifindex: u32 = 0;
    let delta: i32 = 0;

    /* When ifindex is zero, save net_device lookup and use ctx netdev */
    if global_user_ifindex() > 0 {
        ifindex = global_user_ifindex();
    }

    if bpf_check_mtu(ctx as *const c_void, ifindex, &mut mtu_len, delta, 0) != 0 {
        /* mtu_len is also valid when check fail */
        retval = XDP_ABORTED;
    } else if mtu_len != global_user_mtu() as u32 {
        retval = XDP_DROP;
    }

    unsafe {
        global_bpf_mtu_xdp = mtu_len;
    }
    retval
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_exceed_mtu(ctx: *const xdp_md) -> i32 {
    let data_end = vload!((*ctx).data_end) as i32;
    let data = vload!((*ctx).data) as i32;
    let ifindex = global_user_ifindex();
    let data_len = data_end - data;
    let mut retval = XDP_ABORTED; /* Fail */
    let mut mtu_len: u32 = 0;

    /* Exceed MTU with 1 via delta adjust */
    let delta: i32 = global_user_mtu() - (data_len - ETH_HLEN) + 1;

    let err = bpf_check_mtu(ctx as *const c_void, ifindex, &mut mtu_len, delta, 0);
    if err != 0 {
        retval = XDP_PASS; /* Success in exceeding MTU check */
        if err != BPF_MTU_CHK_RET_FRAG_NEEDED {
            retval = XDP_DROP;
        }
    }

    unsafe {
        global_bpf_mtu_xdp = mtu_len;
    }
    retval
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_minus_delta(ctx: *const xdp_md) -> i32 {
    let mut retval = XDP_PASS; /* Expected retval on successful test */
    let data_end = vload!((*ctx).data_end) as i32;
    let data = vload!((*ctx).data) as i32;
    let ifindex = global_user_ifindex();
    let data_len = data_end - data;
    let mut mtu_len: u32 = 0;

    /* Borderline test case: Minus delta exceeding packet length allowed */
    let delta: i32 = -((data_len - ETH_HLEN) + 1);

    /* Minus length (adjusted via delta) still pass MTU check, other helpers
     * are responsible for catching this, when doing actual size adjust
     */
    if bpf_check_mtu(ctx as *const c_void, ifindex, &mut mtu_len, delta, 0) != 0 {
        retval = XDP_ABORTED;
    }

    unsafe {
        global_bpf_mtu_xdp = mtu_len;
    }
    retval
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_input_len(ctx: *const xdp_md) -> i32 {
    let mut retval = XDP_PASS; /* Expected retval on successful test */
    let data_end = vload!((*ctx).data_end) as i32;
    let data = vload!((*ctx).data) as i32;
    let ifindex = global_user_ifindex();
    let data_len = data_end - data;

    /* API allow user give length to check as input via mtu_len param,
     * resulting MTU value is still output in mtu_len param after call.
     *
     * Input len is L3, like MTU and iph->tot_len.
     * Remember XDP data_len is L2.
     */
    let mut mtu_len: u32 = (data_len - ETH_HLEN) as u32;

    if bpf_check_mtu(ctx as *const c_void, ifindex, &mut mtu_len, 0, 0) != 0 {
        retval = XDP_ABORTED;
    }

    unsafe {
        global_bpf_mtu_xdp = mtu_len;
    }
    retval
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_input_len_exceed(ctx: *const xdp_md) -> i32 {
    let mut retval = XDP_ABORTED; /* Fail */
    let ifindex = global_user_ifindex();

    /* API allow user give length to check as input via mtu_len param,
     * resulting MTU value is still output in mtu_len param after call.
     *
     * Input length value is L3 size like MTU.
     */
    let mut mtu_len: u32 = global_user_mtu() as u32;

    mtu_len += 1; /* Exceed with 1 */

    let err = bpf_check_mtu(ctx as *const c_void, ifindex, &mut mtu_len, 0, 0);
    if err == BPF_MTU_CHK_RET_FRAG_NEEDED {
        retval = XDP_PASS; /* Success in exceeding MTU check */
    }

    unsafe {
        global_bpf_mtu_xdp = mtu_len;
    }
    retval
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_use_helper(ctx: *const __sk_buff) -> i32 {
    let mut retval = BPF_OK; /* Expected retval on successful test */
    let mut mtu_len: u32 = 0;
    let delta: i32 = 0;

    if bpf_check_mtu(ctx as *const c_void, 0, &mut mtu_len, delta, 0) != 0 {
        retval = BPF_DROP;
    } else if mtu_len != global_user_mtu() as u32 {
        retval = BPF_REDIRECT;
    }

    unsafe {
        global_bpf_mtu_tc = mtu_len;
    }
    retval
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_exceed_mtu(ctx: *const __sk_buff) -> i32 {
    let ifindex = global_user_ifindex();
    let mut retval = BPF_DROP; /* Fail */
    let skb_len = vload!((*ctx).len) as i32;
    let mut mtu_len: u32 = 0;

    /* Exceed MTU with 1 via delta adjust */
    let delta: i32 = global_user_mtu() - (skb_len - ETH_HLEN) + 1;

    let err = bpf_check_mtu(ctx as *const c_void, ifindex, &mut mtu_len, delta, 0);
    if err != 0 {
        retval = BPF_OK; /* Success in exceeding MTU check */
        if err != BPF_MTU_CHK_RET_FRAG_NEEDED {
            retval = BPF_DROP;
        }
    }

    unsafe {
        global_bpf_mtu_tc = mtu_len;
    }
    retval
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_exceed_mtu_da(ctx: *const __sk_buff) -> i32 {
    /* SKB Direct-Access variant */
    let data_end = vload!((*ctx).data_end) as i32;
    let data = vload!((*ctx).data) as i32;
    let ifindex = global_user_ifindex();
    let data_len = data_end - data;
    let mut retval = BPF_DROP; /* Fail */
    let mut mtu_len: u32 = 0;

    /* Exceed MTU with 1 via delta adjust */
    let delta: i32 = global_user_mtu() - (data_len - ETH_HLEN) + 1;

    let err = bpf_check_mtu(ctx as *const c_void, ifindex, &mut mtu_len, delta, 0);
    if err != 0 {
        retval = BPF_OK; /* Success in exceeding MTU check */
        if err != BPF_MTU_CHK_RET_FRAG_NEEDED {
            retval = BPF_DROP;
        }
    }

    unsafe {
        global_bpf_mtu_tc = mtu_len;
    }
    retval
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_minus_delta(ctx: *const __sk_buff) -> i32 {
    let mut retval = BPF_OK; /* Expected retval on successful test */
    let ifindex = global_user_ifindex();
    let skb_len = vload!((*ctx).len) as i32;
    let mut mtu_len: u32 = 0;

    /* Borderline test case: Minus delta exceeding packet length allowed */
    let delta: i32 = -((skb_len - ETH_HLEN) + 1);

    /* Minus length (adjusted via delta) still pass MTU check, other helpers
     * are responsible for catching this, when doing actual size adjust
     */
    if bpf_check_mtu(ctx as *const c_void, ifindex, &mut mtu_len, delta, 0) != 0 {
        retval = BPF_DROP;
    }

    unsafe {
        global_bpf_mtu_xdp = mtu_len;
    }
    retval
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_input_len(ctx: *const __sk_buff) -> i32 {
    let mut retval = BPF_OK; /* Expected retval on successful test */
    let ifindex = global_user_ifindex();

    /* API allow user give length to check as input via mtu_len param,
     * resulting MTU value is still output in mtu_len param after call.
     *
     * Input length value is L3 size.
     */
    let mut mtu_len: u32 = global_user_mtu() as u32;

    if bpf_check_mtu(ctx as *const c_void, ifindex, &mut mtu_len, 0, 0) != 0 {
        retval = BPF_DROP;
    }

    unsafe {
        global_bpf_mtu_xdp = mtu_len;
    }
    retval
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_input_len_exceed(ctx: *const __sk_buff) -> i32 {
    let mut retval = BPF_DROP; /* Fail */
    let ifindex = global_user_ifindex();

    /* API allow user give length to check as input via mtu_len param,
     * resulting MTU value is still output in mtu_len param after call.
     *
     * Input length value is L3 size like MTU.
     */
    let mut mtu_len: u32 = global_user_mtu() as u32;

    mtu_len += 1; /* Exceed with 1 */

    let err = bpf_check_mtu(ctx as *const c_void, ifindex, &mut mtu_len, 0, 0);
    if err == BPF_MTU_CHK_RET_FRAG_NEEDED {
        retval = BPF_OK; /* Success in exceeding MTU check */
    }

    unsafe {
        global_bpf_mtu_xdp = mtu_len;
    }
    retval
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_chk_segs_flag(ctx: *const __sk_buff) -> i32 {
    let mut mtu_len: u32 = 0;

    let err = bpf_check_mtu(
        ctx as *const c_void,
        global_user_ifindex(),
        &mut mtu_len,
        0,
        BPF_MTU_CHK_SEGS,
    );

    if err == -EINVAL {
        BPF_OK
    } else {
        BPF_DROP
    }
}

bpf_object!("GPL");
