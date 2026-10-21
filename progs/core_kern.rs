// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of progs/core_kern.c (bpf-rs-core idiom): CO-RE relocations
// in a big program the light skeleton loads (prog_tests/core_kern.c).
// Three tracing programs feed a noinline subprog that picks one of two
// array maps at random and stores prandom + v + dev->mtu; balancer_ingress
// is test_verif_scale1's 90-step jhash scan (same bounded-loop shape as
// test_verif_scale1.rs, with the C's __always_inline jhash) plus a dead
// branch on the .rodata `never` holding two CO-RE field reads: one on a
// struct vmlinux does not have (libbpf poisons it, the verifier prunes
// it) and one on bpf_testmod's struct (resolves only when the module is
// loaded). core_relo_proto's bpf_core_type_exists() on three func-proto
// typedefs are the `// BTF_TYPE_INFO:` externs (scripts/type_id.py): the
// ___match / ___doesnt_match flavors are compared to vmlinux's
// func_proto_typedef by essential name, the nested one through its
// parameter's typedef.
// BTF_TYPE_INFO: func_proto_typedef_match_exists exists typedef func_proto_typedef___match
// BTF_TYPE_INFO: func_proto_typedef_doesnt_match_exists exists typedef func_proto_typedef___doesnt_match
// BTF_TYPE_INFO: func_proto_typedef_nested1_exists exists typedef func_proto_typedef_nested1

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_prandom_u32, bpf_map_lookup_elem};
use bpf_rs_core::maps;
use bpf_rs_core::progs::fentry_arg;
use bpf_rs_core::{bpf_map, vload, vstore};
use btf_macros::btf;

extern "C" {
    fn func_proto_typedef_match_exists() -> u32;
    fn func_proto_typedef_doesnt_match_exists() -> u32;
    fn func_proto_typedef_nested1_exists() -> u32;
}

const JHASH_INITVAL: u32 = 0xdeadbeef;

#[inline(always)]
fn jhash_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*c);
    *a ^= c.rotate_left(4);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= a.rotate_left(6);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= b.rotate_left(8);
    *b = b.wrapping_add(*a);
    *a = a.wrapping_sub(*c);
    *a ^= c.rotate_left(16);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= a.rotate_left(19);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= b.rotate_left(4);
    *b = b.wrapping_add(*a);
}

#[inline(always)]
fn jhash_final(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b;
    *c = c.wrapping_sub(b.rotate_left(14));
    *a ^= *c;
    *a = a.wrapping_sub(c.rotate_left(11));
    *b ^= *a;
    *b = b.wrapping_sub(a.rotate_left(25));
    *c ^= *b;
    *c = c.wrapping_sub(b.rotate_left(16));
    *a ^= *c;
    *a = a.wrapping_sub(c.rotate_left(4));
    *b ^= *a;
    *b = b.wrapping_sub(a.rotate_left(14));
    *c ^= *b;
    *c = c.wrapping_sub(b.rotate_left(24));
}

#[inline(always)]
fn jhash(key: *const u8, length: u32, initval: u32) -> u32 {
    let mut a = JHASH_INITVAL.wrapping_add(length).wrapping_add(initval);
    let mut b = a;
    let mut c = a;
    let mut k = key;
    let mut len = length;

    while len > 12 {
        unsafe {
            a = a.wrapping_add(core::ptr::read_volatile(k as *const u32));
            b = b.wrapping_add(core::ptr::read_volatile(k.add(4) as *const u32));
            c = c.wrapping_add(core::ptr::read_volatile(k.add(8) as *const u32));
        }
        jhash_mix(&mut a, &mut b, &mut c);
        len -= 12;
        k = unsafe { k.add(12) };
    }

    unsafe {
        if len >= 12 {
            c = c.wrapping_add((*k.add(11) as u32) << 24);
        }
        if len >= 11 {
            c = c.wrapping_add((*k.add(10) as u32) << 16);
        }
        if len >= 10 {
            c = c.wrapping_add((*k.add(9) as u32) << 8);
        }
        if len >= 9 {
            c = c.wrapping_add(*k.add(8) as u32);
        }
        if len >= 8 {
            b = b.wrapping_add((*k.add(7) as u32) << 24);
        }
        if len >= 7 {
            b = b.wrapping_add((*k.add(6) as u32) << 16);
        }
        if len >= 6 {
            b = b.wrapping_add((*k.add(5) as u32) << 8);
        }
        if len >= 5 {
            b = b.wrapping_add(*k.add(4) as u32);
        }
        if len >= 4 {
            a = a.wrapping_add((*k.add(3) as u32) << 24);
        }
        if len >= 3 {
            a = a.wrapping_add((*k.add(2) as u32) << 16);
        }
        if len >= 2 {
            a = a.wrapping_add((*k.add(1) as u32) << 8);
        }
        if len >= 1 {
            a = a.wrapping_add(*k as u32);
            c ^= a;
            jhash_final(&mut a, &mut b, &mut c);
        }
    }

    c
}

bpf_map! {
    array1 {
        r#type: *const [i32; maps::ARRAY],
        key: *const u32,
        value: *const u32,
        max_entries: *const [i32; 256],
    }
}

bpf_map! {
    array2 {
        r#type: *const [i32; maps::ARRAY],
        key: *const u32,
        value: *const u32,
        max_entries: *const [i32; 256],
    }
}

#[btf]
struct net_device {
    ifindex: i32,
    mtu: u32,
}

#[btf]
struct sk_buff {
    len: u32,
}

#[inline(never)]
fn randmap(v: i32, dev: *const net_device) -> i32 {
    unsafe {
        let mut map = addr_of!(array1) as *const c_void;
        let key: i32 = (bpf_get_prandom_u32() & 0xff) as i32;

        if bpf_get_prandom_u32() & 1 != 0 {
            map = addr_of!(array2) as *const c_void;
        }

        let val = bpf_map_lookup_elem(map, &key) as *mut i32;
        if !val.is_null() {
            let mtu = *(&*dev).mtu().as_ptr();
            *val = bpf_get_prandom_u32().wrapping_add(v as u32).wrapping_add(mtu) as i32;
        }
    }
    0
}

#[link_section = "tp_btf/xdp_devmap_xmit"]
#[no_mangle]
extern "C" fn tp_xdp_devmap_xmit_multi(ctx: *const u64) -> i32 {
    let from_dev = fentry_arg(ctx, 0) as *const net_device;
    let ifindex = unsafe { *(&*from_dev).ifindex().as_ptr() };
    randmap(ifindex, from_dev)
}

#[link_section = "fentry/eth_type_trans"]
#[no_mangle]
extern "C" fn fentry_eth_type_trans(ctx: *const u64) -> i32 {
    let skb = fentry_arg(ctx, 0) as *const sk_buff;
    let dev = fentry_arg(ctx, 1) as *const net_device;
    let (ifindex, len) = unsafe { (*(&*dev).ifindex().as_ptr(), *(&*skb).len().as_ptr()) };
    randmap(ifindex.wrapping_add(len as i32), dev)
}

#[link_section = "fexit/eth_type_trans"]
#[no_mangle]
extern "C" fn fexit_eth_type_trans(ctx: *const u64) -> i32 {
    let skb = fentry_arg(ctx, 0) as *const sk_buff;
    let dev = fentry_arg(ctx, 1) as *const net_device;
    let (ifindex, len) = unsafe { (*(&*dev).ifindex().as_ptr(), *(&*skb).len().as_ptr()) };
    randmap(ifindex.wrapping_add(len as i32), dev)
}

#[link_section = ".rodata"]
#[no_mangle]
static never: i32 = 0;

/// struct __sk_bUfF: it will not exist in vmlinux
#[btf]
#[allow(non_camel_case_types)]
struct __sk_bUfF {
    len: i32,
}

/// struct bpf_testmod_test_read_ctx: it exists in bpf_testmod
#[btf]
struct bpf_testmod_test_read_ctx {
    len: usize,
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn balancer_ingress(ctx: *mut __sk_buff) -> i32 {
    let data_end = vload!((*ctx).data_end) as usize;
    let data = vload!((*ctx).data) as usize;
    const NH_OFF: usize = 14;
    let mut i: i32 = 0;

    for _ in 0..90u32 {
        let ptr = data.wrapping_add(i as usize);
        if ptr + NH_OFF > data_end {
            break;
        }
        let cb0 = vload!((*ctx).cb[0]);
        let hash = jhash(ptr as *const u8, NH_OFF as u32, cb0.wrapping_add(i as u32));
        i = i.wrapping_add(1);
        vstore!((*ctx).tc_index, hash);
        if unsafe { read_volatile(addr_of!(never)) } != 0 {
            unsafe {
                // dead code with an unresolvable CO-RE relo
                i = i.wrapping_add(*(&*(ctx as *const __sk_bUfF)).len().as_ptr());
                // resolves only when bpf_testmod is loaded
                i = i.wrapping_add(*(&*(ctx as *const bpf_testmod_test_read_ctx)).len().as_ptr() as i32);
            }
        }
    }

    0
}

#[no_mangle]
static mut proto_out: [i32; 3] = [0; 3];

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn core_relo_proto(_ctx: *mut c_void) -> i32 {
    unsafe {
        let out = addr_of_mut!(proto_out) as *mut i32;
        write_volatile(out, func_proto_typedef_match_exists() as i32);
        write_volatile(out.add(1), func_proto_typedef_doesnt_match_exists() as i32);
        write_volatile(out.add(2), func_proto_typedef_nested1_exists() as i32);
    }
    0
}

// The C source names its license global `LICENSE`; the symbol name must
// match for the keep-list, so bpf_object! is written out.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
