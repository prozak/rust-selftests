#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func9.c
// (bpf-rs-core idiom). __success test: a set of noinline global functions
// exercising every argument shape the verifier's global-func BTF classifier
// accepts (struct ptr, plain scalar ptr, volatile scalar ptr, enum ptr,
// fixed-size array ptr, pointer-to-pointer).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_prandom_u32, bpf_map_lookup_elem};
use bpf_rs_core::maps::{self, BpfMap};

#[repr(C)]
struct S {
    x: i32,
}

#[repr(C)]
struct C {
    x: i32,
    y: i32,
}

#[repr(i32)]
#[derive(Clone, Copy)]
enum E {
    EItem = 0,
}

#[link_section = ".maps"]
#[no_mangle]
static map: BpfMap<u32, S, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut global_data_x: i32 = 100;

#[no_mangle]
static mut global_data_y: i32 = 500;

#[no_mangle]
#[inline(never)]
pub extern "C" fn foo(s: *const S) -> i32 {
    if !s.is_null() {
        let x = unsafe { (*s).x };
        return (bpf_get_prandom_u32() < x as u32) as i32;
    }

    0
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn bar(x: *mut i32) -> i32 {
    if !x.is_null() {
        unsafe {
            *x &= bpf_get_prandom_u32() as i32;
        }
    }

    0
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn baz(x: *mut i32) -> i32 {
    if !x.is_null() {
        unsafe {
            let v = core::ptr::read_volatile(x);
            core::ptr::write_volatile(x, v & bpf_get_prandom_u32() as i32);
        }
    }

    0
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn qux(e: *mut E) -> i32 {
    if !e.is_null() {
        return unsafe { *e as i32 };
    }

    0
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn quux(arr: *mut [i32; 10]) -> i32 {
    if !arr.is_null() {
        return unsafe { (*arr)[9] };
    }

    0
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn quuz(p: *mut *mut i32) -> i32 {
    if !p.is_null() {
        unsafe {
            *p = core::ptr::null_mut();
        }
    }

    0
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
pub extern "C" fn global_func9(skb: *const __sk_buff) -> i32 {
    let mut result: i32 = 0;

    {
        let s = S {
            x: unsafe { (*skb).len as i32 },
        };
        result |= foo(&s as *const S);
    }

    {
        let key: u32 = 1;
        let s = bpf_map_lookup_elem(&map, &key) as *const S;
        result |= foo(s);
    }

    {
        let c = C {
            x: unsafe { (*skb).len as i32 },
            y: unsafe { (*skb).family as i32 },
        };
        result |= foo(&c as *const C as *const S);
    }

    {
        result |= foo(core::ptr::null());
    }

    {
        bar(&mut result as *mut i32);
        bar(core::ptr::addr_of_mut!(global_data_x));
    }

    {
        result |= baz(core::ptr::addr_of_mut!(global_data_y));
    }

    {
        let mut e = E::EItem;
        result |= qux(&mut e as *mut E);
    }

    {
        let mut array: [i32; 10] = [0; 10];
        result |= quux(&mut array as *mut [i32; 10]);
    }

    {
        let mut p: *mut i32 = core::ptr::null_mut();
        result |= quuz(&mut p as *mut *mut i32);
    }

    if result != 0 {
        1
    } else {
        0
    }
}

bpf_object!("GPL");
