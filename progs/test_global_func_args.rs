#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_global_func_args.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_map_update_elem;
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{vload, vstore};

#[repr(C)]
struct S {
    v: i32,
}

#[no_mangle]
static mut global_variable: S = S { v: 0 };

#[link_section = ".maps"]
#[no_mangle]
static values: BpfMap<u32, i32, { maps::ARRAY }, 7> = BpfMap::new();

#[inline(always)]
fn save_value(index: u32, value: i32) {
    bpf_map_update_elem(&values, &index, &value, 0);
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn foo(index: u32, s: *mut S) -> i32 {
    if !s.is_null() {
        let v = unsafe { (*s).v };
        save_value(index, v);
        let nv = v + 1;
        unsafe {
            (*s).v = nv;
        }
        return nv;
    }

    save_value(index, 0);

    1
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn bar(index: u32, s: *mut S) -> i32 {
    if !s.is_null() {
        let v = vload!((*s).v);
        save_value(index, v);
        let nv = v + 1;
        vstore!((*s).v, nv);
        return nv;
    }

    save_value(index, 0);

    1
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn baz(s: *mut *mut S) -> i32 {
    if !s.is_null() {
        unsafe {
            *s = core::ptr::null_mut();
        }
    }

    0
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
pub extern "C" fn test_cls(_skb: *const __sk_buff) -> i32 {
    let mut index: u32 = 0;

    {
        let v = foo(index, core::ptr::null_mut());
        index += 1;

        save_value(index, v);
        index += 1;
    }

    {
        let mut s = S { v: 100 };

        foo(index, &mut s as *mut S);
        index += 1;

        save_value(index, s.v);
        index += 1;
    }

    {
        unsafe {
            global_variable.v = 42;
        }
        bar(index, core::ptr::addr_of_mut!(global_variable));
        index += 1;

        save_value(index, unsafe { global_variable.v });
        index += 1;
    }

    {
        let mut v = S { v: 0 };
        let mut p: *mut S = &mut v as *mut S;

        baz(&mut p as *mut *mut S);
        save_value(index, p.is_null() as i32);
        index += 1;
    }

    let _ = index;

    0
}

bpf_object!("GPL");
