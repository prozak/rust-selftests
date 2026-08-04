#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_global_data.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK};
use bpf_rs_core::helpers::{bpf_map_update_elem, bpf_map_update_elem_ptr};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct Foo {
    a: u8,
    b: u32,
    c: u64,
}

#[link_section = ".maps"]
#[no_mangle]
static result_number: BpfMap<u32, u64, { maps::ARRAY }, 11> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static result_string: BpfMap<u32, [u8; 32], { maps::ARRAY }, 5> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static result_struct: BpfMap<u32, Foo, { maps::ARRAY }, 5> = BpfMap::new();

// Relocation tests for __u64s.
#[no_mangle]
static mut num0: u64 = 0;
#[no_mangle]
static mut num1: u64 = 42;
#[link_section = ".rodata"]
#[no_mangle]
static num2: u64 = 24;
#[no_mangle]
static mut num3: u64 = 0;
#[no_mangle]
static mut num4: u64 = 0xffeeff;
#[link_section = ".rodata"]
#[no_mangle]
static num5: u64 = 0xabab;
#[link_section = ".rodata"]
#[no_mangle]
static num6: u64 = 0xab;

// Relocation tests for strings.
#[link_section = ".rodata"]
#[no_mangle]
static str0: [u8; 32] = *b"abcdefghijklmnopqrstuvwxyz\0\0\0\0\0\0";
#[no_mangle]
static mut str1: [u8; 32] = *b"abcdefghijklmnopqrstuvwxyz\0\0\0\0\0\0";
#[no_mangle]
static mut str2: [u8; 32] = [0; 32];

// Relocation tests for structs.
#[link_section = ".rodata"]
#[no_mangle]
static struct0: Foo = Foo {
    a: 42,
    b: 0xfefeefef,
    c: 0x1111111111111111,
};
#[no_mangle]
static mut struct1: Foo = Foo { a: 0, b: 0, c: 0 };
#[link_section = ".rodata"]
#[no_mangle]
static struct2: Foo = Foo { a: 0, b: 0, c: 0 };
#[no_mangle]
static mut struct3: Foo = Foo {
    a: 41,
    b: 0xeeeeefef,
    c: 0x2111111111111111,
};

#[link_section = "tc"]
#[no_mangle]
extern "C" fn load_static_data(_skb: *const __sk_buff) -> i32 {
    let bar: u64 = !0u64;

    let key: u32 = 0;
    bpf_map_update_elem_ptr(
        &result_number,
        &key,
        core::ptr::addr_of_mut!(num0) as *const c_void,
        0,
    );
    let key: u32 = 1;
    bpf_map_update_elem_ptr(
        &result_number,
        &key,
        core::ptr::addr_of_mut!(num1) as *const c_void,
        0,
    );
    let key: u32 = 2;
    bpf_map_update_elem(&result_number, &key, &num2, 0);
    let key: u32 = 3;
    bpf_map_update_elem_ptr(
        &result_number,
        &key,
        core::ptr::addr_of_mut!(num3) as *const c_void,
        0,
    );
    let key: u32 = 4;
    bpf_map_update_elem_ptr(
        &result_number,
        &key,
        core::ptr::addr_of_mut!(num4) as *const c_void,
        0,
    );
    let key: u32 = 5;
    bpf_map_update_elem(&result_number, &key, &num5, 0);

    unsafe {
        num4 = 1234;
    }

    let key: u32 = 6;
    bpf_map_update_elem_ptr(
        &result_number,
        &key,
        core::ptr::addr_of_mut!(num4) as *const c_void,
        0,
    );
    let key: u32 = 7;
    bpf_map_update_elem_ptr(
        &result_number,
        &key,
        core::ptr::addr_of_mut!(num0) as *const c_void,
        0,
    );
    let key: u32 = 8;
    bpf_map_update_elem(&result_number, &key, &num6, 0);

    let key: u32 = 0;
    bpf_map_update_elem(&result_string, &key, &str0, 0);
    let key: u32 = 1;
    bpf_map_update_elem_ptr(
        &result_string,
        &key,
        core::ptr::addr_of_mut!(str1) as *const c_void,
        0,
    );
    let key: u32 = 2;
    bpf_map_update_elem_ptr(
        &result_string,
        &key,
        core::ptr::addr_of_mut!(str2) as *const c_void,
        0,
    );

    unsafe {
        (core::ptr::addr_of_mut!(str1) as *mut u8)
            .add(5)
            .write(b'x');
    }

    let key: u32 = 3;
    bpf_map_update_elem_ptr(
        &result_string,
        &key,
        core::ptr::addr_of_mut!(str1) as *const c_void,
        0,
    );

    unsafe {
        let dst = core::ptr::addr_of_mut!(str2) as *mut u8;
        dst.add(2).write(b'h');
        dst.add(3).write(b'e');
        dst.add(4).write(b'l');
        dst.add(5).write(b'l');
        dst.add(6).write(b'o');
        dst.add(7).write(0);
    }

    let key: u32 = 4;
    bpf_map_update_elem_ptr(
        &result_string,
        &key,
        core::ptr::addr_of_mut!(str2) as *const c_void,
        0,
    );

    let key: u32 = 0;
    bpf_map_update_elem(&result_struct, &key, &struct0, 0);
    let key: u32 = 1;
    bpf_map_update_elem_ptr(
        &result_struct,
        &key,
        core::ptr::addr_of_mut!(struct1) as *const c_void,
        0,
    );
    let key: u32 = 2;
    bpf_map_update_elem(&result_struct, &key, &struct2, 0);
    let key: u32 = 3;
    bpf_map_update_elem_ptr(
        &result_struct,
        &key,
        core::ptr::addr_of_mut!(struct3) as *const c_void,
        0,
    );

    let key: u32 = 9;
    bpf_map_update_elem(&result_number, &key, &struct0.c, 0);
    let key: u32 = 10;
    bpf_map_update_elem(&result_number, &key, &bar, 0);

    TC_ACT_OK
}

bpf_object!("GPL");
