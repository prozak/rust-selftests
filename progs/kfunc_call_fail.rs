#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/kfunc_call_fail.c
// (bpf-rs-core idiom).
//
// Every program here is a deliberate verifier-rejection or runtime-error
// case (see prog_tests/kfunc_call.c's kfunc_tests[] table): the kernel
// verifier/kfunc argument checks reject these programs (or the kfunc
// itself errors at runtime) purely from the *operations performed*, with
// no reliance on __failure/__msg decl tags. So a faithful operation-level
// translation reproduces the same kernel-side outcome.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use core::ffi::c_void;

#[repr(C)]
struct prog_test_ref_kfunc {
    _opaque: [u8; 0],
}

struct syscall_test_args {
    data: [u8; 16],
    size: usize,
}

extern "C" {
    fn bpf_kfunc_call_test_mem_len_pass1(mem: *mut c_void, len: i32);
    fn bpf_kfunc_call_test_acquire(scalar_ptr: *mut u64) -> *mut prog_test_ref_kfunc;
    fn bpf_kfunc_call_test_release(p: *mut prog_test_ref_kfunc);
    fn bpf_kfunc_call_test_get_rdwr_mem(p: *mut prog_test_ref_kfunc, size: i32) -> *mut i32;
    fn bpf_kfunc_call_test_get_rdonly_mem(p: *mut prog_test_ref_kfunc, size: i32) -> *mut i32;
    fn bpf_kfunc_call_test_acq_rdonly_mem(p: *mut prog_test_ref_kfunc, size: i32) -> *mut i32;
    fn bpf_kfunc_call_int_mem_release(p: *mut i32);
    fn bpf_kfunc_call_test_pass_ctx(skb: *mut __sk_buff);
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn kfunc_syscall_test_fail(args: *mut syscall_test_args) -> i32 {
    unsafe {
        bpf_kfunc_call_test_mem_len_pass1(
            core::ptr::addr_of_mut!((*args).data) as *mut c_void,
            (core::mem::size_of::<syscall_test_args>() + 1) as i32,
        );
    }
    0
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn kfunc_syscall_test_null_fail(args: *mut syscall_test_args) -> i32 {
    // Must be called with args as a NULL pointer: we don't check for it,
    // so the verifier considers the pointer might not be null and loads
    // the program; it then dynamically fails when actually run with NULL.
    unsafe {
        bpf_kfunc_call_test_mem_len_pass1(
            args as *mut c_void,
            core::mem::size_of::<syscall_test_args>() as i32,
        );
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn kfunc_call_test_get_mem_fail_rdonly(_skb: *const __sk_buff) -> i32 {
    let mut s: u64 = 0;
    let mut ret: i32 = 0;
    unsafe {
        let pt = bpf_kfunc_call_test_acquire(&mut s);
        if !pt.is_null() {
            let p = bpf_kfunc_call_test_get_rdonly_mem(pt, (2 * core::mem::size_of::<i32>()) as i32);
            if !p.is_null() {
                *p = 42; // read-only buffer, so -EACCES
            } else {
                ret = -1;
            }
            bpf_kfunc_call_test_release(pt);
        }
    }
    ret
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn kfunc_call_test_get_mem_fail_use_after_free(_skb: *const __sk_buff) -> i32 {
    let mut s: u64 = 0;
    let mut p: *mut i32 = core::ptr::null_mut();
    let mut ret: i32 = 0;
    unsafe {
        let pt = bpf_kfunc_call_test_acquire(&mut s);
        if !pt.is_null() {
            p = bpf_kfunc_call_test_get_rdwr_mem(pt, (2 * core::mem::size_of::<i32>()) as i32);
            if !p.is_null() {
                *p = 42;
                ret = *p.add(1); /* 108 */
            } else {
                ret = -1;
            }
            bpf_kfunc_call_test_release(pt);
        }
        if !p.is_null() {
            ret = *p; /* p is not valid anymore */
        }
    }
    ret
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn kfunc_call_test_get_mem_fail_oob(_skb: *const __sk_buff) -> i32 {
    let mut s: u64 = 0;
    let mut ret: i32 = 0;
    unsafe {
        let pt = bpf_kfunc_call_test_acquire(&mut s);
        if !pt.is_null() {
            let p = bpf_kfunc_call_test_get_rdonly_mem(pt, (2 * core::mem::size_of::<i32>()) as i32);
            if !p.is_null() {
                ret = *p.add(2 * core::mem::size_of::<i32>()); /* oob access, so -EACCES */
            } else {
                ret = -1;
            }
            bpf_kfunc_call_test_release(pt);
        }
    }
    ret
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn kfunc_call_test_get_mem_fail_oversized(_skb: *const __sk_buff) -> i32 {
    // rdwr_buf_size is a const int, so a C literal would be narrowed to 32
    // bits before the call. Declare this one call site's kfunc with a
    // 64-bit size parameter so the full 64-bit value 2^64 - 192
    // (0xffffffffffffff40, > U32_MAX) reaches the call in the argument
    // register: the verifier records r0_size from the full register value
    // and must reject it before that value is truncated into R0's u32
    // mem_size. (Only the symbol name is load-bearing for the kfunc
    // relocation, so a locally mismatched Rust signature is fine here.)
    extern "C" {
        fn bpf_kfunc_call_test_get_rdwr_mem(p: *mut prog_test_ref_kfunc, size: i64) -> *mut i32;
    }

    let mut s: u64 = 0;
    let ret: i32 = 0;
    unsafe {
        let pt = bpf_kfunc_call_test_acquire(&mut s);
        if !pt.is_null() {
            bpf_kfunc_call_test_get_rdwr_mem(pt, 0xffffffffffffff40u64 as i64);
            bpf_kfunc_call_test_release(pt);
        }
    }
    ret
}

#[no_mangle]
static mut not_const_size: i32 = (2 * core::mem::size_of::<i32>()) as i32;

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn kfunc_call_test_get_mem_fail_not_const(_skb: *const __sk_buff) -> i32 {
    let mut s: u64 = 0;
    let mut ret: i32 = 0;
    unsafe {
        let pt = bpf_kfunc_call_test_acquire(&mut s);
        if !pt.is_null() {
            let sz = core::ptr::read_volatile(core::ptr::addr_of!(not_const_size));
            let p = bpf_kfunc_call_test_get_rdonly_mem(pt, sz); /* non const size, -EINVAL */
            if !p.is_null() {
                ret = *p;
            } else {
                ret = -1;
            }
            bpf_kfunc_call_test_release(pt);
        }
    }
    ret
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn kfunc_call_test_mem_acquire_fail(_skb: *const __sk_buff) -> i32 {
    let mut s: u64 = 0;
    let mut ret: i32 = 0;
    unsafe {
        let pt = bpf_kfunc_call_test_acquire(&mut s);
        if !pt.is_null() {
            // We are failing on this one, because we are not acquiring a
            // PTR_TO_BTF_ID (a struct ptr).
            let p = bpf_kfunc_call_test_acq_rdonly_mem(pt, (2 * core::mem::size_of::<i32>()) as i32);
            if !p.is_null() {
                ret = *p;
            } else {
                ret = -1;
            }
            bpf_kfunc_call_int_mem_release(p);
            bpf_kfunc_call_test_release(pt);
        }
    }
    ret
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn kfunc_call_test_pointer_arg_type_mismatch(_skb: *const __sk_buff) -> i32 {
    unsafe {
        bpf_kfunc_call_test_pass_ctx(10 as *mut __sk_buff);
    }
    0
}

bpf_object!("GPL");
