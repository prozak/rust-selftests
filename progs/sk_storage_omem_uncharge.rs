#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/sk_storage_omem_uncharge.c
// (bpf-rs-core idiom).
//
// C's `sk->sk_cookie` is `#define sk_cookie __sk_common.skc_cookie`
// (include/net/sock.h); the CO-RE field path below spells that out
// explicitly since Rust has no equivalent macro alias.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_sk_storage_get;
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;
use core::ffi::c_void;

#[btf]
struct atomic_t {
    counter: i32,
}

#[btf]
struct atomic64_t {
    counter: i64,
}

#[btf]
struct sock_common {
    skc_cookie: atomic64_t,
}

#[btf]
struct sock {
    __sk_common: sock_common,
    sk_omem_alloc: atomic_t,
}

bpf_map! {
    sk_storage {
        r#type: *const [i32; 24],  // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const i32,
    }
}

#[no_mangle]
static mut sk_ptr: *mut c_void = core::ptr::null_mut();
#[no_mangle]
static mut cookie_found: i32 = 0;
#[no_mangle]
static mut cookie: u64 = 0;
#[no_mangle]
static mut omem: u32 = 0;

#[link_section = "fexit/bpf_sk_storage_free"]
#[no_mangle]
extern "C" fn bpf_sk_storage_free(ctx: *const u64) -> i32 {
    let sk = arg(ctx, 0) as *mut sock;

    if unsafe { sk_ptr } != sk as *mut c_void {
        return 0;
    }

    let sk_cookie = unsafe { *(&*sk).__sk_common().skc_cookie().counter().as_ptr() } as u64;
    if sk_cookie != unsafe { cookie } {
        return 0;
    }

    unsafe { cookie_found += 1 };
    unsafe { omem = *(&*sk).sk_omem_alloc().counter().as_ptr() as u32 };

    0
}

#[link_section = "fentry/inet6_sock_destruct"]
#[no_mangle]
extern "C" fn inet6_sock_destruct(ctx: *const u64) -> i32 {
    let sk = arg(ctx, 0) as *mut sock;

    let cur_cookie = unsafe { cookie };
    if cur_cookie == 0 {
        return 0;
    }
    let sk_cookie = unsafe { *(&*sk).__sk_common().skc_cookie().counter().as_ptr() } as u64;
    if sk_cookie != cur_cookie {
        return 0;
    }

    let value = bpf_sk_storage_get(&sk_storage, sk, core::ptr::null_mut(), 0) as *mut i32;
    if !value.is_null() && unsafe { *value } == 0xdeadbeefu32 as i32 {
        unsafe { cookie_found += 1 };
        unsafe { sk_ptr = sk as *mut c_void };
    }

    0
}

bpf_object!("GPL");
