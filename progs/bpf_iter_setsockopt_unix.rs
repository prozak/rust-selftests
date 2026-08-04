#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/bpf_iter_setsockopt_unix.c
// (bpf-rs-core idiom).
//
// unix_sk->addr is a real CO-RE-reachable kernel pointer field (unlike
// connect_unix_prog.c's opaque bpf_sock_addr_kern uaddr), so it is fetched
// through #[btf] like bpf_iter_setsockopt.rs's sk_common chases. From there
// the C source walks addr->name->sun_path: `name` is `struct sockaddr_un
// name[]`, a flexible array member embedded right after unix_address's
// `refcnt`/`len` (offset 8, no padding -- both are 4-byte ints), and
// `sun_path` sits right after sockaddr_un's 2-byte sun_family (offset 2,
// same constant getsockname_unix_prog.rs/connect_unix_prog.rs use). Both
// offsets are fixed UAPI/kernel-ABI layout, not something that varies across
// targets, so (mirroring those two files) they're read directly via
// bpf_probe_read_kernel instead of chaining more #[btf] hops through a
// flexible array member the macro has no vocabulary for.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_getsockopt, bpf_probe_read_kernel, bpf_setsockopt};
use btf_macros::btf;
use core::ffi::c_void;

const AUTOBIND_LEN: usize = 6;
const NR_CASES: usize = 5;

const SOL_SOCKET: i32 = 1;
const SO_SNDBUF: i32 = 7;

// offsetof(struct unix_address, name): refcount_t refcnt (4 bytes) + int len
// (4 bytes), no padding.
const NAME_OFFSET: usize = 8;
// offsetof(struct sockaddr_un, sun_path): __kernel_sa_family_t sun_family is
// 2 bytes, no padding.
const SUN_PATH_OFFSET: usize = 2;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__unix {
    meta: *mut bpf_iter_meta,
    unix_sk: *mut unix_sock,
}

#[btf]
struct unix_sock {
    addr: *mut u8,
}

#[no_mangle]
static mut sun_path: [u8; AUTOBIND_LEN] = [0; AUTOBIND_LEN];

#[no_mangle]
static mut sndbuf_setsockopt: [i32; NR_CASES] = [-1, 0, 8192, i32::MAX / 2, i32::MAX];
#[no_mangle]
static mut sndbuf_getsockopt: [i32; NR_CASES] = [-1, -1, -1, -1, -1];
#[no_mangle]
static mut sndbuf_getsockopt_expected: [i32; NR_CASES] = [0; NR_CASES];

#[link_section = "iter/unix"]
#[no_mangle]
extern "C" fn change_sndbuf(ctx: *const bpf_iter__unix) -> i32 {
    let ctx = unsafe { &*ctx };
    let unix_sk = ctx.unix_sk;
    if unix_sk.is_null() {
        return 0;
    }

    let unix_sk_ref = unsafe { &*unix_sk };
    let addr = unsafe { *unix_sk_ref.addr().as_ptr() };
    if addr.is_null() {
        return 0;
    }

    let sun_path_ptr = unsafe { addr.add(NAME_OFFSET + SUN_PATH_OFFSET) };
    let mut buf = [0u8; AUTOBIND_LEN];
    let ret = bpf_probe_read_kernel(&mut buf, AUTOBIND_LEN as u32, sun_path_ptr as *const c_void);
    if ret != 0 {
        return 0;
    }

    if buf[0] != 0 {
        return 0;
    }

    let mut i = 0usize;
    while i < AUTOBIND_LEN {
        if buf[i] != unsafe { sun_path[i] } {
            return 0;
        }
        i += 1;
    }

    let mut i = 0usize;
    while i < NR_CASES {
        let err = bpf_setsockopt(
            unix_sk as *mut c_void,
            SOL_SOCKET,
            SO_SNDBUF,
            unsafe { core::ptr::addr_of_mut!(sndbuf_setsockopt[i]) as *mut c_void },
            4,
        );
        if err != 0 {
            break;
        }

        let err = bpf_getsockopt(
            unix_sk as *mut c_void,
            SOL_SOCKET,
            SO_SNDBUF,
            unsafe { core::ptr::addr_of_mut!(sndbuf_getsockopt[i]) as *mut c_void },
            4,
        );
        if err != 0 {
            break;
        }

        i += 1;
    }

    0
}

bpf_object!("GPL");
