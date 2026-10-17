// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_helper_access_var_len.c, translated
// by hand; include!d by the generated progs/verifier_helper_access_var_len.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::{bpf_dynptr_from_mem, bpf_fib_lookup, bpf_load_hdr_opt, bpf_map_lookup_elem, bpf_snprintf, bpf_sysctl_get_name};

const XDP_PASS: i32 = 2;

/// The "ok" format string (the C's literal in .rodata).
static FMT_OK: [u8; 3] = *b"ok\0";

// HAND: writeonly_sized_input -- translate the C below (see the file comment)
//   SEC("tc")
//   __failure __msg("read from map forbidden")
//   int writeonly_sized_input(struct __sk_buff *ctx)
//   {
//       struct bpf_fib_lookup *params;
//       __u32 key = 0;
//
//       params = bpf_map_lookup_elem(&map_fib_wo, &key);
//       if (params)
//           bpf_fib_lookup(ctx, params, sizeof(*params), 0);
//       return 0;
//   }
#[link_section = "tc"]
#[no_mangle]
extern "C" fn writeonly_sized_input(ctx: *mut __sk_buff) -> i32 {
    let key: u32 = 0;
    let params = bpf_map_lookup_elem(&map_fib_wo, &key) as *mut bpf_fib_lookup;
    if !params.is_null() {
        bpf_fib_lookup(ctx as *const c_void, params, core::mem::size_of::<bpf_fib_lookup>() as i32, 0);
    }
    0
}

// HAND: readwrite_sized_input -- translate the C below (see the file comment)
//   SEC("tc")
//   __success
//   int readwrite_sized_input(struct __sk_buff *ctx)
//   {
//       struct bpf_fib_lookup *params;
//       __u32 key = 0;
//
//       params = bpf_map_lookup_elem(&map_fib_rw, &key);
//       if (params)
//           bpf_fib_lookup(ctx, params, sizeof(*params), 0);
//       return 0;
//   }
#[link_section = "tc"]
#[no_mangle]
extern "C" fn readwrite_sized_input(ctx: *mut __sk_buff) -> i32 {
    let key: u32 = 0;
    let params = bpf_map_lookup_elem(&map_fib_rw, &key) as *mut bpf_fib_lookup;
    if !params.is_null() {
        bpf_fib_lookup(ctx as *const c_void, params, core::mem::size_of::<bpf_fib_lookup>() as i32, 0);
    }
    0
}

// HAND: readonly_sized_output -- translate the C below (see the file comment)
//   SEC("tc")
//   __failure __msg("write into map forbidden")
//   int readonly_sized_output(struct __sk_buff *ctx)
//   {
//       struct bpf_fib_lookup *params;
//       __u32 key = 0;
//
//       params = bpf_map_lookup_elem(&map_fib_ro, &key);
//       if (params)
//           bpf_fib_lookup(ctx, params, sizeof(*params), 0);
//       return 0;
//   }
#[link_section = "tc"]
#[no_mangle]
extern "C" fn readonly_sized_output(ctx: *mut __sk_buff) -> i32 {
    let key: u32 = 0;
    let params = bpf_map_lookup_elem(&map_fib_ro, &key) as *mut bpf_fib_lookup;
    if !params.is_null() {
        bpf_fib_lookup(ctx as *const c_void, params, core::mem::size_of::<bpf_fib_lookup>() as i32, 0);
    }
    0
}

// HAND: xdp_writeonly_sized_input -- translate the C below (see the file comment)
//   SEC("xdp")
//   __failure __msg("read from map forbidden")
//   int xdp_writeonly_sized_input(struct xdp_md *ctx)
//   {
//       struct bpf_fib_lookup *params;
//       __u32 key = 0;
//
//       params = bpf_map_lookup_elem(&map_fib_wo, &key);
//       if (params)
//           bpf_fib_lookup(ctx, params, sizeof(*params), 0);
//       return XDP_PASS;
//   }
#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_writeonly_sized_input(ctx: *mut xdp_md) -> i32 {
    let key: u32 = 0;
    let params = bpf_map_lookup_elem(&map_fib_wo, &key) as *mut bpf_fib_lookup;
    if !params.is_null() {
        bpf_fib_lookup(ctx as *const c_void, params, core::mem::size_of::<bpf_fib_lookup>() as i32, 0);
    }
    XDP_PASS
}

// HAND: writeonly_header_option -- translate the C below (see the file comment)
//   SEC("sockops")
//   __failure __msg("read from map forbidden")
//   int writeonly_header_option(struct bpf_sock_ops *ctx)
//   {
//       struct bpf_fib_lookup *buf;
//       __u32 key = 0;
//
//       buf = bpf_map_lookup_elem(&map_fib_wo, &key);
//       if (buf)
//           bpf_load_hdr_opt(ctx, buf, sizeof(*buf), 0);
//       return 0;
//   }
#[link_section = "sockops"]
#[no_mangle]
extern "C" fn writeonly_header_option(ctx: *mut bpf_sock_ops) -> i32 {
    let key: u32 = 0;
    let buf = bpf_map_lookup_elem(&map_fib_wo, &key);
    if !buf.is_null() {
        bpf_load_hdr_opt(ctx, buf, core::mem::size_of::<bpf_fib_lookup>() as u32, 0);
    }
    0
}

// HAND: readwrite_header_option -- translate the C below (see the file comment)
//   SEC("sockops")
//   __success
//   int readwrite_header_option(struct bpf_sock_ops *ctx)
//   {
//       struct bpf_fib_lookup *buf;
//       __u32 key = 0;
//
//       buf = bpf_map_lookup_elem(&map_fib_rw, &key);
//       if (buf)
//           bpf_load_hdr_opt(ctx, buf, sizeof(*buf), 0);
//       return 0;
//   }
#[link_section = "sockops"]
#[no_mangle]
extern "C" fn readwrite_header_option(ctx: *mut bpf_sock_ops) -> i32 {
    let key: u32 = 0;
    let buf = bpf_map_lookup_elem(&map_fib_rw, &key);
    if !buf.is_null() {
        bpf_load_hdr_opt(ctx, buf, core::mem::size_of::<bpf_fib_lookup>() as u32, 0);
    }
    0
}

// HAND: snprintf_writeonly_output -- translate the C below (see the file comment)
//   SEC("tc")
//   __success
//   int snprintf_writeonly_output(struct __sk_buff *ctx)
//   {
//       void *buf;
//       __u32 key = 0;
//
//       buf = bpf_map_lookup_elem(&map_fib_wo, &key);
//       if (buf)
//           bpf_snprintf(buf, 16, "ok", NULL, 0);
//       return 0;
//   }
#[link_section = "tc"]
#[no_mangle]
extern "C" fn snprintf_writeonly_output(_ctx: *mut __sk_buff) -> i32 {
    let key: u32 = 0;
    let buf = bpf_map_lookup_elem(&map_fib_wo, &key);
    if !buf.is_null() {
        bpf_snprintf(buf, 16, FMT_OK.as_ptr() as *const c_void, core::ptr::null(), 0);
    }
    0
}

// HAND: snprintf_readonly_output -- translate the C below (see the file comment)
//   SEC("tc")
//   __failure __msg("write into map forbidden")
//   int snprintf_readonly_output(struct __sk_buff *ctx)
//   {
//       void *buf;
//       __u32 key = 0;
//
//       buf = bpf_map_lookup_elem(&map_fib_ro, &key);
//       if (buf)
//           bpf_snprintf(buf, 16, "ok", NULL, 0);
//       return 0;
//   }
#[link_section = "tc"]
#[no_mangle]
extern "C" fn snprintf_readonly_output(_ctx: *mut __sk_buff) -> i32 {
    let key: u32 = 0;
    let buf = bpf_map_lookup_elem(&map_fib_ro, &key);
    if !buf.is_null() {
        bpf_snprintf(buf, 16, FMT_OK.as_ptr() as *const c_void, core::ptr::null(), 0);
    }
    0
}

// HAND: sysctl_writeonly_output -- translate the C below (see the file comment)
//   SEC("cgroup/sysctl")
//   __success
//   __caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
//   __success_unpriv
//   int sysctl_writeonly_output(struct bpf_sysctl *ctx)
//   {
//       void *buf;
//       __u32 key = 0;
//
//       buf = bpf_map_lookup_elem(&map_fib_wo, &key);
//       if (buf)
//           bpf_sysctl_get_name(ctx, buf, 16, 0);
//       return 0;
//   }
#[link_section = "cgroup/sysctl"]
#[no_mangle]
extern "C" fn sysctl_writeonly_output(ctx: *mut bpf_sysctl) -> i32 {
    let key: u32 = 0;
    let buf = bpf_map_lookup_elem(&map_fib_wo, &key);
    if !buf.is_null() {
        bpf_sysctl_get_name(ctx, buf, 16, 0);
    }
    0
}

// HAND: sysctl_partial_dynptr -- translate the C below (see the file comment)
//   SEC("cgroup/sysctl")
//   __success
//   __caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
//   __failure_unpriv __msg_unpriv("invalid read from stack R2")
//   int sysctl_partial_dynptr(struct bpf_sysctl *ctx)
//   {
//       struct bpf_dynptr ptr;
//       long long key = 0, *data;
//
//       data = bpf_map_lookup_elem(&map_hash_8b, &key);
//       if (!data)
//           return 0;
//       bpf_dynptr_from_mem(data, sizeof(*data), 0, &ptr);
//       bpf_sysctl_get_name(ctx, (char *)&ptr, sizeof(ptr), 0);
//       return 0;
//   }
#[link_section = "cgroup/sysctl"]
#[no_mangle]
extern "C" fn sysctl_partial_dynptr(ctx: *mut bpf_sysctl) -> i32 {
    // struct bpf_dynptr ptr (16 bytes), uninitialized as in C
    let mut ptr = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    let key: i64 = 0;
    let data = bpf_map_lookup_elem(&map_hash_8b, &key) as *mut i64;
    if data.is_null() {
        return 0;
    }
    bpf_dynptr_from_mem(data as *mut c_void, 8, 0, ptr.as_mut_ptr() as *mut c_void);
    bpf_sysctl_get_name(ctx, ptr.as_mut_ptr() as *mut c_void, 16, 0);
    0
}

// HAND: snprintf_partial_output_runtime -- translate the C below (see the file comment)
//   SEC("tc")
//   __success __retval(42)
//   int snprintf_partial_output_runtime(struct __sk_buff *ctx)
//   {
//       char buf[16];
//
//       buf[15] = 42;
//       bpf_snprintf(buf, sizeof(buf), "ok", NULL, 0);
//       return buf[15];
//   }
#[link_section = "tc"]
#[no_mangle]
extern "C" fn snprintf_partial_output_runtime(_ctx: *mut __sk_buff) -> i32 {
    // char buf[16], only buf[15] written before the call
    let mut buf = core::mem::MaybeUninit::<[i8; 16]>::uninit();
    unsafe { (buf.as_mut_ptr() as *mut i8).add(15).write(42) };
    bpf_snprintf(buf.as_mut_ptr() as *mut c_void, 16, FMT_OK.as_ptr() as *const c_void, core::ptr::null(), 0);
    unsafe { (buf.as_ptr() as *const i8).add(15).read() as i32 }
}
