// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_ctx.c, translated
// by hand; include!d by the generated progs/verifier_ctx.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// Every body is a ctx access pattern (`char *p = ctx; ... p + off ...`),
// translated statement by statement with the unchanged operand values; the
// netfilter programs' offsetof(struct bpf_nf_ctx, skb) is 8.
use bpf_rs_core::helpers::{bpf_get_prandom_u32, bpf_snprintf, bpf_strncmp};

/// bpf_probe_read_kernel (helper 113) on a raw pointer.
#[inline(always)]
fn probe_read_kernel(dst: *mut c_void, size: u32, src: *const c_void) -> i64 {
    let f: extern "C" fn(*mut c_void, u32, *const c_void) -> i64 = unsafe { core::mem::transmute(113usize) };
    f(dst, size, src)
}

// HAND: syscall_ctx_fixed_off_write -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: write to ctx with fixed offset")
//   __success
//   int syscall_ctx_fixed_off_write(void *ctx)
//   {
//       char *p = ctx;
//
//       *(__u32 *)p = 0;
//       *(__u32 *)(p + 4) = 0;
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_fixed_off_write(ctx: *mut c_void) -> i32 {
    let p = ctx as *mut u8;
    unsafe { *(p.wrapping_add(0) as *mut u32) = 0 };
    unsafe { *(p.wrapping_add(4) as *mut u32) = 0 };
    0
}

// HAND: syscall_ctx_fixed_off_read -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: read ctx with fixed offset")
//   __success
//   int syscall_ctx_fixed_off_read(void *ctx)
//   {
//       char *p = ctx;
//       volatile __u32 val;
//
//       val = *(__u32 *)(p + 4);
//       (void)val;
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_fixed_off_read(ctx: *mut c_void) -> i32 {
    let p = ctx as *mut u8;
    let mut val: u32 = 0;
    unsafe { core::ptr::write_volatile(&mut val, *(p.wrapping_add(4) as *const u32)) };
    let _ = val;
    0
}

// HAND: syscall_ctx_unaligned_fixed_off_read -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: unaligned read ctx with fixed offset")
//   __success
//   int syscall_ctx_unaligned_fixed_off_read(void *ctx)
//   {
//       char *p = ctx;
//       volatile __u32 val;
//
//       val = *(__u32 *)(p + 2);
//       (void)val;
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_unaligned_fixed_off_read(ctx: *mut c_void) -> i32 {
    let p = ctx as *mut u8;
    let mut val: u32 = 0;
    unsafe { core::ptr::write_volatile(&mut val, *(p.wrapping_add(2) as *const u32)) };
    let _ = val;
    0
}

// HAND: syscall_ctx_unaligned_fixed_off_write -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: unaligned write ctx with fixed offset")
//   __success
//   int syscall_ctx_unaligned_fixed_off_write(void *ctx)
//   {
//       char *p = ctx;
//
//       *(__u32 *)(p + 2) = 0;
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_unaligned_fixed_off_write(ctx: *mut c_void) -> i32 {
    let p = ctx as *mut u8;
    unsafe { *(p.wrapping_add(2) as *mut u32) = 0 };
    0
}

// HAND: syscall_ctx_var_off_read -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: read ctx with variable offset")
//   __success
//   int syscall_ctx_var_off_read(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//       volatile __u32 val;
//
//       off &= 0xfc;
//       p += off;
//       val = *(__u32 *)p;
//       (void)val;
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_var_off_read(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    let mut val: u32 = 0;
    off &= 0xfc;
    p = p.wrapping_add(off as usize);
    unsafe { core::ptr::write_volatile(&mut val, *(p.wrapping_add(0) as *const u32)) };
    let _ = val;
    0
}

// HAND: syscall_ctx_var_off_write -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: write ctx with variable offset")
//   __success
//   int syscall_ctx_var_off_write(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off &= 0xfc;
//       p += off;
//       *(__u32 *)p = 0;
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_var_off_write(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off &= 0xfc;
    p = p.wrapping_add(off as usize);
    unsafe { *(p.wrapping_add(0) as *mut u32) = 0 };
    0
}

// HAND: syscall_ctx_unaligned_var_off_read -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: unaligned read ctx with variable offset")
//   __success
//   int syscall_ctx_unaligned_var_off_read(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//       volatile __u32 val;
//
//       off &= 0xfc;
//       off += 2;
//       p += off;
//       val = *(__u32 *)p;
//       (void)val;
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_unaligned_var_off_read(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    let mut val: u32 = 0;
    off &= 0xfc;
    off = off.wrapping_add(2);
    p = p.wrapping_add(off as usize);
    unsafe { core::ptr::write_volatile(&mut val, *(p.wrapping_add(0) as *const u32)) };
    let _ = val;
    0
}

// HAND: syscall_ctx_unaligned_var_off_write -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: unaligned write ctx with variable offset")
//   __success
//   int syscall_ctx_unaligned_var_off_write(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off &= 0xfc;
//       off += 2;
//       p += off;
//       *(__u32 *)p = 0;
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_unaligned_var_off_write(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off &= 0xfc;
    off = off.wrapping_add(2);
    p = p.wrapping_add(off as usize);
    unsafe { *(p.wrapping_add(0) as *mut u32) = 0 };
    0
}

// HAND: syscall_ctx_u16_max_fixed_off -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: reject ctx access past U16_MAX with fixed offset")
//   __failure __msg("outside of the allowed memory range")
//   int syscall_ctx_u16_max_fixed_off(void *ctx)
//   {
//       char *p = ctx;
//       volatile __u32 val;
//
//       p += 65535;
//       val = *(__u32 *)p;
//       (void)val;
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_u16_max_fixed_off(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    let mut val: u32 = 0;
    p = p.wrapping_add(65535);
    unsafe { core::ptr::write_volatile(&mut val, *(p.wrapping_add(0) as *const u32)) };
    let _ = val;
    0
}

// HAND: syscall_ctx_u16_max_var_off -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: reject ctx access past U16_MAX with variable offset")
//   __failure __msg("outside of the allowed memory range")
//   int syscall_ctx_u16_max_var_off(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//       volatile __u32 val;
//
//       off &= 0xffff;
//       off += 1;
//       p += off;
//       val = *(__u32 *)p;
//       (void)val;
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_u16_max_var_off(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    let mut val: u32 = 0;
    off &= 0xffff;
    off = off.wrapping_add(1);
    p = p.wrapping_add(off as usize);
    unsafe { core::ptr::write_volatile(&mut val, *(p.wrapping_add(0) as *const u32)) };
    let _ = val;
    0
}

// HAND: syscall_ctx_neg_var_off -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: reject negative variable offset ctx access")
//   __failure __msg("min value is negative")
//   int syscall_ctx_neg_var_off(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off &= 4;
//       p -= off;
//       return *(__u32 *)p;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_neg_var_off(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off &= 4;
    p = p.wrapping_sub(off as usize);
    (unsafe { *(p as *const u32) }) as i32
}

// HAND: syscall_ctx_unbounded_var_off -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: reject unbounded variable offset ctx access")
//   __failure __msg("unbounded memory access")
//   int syscall_ctx_unbounded_var_off(void *ctx)
//   {
//       __u64 off = (__u32)bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off <<= 2;
//       p += off;
//       return *(__u32 *)p;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_unbounded_var_off(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off <<= 2;
    p = p.wrapping_add(off as usize);
    (unsafe { *(p as *const u32) }) as i32
}

// HAND: syscall_ctx_helper_fixed_off_read -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: helper read ctx with fixed offset")
//   __success
//   int syscall_ctx_helper_fixed_off_read(void *ctx)
//   {
//       char *p = ctx;
//
//       p += 4;
//       return bpf_strncmp(p, 4, ctx_strncmp_target);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_helper_fixed_off_read(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(4);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: syscall_ctx_helper_fixed_off_write -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: helper write ctx with fixed offset")
//   __success
//   int syscall_ctx_helper_fixed_off_write(void *ctx)
//   {
//       char *p = ctx;
//
//       p += 4;
//       return probe_read_kernel(p, 4, 0);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_helper_fixed_off_write(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(4);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: syscall_ctx_helper_unaligned_fixed_off_read -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: helper unaligned read ctx with fixed offset")
//   __success
//   int syscall_ctx_helper_unaligned_fixed_off_read(void *ctx)
//   {
//       char *p = ctx;
//
//       p += 2;
//       return bpf_strncmp(p, 4, ctx_strncmp_target);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_helper_unaligned_fixed_off_read(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(2);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: syscall_ctx_helper_unaligned_fixed_off_write -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: helper unaligned write ctx with fixed offset")
//   __success
//   int syscall_ctx_helper_unaligned_fixed_off_write(void *ctx)
//   {
//       char *p = ctx;
//
//       p += 2;
//       return probe_read_kernel(p, 4, 0);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_helper_unaligned_fixed_off_write(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(2);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: syscall_ctx_helper_var_off_read -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: helper read ctx with variable offset")
//   __success
//   int syscall_ctx_helper_var_off_read(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off &= 0xfc;
//       p += off;
//       return bpf_strncmp(p, 4, ctx_strncmp_target);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_helper_var_off_read(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off &= 0xfc;
    p = p.wrapping_add(off as usize);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: syscall_ctx_helper_var_off_write -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: helper write ctx with variable offset")
//   __success
//   int syscall_ctx_helper_var_off_write(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off &= 0xfc;
//       p += off;
//       return probe_read_kernel(p, 4, 0);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_helper_var_off_write(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off &= 0xfc;
    p = p.wrapping_add(off as usize);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: syscall_ctx_helper_unaligned_var_off_read -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: helper unaligned read ctx with variable offset")
//   __success
//   int syscall_ctx_helper_unaligned_var_off_read(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off &= 0xfc;
//       off += 2;
//       p += off;
//       return bpf_strncmp(p, 4, ctx_strncmp_target);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_helper_unaligned_var_off_read(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off &= 0xfc;
    off = off.wrapping_add(2);
    p = p.wrapping_add(off as usize);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: syscall_ctx_helper_unaligned_var_off_write -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: helper unaligned write ctx with variable offset")
//   __success
//   int syscall_ctx_helper_unaligned_var_off_write(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off &= 0xfc;
//       off += 2;
//       p += off;
//       return probe_read_kernel(p, 4, 0);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_helper_unaligned_var_off_write(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off &= 0xfc;
    off = off.wrapping_add(2);
    p = p.wrapping_add(off as usize);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: syscall_ctx_helper_u16_max_fixed_off_read -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: reject helper read ctx past U16_MAX with fixed offset")
//   __failure __msg("outside of the allowed memory range")
//   int syscall_ctx_helper_u16_max_fixed_off_read(void *ctx)
//   {
//       char *p = ctx;
//
//       p += 65535;
//       return bpf_strncmp(p, 4, ctx_strncmp_target);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_helper_u16_max_fixed_off_read(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(65535);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: syscall_ctx_helper_u16_max_fixed_off_write -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: reject helper write ctx past U16_MAX with fixed offset")
//   __failure __msg("outside of the allowed memory range")
//   int syscall_ctx_helper_u16_max_fixed_off_write(void *ctx)
//   {
//       char *p = ctx;
//
//       p += 65535;
//       return probe_read_kernel(p, 4, 0);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_helper_u16_max_fixed_off_write(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(65535);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: syscall_ctx_helper_u16_max_var_off_read -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: reject helper read ctx past U16_MAX with variable offset")
//   __failure __msg("outside of the allowed memory range")
//   int syscall_ctx_helper_u16_max_var_off_read(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off &= 0xffff;
//       off += 1;
//       p += off;
//       return bpf_strncmp(p, 4, ctx_strncmp_target);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_helper_u16_max_var_off_read(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off &= 0xffff;
    off = off.wrapping_add(1);
    p = p.wrapping_add(off as usize);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: syscall_ctx_helper_u16_max_var_off_write -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: reject helper write ctx past U16_MAX with variable offset")
//   __failure __msg("outside of the allowed memory range")
//   int syscall_ctx_helper_u16_max_var_off_write(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off &= 0xffff;
//       off += 1;
//       p += off;
//       return probe_read_kernel(p, 4, 0);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_helper_u16_max_var_off_write(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off &= 0xffff;
    off = off.wrapping_add(1);
    p = p.wrapping_add(off as usize);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: syscall_ctx_helper_zero_sized_read -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: helper read zero-sized ctx access")
//   __success
//   int syscall_ctx_helper_zero_sized_read(void *ctx)
//   {
//       return bpf_snprintf(0, 0, ctx_snprintf_fmt, ctx, 0);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_helper_zero_sized_read(ctx: *mut c_void) -> i32 {
    bpf_snprintf(core::ptr::null_mut(), 0, core::ptr::addr_of!(ctx_snprintf_fmt) as *const c_void, ctx as *const c_void, 0) as i32
}

// HAND: syscall_ctx_helper_zero_sized_write -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: helper write zero-sized ctx access")
//   __success
//   int syscall_ctx_helper_zero_sized_write(void *ctx)
//   {
//       return probe_read_kernel(ctx, 0, 0);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_helper_zero_sized_write(ctx: *mut c_void) -> i32 {
    probe_read_kernel(ctx as *mut c_void, 0, core::ptr::null()) as i32
}

// HAND: syscall_ctx_kfunc_fixed_off -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: kfunc access ctx with fixed offset")
//   __success
//   int syscall_ctx_kfunc_fixed_off(void *ctx)
//   {
//       char *p = ctx;
//
//       p += 4;
//       bpf_kfunc_call_test_mem_len_pass1(p, 4);
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_kfunc_fixed_off(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(4);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: syscall_ctx_kfunc_var_off -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: kfunc access ctx with variable offset")
//   __success
//   int syscall_ctx_kfunc_var_off(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off &= 0xfc;
//       p += off;
//       bpf_kfunc_call_test_mem_len_pass1(p, 4);
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_kfunc_var_off(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off &= 0xfc;
    p = p.wrapping_add(off as usize);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: syscall_ctx_kfunc_unaligned_fixed_off -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: kfunc unaligned access ctx with fixed offset")
//   __success
//   int syscall_ctx_kfunc_unaligned_fixed_off(void *ctx)
//   {
//       char *p = ctx;
//
//       p += 2;
//       bpf_kfunc_call_test_mem_len_pass1(p, 4);
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_kfunc_unaligned_fixed_off(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(2);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: syscall_ctx_kfunc_unaligned_var_off -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: kfunc unaligned access ctx with variable offset")
//   __success
//   int syscall_ctx_kfunc_unaligned_var_off(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off &= 0xfc;
//       off += 2;
//       p += off;
//       bpf_kfunc_call_test_mem_len_pass1(p, 4);
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_kfunc_unaligned_var_off(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off &= 0xfc;
    off = off.wrapping_add(2);
    p = p.wrapping_add(off as usize);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: syscall_ctx_kfunc_u16_max_fixed_off -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: reject kfunc ctx access past U16_MAX with fixed offset")
//   __failure __msg("outside of the allowed memory range")
//   int syscall_ctx_kfunc_u16_max_fixed_off(void *ctx)
//   {
//       char *p = ctx;
//
//       p += 65535;
//       bpf_kfunc_call_test_mem_len_pass1(p, 4);
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_kfunc_u16_max_fixed_off(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(65535);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: syscall_ctx_kfunc_u16_max_var_off -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: reject kfunc ctx access past U16_MAX with variable offset")
//   __failure __msg("outside of the allowed memory range")
//   int syscall_ctx_kfunc_u16_max_var_off(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off &= 0xffff;
//       off += 1;
//       p += off;
//       bpf_kfunc_call_test_mem_len_pass1(p, 4);
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_kfunc_u16_max_var_off(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off &= 0xffff;
    off = off.wrapping_add(1);
    p = p.wrapping_add(off as usize);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: syscall_ctx_kfunc_zero_sized -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __description("syscall: kfunc access zero-sized ctx")
//   __success
//   int syscall_ctx_kfunc_zero_sized(void *ctx)
//   {
//       bpf_kfunc_call_test_mem_len_pass1(ctx, 0);
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn syscall_ctx_kfunc_zero_sized(ctx: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_test_mem_len_pass1(ctx as *mut c_void, 0) };
    0
}

// HAND: no_rewrite_kprobe_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_kprobe_fixed not found in the source)
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn no_rewrite_kprobe_fixed(ctx: *mut c_void) -> i32 {
    let p = ctx as *mut u8;
    let mut val: u64 = 0;
    unsafe { core::ptr::write_volatile(&mut val, *(p.wrapping_add(8) as *const u64)) };
    let _ = val;
    0
}

// HAND: no_rewrite_kprobe_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_kprobe_var not found in the source)
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn no_rewrite_kprobe_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    (unsafe { *(p as *const u64) }) as i32
}

// HAND: no_rewrite_kprobe_neg -- translate the C below (see the file comment)
//   (definition of no_rewrite_kprobe_neg not found in the source)
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn no_rewrite_kprobe_neg(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_sub(612);
    (unsafe { *(p as *const u64) }) as i32
}

// HAND: no_rewrite_kprobe_helper_read_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_kprobe_helper_read_fixed not found in the source)
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn no_rewrite_kprobe_helper_read_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: no_rewrite_kprobe_helper_write_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_kprobe_helper_write_fixed not found in the source)
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn no_rewrite_kprobe_helper_write_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: no_rewrite_kprobe_helper_read_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_kprobe_helper_read_var not found in the source)
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn no_rewrite_kprobe_helper_read_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: no_rewrite_kprobe_helper_write_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_kprobe_helper_write_var not found in the source)
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn no_rewrite_kprobe_helper_write_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: no_rewrite_kprobe_helper_read_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_kprobe_helper_read_zero not found in the source)
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn no_rewrite_kprobe_helper_read_zero(ctx: *mut c_void) -> i32 {
    bpf_snprintf(core::ptr::null_mut(), 0, core::ptr::addr_of!(ctx_snprintf_fmt) as *const c_void, ctx as *const c_void, 0) as i32
}

// HAND: no_rewrite_kprobe_helper_write_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_kprobe_helper_write_zero not found in the source)
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn no_rewrite_kprobe_helper_write_zero(ctx: *mut c_void) -> i32 {
    probe_read_kernel(ctx as *mut c_void, 0, core::ptr::null()) as i32
}

// HAND: no_rewrite_kprobe_kfunc_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_kprobe_kfunc_fixed not found in the source)
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn no_rewrite_kprobe_kfunc_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: no_rewrite_kprobe_kfunc_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_kprobe_kfunc_var not found in the source)
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn no_rewrite_kprobe_kfunc_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: no_rewrite_kprobe_kfunc_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_kprobe_kfunc_zero not found in the source)
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn no_rewrite_kprobe_kfunc_zero(ctx: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_test_mem_len_pass1(ctx as *mut c_void, 0) };
    0
}

// HAND: no_rewrite_tp_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_tp_fixed not found in the source)
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn no_rewrite_tp_fixed(ctx: *mut c_void) -> i32 {
    let p = ctx as *mut u8;
    let mut val: u64 = 0;
    unsafe { core::ptr::write_volatile(&mut val, *(p.wrapping_add(8) as *const u64)) };
    let _ = val;
    0
}

// HAND: no_rewrite_tp_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_tp_var not found in the source)
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn no_rewrite_tp_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    (unsafe { *(p as *const u64) }) as i32
}

// HAND: no_rewrite_tp_neg -- translate the C below (see the file comment)
//   (definition of no_rewrite_tp_neg not found in the source)
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn no_rewrite_tp_neg(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_sub(612);
    (unsafe { *(p as *const u64) }) as i32
}

// HAND: no_rewrite_tp_helper_read_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_tp_helper_read_fixed not found in the source)
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn no_rewrite_tp_helper_read_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: no_rewrite_tp_helper_write_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_tp_helper_write_fixed not found in the source)
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn no_rewrite_tp_helper_write_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: no_rewrite_tp_helper_read_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_tp_helper_read_var not found in the source)
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn no_rewrite_tp_helper_read_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: no_rewrite_tp_helper_write_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_tp_helper_write_var not found in the source)
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn no_rewrite_tp_helper_write_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: no_rewrite_tp_helper_read_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_tp_helper_read_zero not found in the source)
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn no_rewrite_tp_helper_read_zero(ctx: *mut c_void) -> i32 {
    bpf_snprintf(core::ptr::null_mut(), 0, core::ptr::addr_of!(ctx_snprintf_fmt) as *const c_void, ctx as *const c_void, 0) as i32
}

// HAND: no_rewrite_tp_helper_write_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_tp_helper_write_zero not found in the source)
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn no_rewrite_tp_helper_write_zero(ctx: *mut c_void) -> i32 {
    probe_read_kernel(ctx as *mut c_void, 0, core::ptr::null()) as i32
}

// HAND: no_rewrite_tp_kfunc_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_tp_kfunc_fixed not found in the source)
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn no_rewrite_tp_kfunc_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: no_rewrite_tp_kfunc_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_tp_kfunc_var not found in the source)
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn no_rewrite_tp_kfunc_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: no_rewrite_tp_kfunc_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_tp_kfunc_zero not found in the source)
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn no_rewrite_tp_kfunc_zero(ctx: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_test_mem_len_pass1(ctx as *mut c_void, 0) };
    0
}

// HAND: no_rewrite_raw_tp_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_fixed not found in the source)
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_fixed(ctx: *mut c_void) -> i32 {
    let p = ctx as *mut u8;
    let mut val: u64 = 0;
    unsafe { core::ptr::write_volatile(&mut val, *(p.wrapping_add(8) as *const u64)) };
    let _ = val;
    0
}

// HAND: no_rewrite_raw_tp_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_var not found in the source)
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    (unsafe { *(p as *const u64) }) as i32
}

// HAND: no_rewrite_raw_tp_neg -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_neg not found in the source)
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_neg(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_sub(612);
    (unsafe { *(p as *const u64) }) as i32
}

// HAND: no_rewrite_raw_tp_helper_read_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_helper_read_fixed not found in the source)
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_helper_read_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: no_rewrite_raw_tp_helper_write_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_helper_write_fixed not found in the source)
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_helper_write_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: no_rewrite_raw_tp_helper_read_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_helper_read_var not found in the source)
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_helper_read_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: no_rewrite_raw_tp_helper_write_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_helper_write_var not found in the source)
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_helper_write_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: no_rewrite_raw_tp_helper_read_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_helper_read_zero not found in the source)
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_helper_read_zero(ctx: *mut c_void) -> i32 {
    bpf_snprintf(core::ptr::null_mut(), 0, core::ptr::addr_of!(ctx_snprintf_fmt) as *const c_void, ctx as *const c_void, 0) as i32
}

// HAND: no_rewrite_raw_tp_helper_write_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_helper_write_zero not found in the source)
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_helper_write_zero(ctx: *mut c_void) -> i32 {
    probe_read_kernel(ctx as *mut c_void, 0, core::ptr::null()) as i32
}

// HAND: no_rewrite_raw_tp_kfunc_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_kfunc_fixed not found in the source)
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_kfunc_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: no_rewrite_raw_tp_kfunc_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_kfunc_var not found in the source)
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_kfunc_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: no_rewrite_raw_tp_kfunc_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_kfunc_zero not found in the source)
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_kfunc_zero(ctx: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_test_mem_len_pass1(ctx as *mut c_void, 0) };
    0
}

// HAND: no_rewrite_raw_tp_w_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_w_fixed not found in the source)
#[link_section = "?raw_tracepoint.w"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_w_fixed(ctx: *mut c_void) -> i32 {
    let p = ctx as *mut u8;
    let mut val: u64 = 0;
    unsafe { core::ptr::write_volatile(&mut val, *(p.wrapping_add(8) as *const u64)) };
    let _ = val;
    0
}

// HAND: no_rewrite_raw_tp_w_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_w_var not found in the source)
#[link_section = "?raw_tracepoint.w"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_w_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    (unsafe { *(p as *const u64) }) as i32
}

// HAND: no_rewrite_raw_tp_w_neg -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_w_neg not found in the source)
#[link_section = "?raw_tracepoint.w"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_w_neg(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_sub(612);
    (unsafe { *(p as *const u64) }) as i32
}

// HAND: no_rewrite_raw_tp_w_helper_read_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_w_helper_read_fixed not found in the source)
#[link_section = "?raw_tracepoint.w"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_w_helper_read_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: no_rewrite_raw_tp_w_helper_write_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_w_helper_write_fixed not found in the source)
#[link_section = "?raw_tracepoint.w"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_w_helper_write_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: no_rewrite_raw_tp_w_helper_read_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_w_helper_read_var not found in the source)
#[link_section = "?raw_tracepoint.w"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_w_helper_read_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: no_rewrite_raw_tp_w_helper_write_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_w_helper_write_var not found in the source)
#[link_section = "?raw_tracepoint.w"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_w_helper_write_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: no_rewrite_raw_tp_w_helper_read_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_w_helper_read_zero not found in the source)
#[link_section = "?raw_tracepoint.w"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_w_helper_read_zero(ctx: *mut c_void) -> i32 {
    bpf_snprintf(core::ptr::null_mut(), 0, core::ptr::addr_of!(ctx_snprintf_fmt) as *const c_void, ctx as *const c_void, 0) as i32
}

// HAND: no_rewrite_raw_tp_w_helper_write_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_w_helper_write_zero not found in the source)
#[link_section = "?raw_tracepoint.w"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_w_helper_write_zero(ctx: *mut c_void) -> i32 {
    probe_read_kernel(ctx as *mut c_void, 0, core::ptr::null()) as i32
}

// HAND: no_rewrite_raw_tp_w_kfunc_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_w_kfunc_fixed not found in the source)
#[link_section = "?raw_tracepoint.w"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_w_kfunc_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: no_rewrite_raw_tp_w_kfunc_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_w_kfunc_var not found in the source)
#[link_section = "?raw_tracepoint.w"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_w_kfunc_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: no_rewrite_raw_tp_w_kfunc_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_raw_tp_w_kfunc_zero not found in the source)
#[link_section = "?raw_tracepoint.w"]
#[no_mangle]
extern "C" fn no_rewrite_raw_tp_w_kfunc_zero(ctx: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_test_mem_len_pass1(ctx as *mut c_void, 0) };
    0
}

// HAND: no_rewrite_fentry_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_fentry_fixed not found in the source)
#[link_section = "?fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn no_rewrite_fentry_fixed(ctx: *mut c_void) -> i32 {
    let p = ctx as *mut u8;
    let mut val: u64 = 0;
    unsafe { core::ptr::write_volatile(&mut val, *(p.wrapping_add(8) as *const u64)) };
    let _ = val;
    0
}

// HAND: no_rewrite_fentry_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_fentry_var not found in the source)
#[link_section = "?fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn no_rewrite_fentry_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    (unsafe { *(p as *const u64) }) as i32
}

// HAND: no_rewrite_fentry_neg -- translate the C below (see the file comment)
//   (definition of no_rewrite_fentry_neg not found in the source)
#[link_section = "?fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn no_rewrite_fentry_neg(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_sub(612);
    (unsafe { *(p as *const u64) }) as i32
}

// HAND: no_rewrite_fentry_helper_read_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_fentry_helper_read_fixed not found in the source)
#[link_section = "?fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn no_rewrite_fentry_helper_read_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: no_rewrite_fentry_helper_write_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_fentry_helper_write_fixed not found in the source)
#[link_section = "?fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn no_rewrite_fentry_helper_write_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: no_rewrite_fentry_helper_read_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_fentry_helper_read_var not found in the source)
#[link_section = "?fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn no_rewrite_fentry_helper_read_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: no_rewrite_fentry_helper_write_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_fentry_helper_write_var not found in the source)
#[link_section = "?fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn no_rewrite_fentry_helper_write_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: no_rewrite_fentry_helper_read_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_fentry_helper_read_zero not found in the source)
#[link_section = "?fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn no_rewrite_fentry_helper_read_zero(ctx: *mut c_void) -> i32 {
    bpf_snprintf(core::ptr::null_mut(), 0, core::ptr::addr_of!(ctx_snprintf_fmt) as *const c_void, ctx as *const c_void, 0) as i32
}

// HAND: no_rewrite_fentry_helper_write_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_fentry_helper_write_zero not found in the source)
#[link_section = "?fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn no_rewrite_fentry_helper_write_zero(ctx: *mut c_void) -> i32 {
    probe_read_kernel(ctx as *mut c_void, 0, core::ptr::null()) as i32
}

// HAND: no_rewrite_fentry_kfunc_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_fentry_kfunc_fixed not found in the source)
#[link_section = "?fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn no_rewrite_fentry_kfunc_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: no_rewrite_fentry_kfunc_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_fentry_kfunc_var not found in the source)
#[link_section = "?fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn no_rewrite_fentry_kfunc_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: no_rewrite_fentry_kfunc_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_fentry_kfunc_zero not found in the source)
#[link_section = "?fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn no_rewrite_fentry_kfunc_zero(ctx: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_test_mem_len_pass1(ctx as *mut c_void, 0) };
    0
}

// HAND: no_rewrite_cgroup_dev_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_cgroup_dev_fixed not found in the source)
#[link_section = "?cgroup/dev"]
#[no_mangle]
extern "C" fn no_rewrite_cgroup_dev_fixed(ctx: *mut c_void) -> i32 {
    let p = ctx as *mut u8;
    let mut val: u32 = 0;
    unsafe { core::ptr::write_volatile(&mut val, *(p.wrapping_add(4) as *const u32)) };
    let _ = val;
    0
}

// HAND: no_rewrite_cgroup_dev_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_cgroup_dev_var not found in the source)
#[link_section = "?cgroup/dev"]
#[no_mangle]
extern "C" fn no_rewrite_cgroup_dev_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    (unsafe { *(p as *const u32) }) as i32
}

// HAND: no_rewrite_cgroup_dev_neg -- translate the C below (see the file comment)
//   (definition of no_rewrite_cgroup_dev_neg not found in the source)
#[link_section = "?cgroup/dev"]
#[no_mangle]
extern "C" fn no_rewrite_cgroup_dev_neg(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_sub(612);
    (unsafe { *(p as *const u32) }) as i32
}

// HAND: no_rewrite_cgroup_dev_helper_read_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_cgroup_dev_helper_read_fixed not found in the source)
#[link_section = "?cgroup/dev"]
#[no_mangle]
extern "C" fn no_rewrite_cgroup_dev_helper_read_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(4);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: no_rewrite_cgroup_dev_helper_write_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_cgroup_dev_helper_write_fixed not found in the source)
#[link_section = "?cgroup/dev"]
#[no_mangle]
extern "C" fn no_rewrite_cgroup_dev_helper_write_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(4);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: no_rewrite_cgroup_dev_helper_read_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_cgroup_dev_helper_read_var not found in the source)
#[link_section = "?cgroup/dev"]
#[no_mangle]
extern "C" fn no_rewrite_cgroup_dev_helper_read_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: no_rewrite_cgroup_dev_helper_write_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_cgroup_dev_helper_write_var not found in the source)
#[link_section = "?cgroup/dev"]
#[no_mangle]
extern "C" fn no_rewrite_cgroup_dev_helper_write_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: no_rewrite_cgroup_dev_helper_read_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_cgroup_dev_helper_read_zero not found in the source)
#[link_section = "?cgroup/dev"]
#[no_mangle]
extern "C" fn no_rewrite_cgroup_dev_helper_read_zero(ctx: *mut c_void) -> i32 {
    bpf_snprintf(core::ptr::null_mut(), 0, core::ptr::addr_of!(ctx_snprintf_fmt) as *const c_void, ctx as *const c_void, 0) as i32
}

// HAND: no_rewrite_cgroup_dev_helper_write_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_cgroup_dev_helper_write_zero not found in the source)
#[link_section = "?cgroup/dev"]
#[no_mangle]
extern "C" fn no_rewrite_cgroup_dev_helper_write_zero(ctx: *mut c_void) -> i32 {
    probe_read_kernel(ctx as *mut c_void, 0, core::ptr::null()) as i32
}

// HAND: no_rewrite_cgroup_dev_kfunc_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_cgroup_dev_kfunc_fixed not found in the source)
#[link_section = "?cgroup/dev"]
#[no_mangle]
extern "C" fn no_rewrite_cgroup_dev_kfunc_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(4);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: no_rewrite_cgroup_dev_kfunc_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_cgroup_dev_kfunc_var not found in the source)
#[link_section = "?cgroup/dev"]
#[no_mangle]
extern "C" fn no_rewrite_cgroup_dev_kfunc_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: no_rewrite_cgroup_dev_kfunc_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_cgroup_dev_kfunc_zero not found in the source)
#[link_section = "?cgroup/dev"]
#[no_mangle]
extern "C" fn no_rewrite_cgroup_dev_kfunc_zero(ctx: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_test_mem_len_pass1(ctx as *mut c_void, 0) };
    0
}

// HAND: no_rewrite_netfilter_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_netfilter_fixed not found in the source)
#[link_section = "?netfilter"]
#[no_mangle]
extern "C" fn no_rewrite_netfilter_fixed(ctx: *mut c_void) -> i32 {
    let p = ctx as *mut u8;
    let mut val: u64 = 0;
    unsafe { core::ptr::write_volatile(&mut val, *(p.wrapping_add(8) as *const u64)) };
    let _ = val;
    0
}

// HAND: no_rewrite_netfilter_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_netfilter_var not found in the source)
#[link_section = "?netfilter"]
#[no_mangle]
extern "C" fn no_rewrite_netfilter_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    (unsafe { *(p as *const u64) }) as i32
}

// HAND: no_rewrite_netfilter_neg -- translate the C below (see the file comment)
//   (definition of no_rewrite_netfilter_neg not found in the source)
#[link_section = "?netfilter"]
#[no_mangle]
extern "C" fn no_rewrite_netfilter_neg(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_sub(612);
    (unsafe { *(p as *const u64) }) as i32
}

// HAND: no_rewrite_netfilter_helper_read_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_netfilter_helper_read_fixed not found in the source)
#[link_section = "?netfilter"]
#[no_mangle]
extern "C" fn no_rewrite_netfilter_helper_read_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: no_rewrite_netfilter_helper_write_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_netfilter_helper_write_fixed not found in the source)
#[link_section = "?netfilter"]
#[no_mangle]
extern "C" fn no_rewrite_netfilter_helper_write_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: no_rewrite_netfilter_helper_read_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_netfilter_helper_read_var not found in the source)
#[link_section = "?netfilter"]
#[no_mangle]
extern "C" fn no_rewrite_netfilter_helper_read_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    bpf_strncmp(p as *const c_void, 4, core::ptr::addr_of!(ctx_strncmp_target) as *const c_void) as i32
}

// HAND: no_rewrite_netfilter_helper_write_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_netfilter_helper_write_var not found in the source)
#[link_section = "?netfilter"]
#[no_mangle]
extern "C" fn no_rewrite_netfilter_helper_write_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    probe_read_kernel(p as *mut c_void, 4, core::ptr::null()) as i32
}

// HAND: no_rewrite_netfilter_helper_read_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_netfilter_helper_read_zero not found in the source)
#[link_section = "?netfilter"]
#[no_mangle]
extern "C" fn no_rewrite_netfilter_helper_read_zero(ctx: *mut c_void) -> i32 {
    bpf_snprintf(core::ptr::null_mut(), 0, core::ptr::addr_of!(ctx_snprintf_fmt) as *const c_void, ctx as *const c_void, 0) as i32
}

// HAND: no_rewrite_netfilter_helper_write_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_netfilter_helper_write_zero not found in the source)
#[link_section = "?netfilter"]
#[no_mangle]
extern "C" fn no_rewrite_netfilter_helper_write_zero(ctx: *mut c_void) -> i32 {
    probe_read_kernel(ctx as *mut c_void, 0, core::ptr::null()) as i32
}

// HAND: no_rewrite_netfilter_kfunc_fixed -- translate the C below (see the file comment)
//   (definition of no_rewrite_netfilter_kfunc_fixed not found in the source)
#[link_section = "?netfilter"]
#[no_mangle]
extern "C" fn no_rewrite_netfilter_kfunc_fixed(ctx: *mut c_void) -> i32 {
    let mut p = ctx as *mut u8;
    p = p.wrapping_add(8);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: no_rewrite_netfilter_kfunc_var -- translate the C below (see the file comment)
//   (definition of no_rewrite_netfilter_kfunc_var not found in the source)
#[link_section = "?netfilter"]
#[no_mangle]
extern "C" fn no_rewrite_netfilter_kfunc_var(ctx: *mut c_void) -> i32 {
    let mut off_var: u64 = bpf_get_prandom_u32() as u64;
    let mut p = ctx as *mut u8;
    off_var &= 4;
    p = p.wrapping_add(off_var as usize);
    unsafe { bpf_kfunc_call_test_mem_len_pass1(p as *mut c_void, 4) };
    0
}

// HAND: no_rewrite_netfilter_kfunc_zero -- translate the C below (see the file comment)
//   (definition of no_rewrite_netfilter_kfunc_zero not found in the source)
#[link_section = "?netfilter"]
#[no_mangle]
extern "C" fn no_rewrite_netfilter_kfunc_zero(ctx: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_test_mem_len_pass1(ctx as *mut c_void, 0) };
    0
}
