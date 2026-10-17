// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_lsm_init_xattr.c, translated
// by hand; include!d by the generated progs/verifier_lsm_init_xattr.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::bpf_dynptr_from_mem;
use btf_macros::btf;

/// The kernel's qstr, its `len` read with CO-RE.
#[btf]
struct qstr {
    len: u32,
}

// HAND: reject_count_write -- translate the C below (see the file comment)
//   SEC("lsm/inode_init_security")
//   __failure __msg("cannot write into rdonly_trusted_mem")
//   int BPF_PROG(reject_count_write, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       *xattr_count = 0;
//       return 0;
//   }
// BPF_PROG(reject_count_write, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn reject_count_write(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut xattr;
    let xattr_count = unsafe { *ctx.add(4) } as *mut i32;
    let _ = xattrs;
    unsafe { *xattr_count = 0 };
    0
}

// HAND: allow_count_read -- translate the C below (see the file comment)
//   SEC("lsm/inode_init_security")
//   __success
//   int BPF_PROG(allow_count_read, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       scratch_count = *xattr_count;
//       return 0;
//   }
// BPF_PROG(allow_count_read, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn allow_count_read(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut xattr;
    let xattr_count = unsafe { *ctx.add(4) } as *mut i32;
    let _ = xattrs;
    unsafe { scratch_count = *xattr_count };
    0
}

// HAND: reject_unchecked_xattrs -- translate the C below (see the file comment)
//   SEC("lsm/inode_init_security")
//   __failure __msg("Possibly NULL pointer passed to trusted")
//   int BPF_PROG(reject_unchecked_xattrs, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       struct bpf_dynptr value;
//
//       bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
//       bpf_inode_init_xattr(xattrs, xattr_count, xattr_zone, &value);
//       return 0;
//   }
// BPF_PROG(reject_unchecked_xattrs, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn reject_unchecked_xattrs(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut xattr;
    let xattr_count = unsafe { *ctx.add(4) } as *mut i32;
    let mut value = core::mem::MaybeUninit::<bpf_dynptr>::uninit();
    bpf_dynptr_from_mem(core::ptr::addr_of_mut!(value_buf) as *mut c_void, 8, 0, value.as_mut_ptr() as *mut c_void);
    unsafe { bpf_inode_init_xattr(xattrs as *mut c_void, xattr_count as *mut c_void, core::ptr::addr_of!(xattr_zone) as *mut c_void, value.as_mut_ptr() as *mut c_void) };
    0
}

// HAND: reject_unchecked_qstr -- translate the C below (see the file comment)
//   SEC("lsm/inode_init_security")
//   __failure __msg("invalid mem access 'trusted_ptr_or_null_'")
//   int BPF_PROG(reject_unchecked_qstr, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       scratch_count = qstr->len;
//       return 0;
//   }
// BPF_PROG(reject_unchecked_qstr, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn reject_unchecked_qstr(ctx: *mut u64) -> i32 {
    let qs = unsafe { *ctx.add(2) } as *mut qstr;
    unsafe { scratch_count = *(&*qs).len().get().unwrap() as i32 };
    0
}

// HAND: allow_spilled_count -- translate the C below (see the file comment)
//   SEC("lsm/inode_init_security")
//   __success
//   int BPF_PROG(allow_spilled_count, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       struct bpf_dynptr value;
//       int *saved = xattr_count;
//
//       if (!xattrs)
//           return 0;
//
//       bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
//       bpf_inode_init_xattr(xattrs, saved, xattr_zone, &value);
//       return 0;
//   }
// BPF_PROG(allow_spilled_count, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn allow_spilled_count(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut xattr;
    let xattr_count = unsafe { *ctx.add(4) } as *mut i32;
    let saved = xattr_count;
    if xattrs.is_null() {
        return 0;
    }
    let mut value = core::mem::MaybeUninit::<bpf_dynptr>::uninit();
    bpf_dynptr_from_mem(core::ptr::addr_of_mut!(value_buf) as *mut c_void, 8, 0, value.as_mut_ptr() as *mut c_void);
    unsafe { bpf_inode_init_xattr(xattrs as *mut c_void, saved as *mut c_void, core::ptr::addr_of!(xattr_zone) as *mut c_void, value.as_mut_ptr() as *mut c_void) };
    0
}

// HAND: reject_forged_count -- translate the C below (see the file comment)
//   SEC("lsm/inode_init_security")
//   __failure __msg("expected=rdonly_trusted_mem")
//   int BPF_PROG(reject_forged_count, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       struct bpf_dynptr value;
//
//       if (!xattrs)
//           return 0;
//
//       bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
//       bpf_inode_init_xattr(xattrs, &scratch_count, xattr_zone, &value);
//       return 0;
//   }
// BPF_PROG(reject_forged_count, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn reject_forged_count(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut xattr;
    let xattr_count = unsafe { *ctx.add(4) } as *mut i32;
    let _ = xattr_count;
    if xattrs.is_null() {
        return 0;
    }
    let mut value = core::mem::MaybeUninit::<bpf_dynptr>::uninit();
    bpf_dynptr_from_mem(core::ptr::addr_of_mut!(value_buf) as *mut c_void, 8, 0, value.as_mut_ptr() as *mut c_void);
    unsafe { bpf_inode_init_xattr(xattrs as *mut c_void, core::ptr::addr_of_mut!(scratch_count) as *mut c_void, core::ptr::addr_of!(xattr_zone) as *mut c_void, value.as_mut_ptr() as *mut c_void) };
    0
}

// HAND: reject_stack_count -- translate the C below (see the file comment)
//   SEC("lsm/inode_init_security")
//   __failure __msg("expected=rdonly_trusted_mem")
//   int BPF_PROG(reject_stack_count, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       struct bpf_dynptr value;
//       int local = 0;
//
//       if (!xattrs)
//           return 0;
//
//       bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
//       bpf_inode_init_xattr(xattrs, &local, xattr_zone, &value);
//       return 0;
//   }
// BPF_PROG(reject_stack_count, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn reject_stack_count(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut xattr;
    let xattr_count = unsafe { *ctx.add(4) } as *mut i32;
    let _ = xattr_count;
    let mut local: i32 = 0;
    if xattrs.is_null() {
        return 0;
    }
    let mut value = core::mem::MaybeUninit::<bpf_dynptr>::uninit();
    bpf_dynptr_from_mem(core::ptr::addr_of_mut!(value_buf) as *mut c_void, 8, 0, value.as_mut_ptr() as *mut c_void);
    unsafe { bpf_inode_init_xattr(xattrs as *mut c_void, &mut local as *mut i32 as *mut c_void, core::ptr::addr_of!(xattr_zone) as *mut c_void, value.as_mut_ptr() as *mut c_void) };
    0
}

// HAND: reject_other_ctx_arg -- translate the C below (see the file comment)
//   SEC("lsm/inode_init_security")
//   __failure __msg("expected=rdonly_trusted_mem")
//   int BPF_PROG(reject_other_ctx_arg, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       struct bpf_dynptr value;
//
//       if (!xattrs)
//           return 0;
//
//       bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
//       bpf_inode_init_xattr(xattrs, (int *)xattrs, xattr_zone, &value);
//       return 0;
//   }
// BPF_PROG(reject_other_ctx_arg, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn reject_other_ctx_arg(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut xattr;
    let xattr_count = unsafe { *ctx.add(4) } as *mut i32;
    let _ = xattr_count;
    if xattrs.is_null() {
        return 0;
    }
    let mut value = core::mem::MaybeUninit::<bpf_dynptr>::uninit();
    bpf_dynptr_from_mem(core::ptr::addr_of_mut!(value_buf) as *mut c_void, 8, 0, value.as_mut_ptr() as *mut c_void);
    unsafe { bpf_inode_init_xattr(xattrs as *mut c_void, xattrs as *mut i32 as *mut c_void, core::ptr::addr_of!(xattr_zone) as *mut c_void, value.as_mut_ptr() as *mut c_void) };
    0
}

// HAND: reject_null_count -- translate the C below (see the file comment)
//   SEC("lsm/inode_init_security")
//   __failure __msg("Possibly NULL pointer passed to trusted")
//   int BPF_PROG(reject_null_count, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       struct bpf_dynptr value;
//
//       if (!xattrs)
//           return 0;
//
//       bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
//       bpf_inode_init_xattr(xattrs, NULL, xattr_zone, &value);
//       return 0;
//   }
// BPF_PROG(reject_null_count, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn reject_null_count(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut xattr;
    let xattr_count = unsafe { *ctx.add(4) } as *mut i32;
    let _ = xattr_count;
    if xattrs.is_null() {
        return 0;
    }
    let mut value = core::mem::MaybeUninit::<bpf_dynptr>::uninit();
    bpf_dynptr_from_mem(core::ptr::addr_of_mut!(value_buf) as *mut c_void, 8, 0, value.as_mut_ptr() as *mut c_void);
    unsafe { bpf_inode_init_xattr(xattrs as *mut c_void, core::ptr::null_mut::<i32>() as *mut c_void, core::ptr::addr_of!(xattr_zone) as *mut c_void, value.as_mut_ptr() as *mut c_void) };
    0
}

// HAND: reject_shifted_count -- translate the C below (see the file comment)
//   SEC("lsm/inode_init_security")
//   __failure __msg("dereference of modified rdonly_trusted_mem ptr")
//   int BPF_PROG(reject_shifted_count, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       struct bpf_dynptr value;
//
//       if (!xattrs)
//           return 0;
//
//       bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
//       bpf_inode_init_xattr(xattrs, xattr_count + 1, xattr_zone, &value);
//       return 0;
//   }
// BPF_PROG(reject_shifted_count, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn reject_shifted_count(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut xattr;
    let xattr_count = unsafe { *ctx.add(4) } as *mut i32;
    if xattrs.is_null() {
        return 0;
    }
    let mut value = core::mem::MaybeUninit::<bpf_dynptr>::uninit();
    bpf_dynptr_from_mem(core::ptr::addr_of_mut!(value_buf) as *mut c_void, 8, 0, value.as_mut_ptr() as *mut c_void);
    unsafe { bpf_inode_init_xattr(xattrs as *mut c_void, xattr_count.wrapping_add(1) as *mut c_void, core::ptr::addr_of!(xattr_zone) as *mut c_void, value.as_mut_ptr() as *mut c_void) };
    0
}

// HAND: reject_var_shifted_count -- translate the C below (see the file comment)
//   SEC("lsm/inode_init_security")
//   __failure __msg("variable rdonly_trusted_mem access var_off=")
//   int BPF_PROG(reject_var_shifted_count, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       struct bpf_dynptr value;
//
//       if (!xattrs)
//           return 0;
//
//       bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
//       bpf_inode_init_xattr(xattrs, xattr_count + (scratch_count & 1),
//                    xattr_zone, &value);
//       return 0;
//   }
// BPF_PROG(reject_var_shifted_count, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn reject_var_shifted_count(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut xattr;
    let xattr_count = unsafe { *ctx.add(4) } as *mut i32;
    if xattrs.is_null() {
        return 0;
    }
    let mut value = core::mem::MaybeUninit::<bpf_dynptr>::uninit();
    bpf_dynptr_from_mem(core::ptr::addr_of_mut!(value_buf) as *mut c_void, 8, 0, value.as_mut_ptr() as *mut c_void);
    unsafe { bpf_inode_init_xattr(xattrs as *mut c_void, xattr_count.wrapping_add((unsafe { scratch_count } & 1) as usize) as *mut c_void, core::ptr::addr_of!(xattr_zone) as *mut c_void, value.as_mut_ptr() as *mut c_void) };
    0
}

// HAND: reject_ctx_forged_count -- translate the C below (see the file comment)
//   SEC("lsm/inode_init_security")
//   __failure __msg("invalid bpf_context access")
//   int reject_ctx_forged_count(unsigned long long *ctx)
//   {
//       volatile unsigned long long *slot = ctx;
//       struct bpf_dynptr value;
//
//       bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
//       slot[4] = 0;
//       bpf_inode_init_xattr((struct xattr *)(long)slot[3],
//                    (int *)(long)slot[4], xattr_zone, &value);
//       return 0;
//   }
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn reject_ctx_forged_count(ctx: *mut u64) -> i32 {
    // volatile unsigned long long *slot = ctx
    let slot = ctx;
    let mut value = core::mem::MaybeUninit::<bpf_dynptr>::uninit();
    bpf_dynptr_from_mem(core::ptr::addr_of_mut!(value_buf) as *mut c_void, 8, 0, value.as_mut_ptr() as *mut c_void);
    unsafe {
        core::ptr::write_volatile(slot.add(4), 0);
        bpf_inode_init_xattr(
            core::ptr::read_volatile(slot.add(3)) as *mut c_void,
            core::ptr::read_volatile(slot.add(4)) as *mut c_void,
            core::ptr::addr_of!(xattr_zone) as *mut c_void,
            value.as_mut_ptr() as *mut c_void,
        );
    }
    0
}

// HAND: claim_via_subprog -- translate the C below (see the file comment)
//   static __noinline int claim_via_subprog(struct xattr *xattrs, int *xattr_count,
//                       struct bpf_dynptr *value)
//   {
//       return bpf_inode_init_xattr(xattrs, xattr_count, xattr_zone, value);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn claim_via_subprog(xattrs: *mut xattr, xattr_count: *mut i32, value: *mut bpf_dynptr) -> i32 {
    unsafe { bpf_inode_init_xattr(xattrs as *mut c_void, xattr_count as *mut c_void, core::ptr::addr_of!(xattr_zone) as *mut c_void, value as *mut c_void) }
}

// HAND: allow_count_via_subprog -- translate the C below (see the file comment)
//   SEC("lsm/inode_init_security")
//   __success
//   int BPF_PROG(allow_count_via_subprog, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       struct bpf_dynptr value;
//
//       if (!xattrs)
//           return 0;
//
//       bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
//       claim_via_subprog(xattrs, xattr_count, &value);
//       return 0;
//   }
// BPF_PROG(allow_count_via_subprog, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn allow_count_via_subprog(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut xattr;
    let xattr_count = unsafe { *ctx.add(4) } as *mut i32;
    if xattrs.is_null() {
        return 0;
    }
    let mut value = core::mem::MaybeUninit::<bpf_dynptr>::uninit();
    bpf_dynptr_from_mem(core::ptr::addr_of_mut!(value_buf) as *mut c_void, 8, 0, value.as_mut_ptr() as *mut c_void);
    claim_via_subprog(xattrs, xattr_count, value.as_mut_ptr());
    0
}

// HAND: reject_shifted_xattrs -- translate the C below (see the file comment)
//   SEC("lsm/inode_init_security")
//   __failure __msg("access beyond struct xattr at off 24")
//   int BPF_PROG(reject_shifted_xattrs, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       struct bpf_dynptr value;
//
//       if (!xattrs)
//           return 0;
//
//       bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
//       bpf_inode_init_xattr(xattrs + 1, xattr_count, xattr_zone, &value);
//       return 0;
//   }
// BPF_PROG(reject_shifted_xattrs, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn reject_shifted_xattrs(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut xattr;
    let xattr_count = unsafe { *ctx.add(4) } as *mut i32;
    if xattrs.is_null() {
        return 0;
    }
    let mut value = core::mem::MaybeUninit::<bpf_dynptr>::uninit();
    bpf_dynptr_from_mem(core::ptr::addr_of_mut!(value_buf) as *mut c_void, 8, 0, value.as_mut_ptr() as *mut c_void);
    unsafe { bpf_inode_init_xattr(xattrs.wrapping_add(1) as *mut c_void, xattr_count as *mut c_void, core::ptr::addr_of!(xattr_zone) as *mut c_void, value.as_mut_ptr() as *mut c_void) };
    0
}

// HAND: reject_sleepable -- translate the C below (see the file comment)
//   SEC("lsm.s/inode_init_security")
//   __failure __msg("bpf_lsm_inode_init_security is not sleepable")
//   int BPF_PROG(reject_sleepable, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       return 0;
//   }
// BPF_PROG(reject_sleepable, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm.s/inode_init_security"]
#[no_mangle]
extern "C" fn reject_sleepable(ctx: *mut u64) -> i32 {
    let _ = ctx;
    0
}

// HAND: reject_lsm_cgroup -- translate the C below (see the file comment)
//   SEC("lsm_cgroup/inode_init_security")
//   __failure __msg("calling kernel function bpf_inode_init_xattr is not allowed")
//   int BPF_PROG(reject_lsm_cgroup, struct inode *inode, struct inode *dir,
//            const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
//   {
//       struct bpf_dynptr value;
//
//       if (!xattrs)
//           return 0;
//
//       bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
//       bpf_inode_init_xattr(xattrs, xattr_count, xattr_zone, &value);
//       return 0;
//   }
// BPF_PROG(reject_lsm_cgroup, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm_cgroup/inode_init_security"]
#[no_mangle]
extern "C" fn reject_lsm_cgroup(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut xattr;
    let xattr_count = unsafe { *ctx.add(4) } as *mut i32;
    if xattrs.is_null() {
        return 0;
    }
    let mut value = core::mem::MaybeUninit::<bpf_dynptr>::uninit();
    bpf_dynptr_from_mem(core::ptr::addr_of_mut!(value_buf) as *mut c_void, 8, 0, value.as_mut_ptr() as *mut c_void);
    unsafe { bpf_inode_init_xattr(xattrs as *mut c_void, xattr_count as *mut c_void, core::ptr::addr_of!(xattr_zone) as *mut c_void, value.as_mut_ptr() as *mut c_void) };
    0
}

// HAND: reject_wrong_hook -- translate the C below (see the file comment)
//   SEC("lsm/inode_setxattr")
//   __failure __msg("calling kernel function bpf_inode_init_xattr is not allowed")
//   int BPF_PROG(reject_wrong_hook, struct mnt_idmap *idmap, struct dentry *dentry,
//            const char *name, const void *value, size_t size, int flags)
//   {
//       struct bpf_dynptr val;
//
//       bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &val);
//       bpf_inode_init_xattr(NULL, &scratch_count, xattr_zone, &val);
//       return 0;
//   }
// BPF_PROG(reject_wrong_hook, idmap, dentry, name, value, size, flags)
#[link_section = "lsm/inode_setxattr"]
#[no_mangle]
extern "C" fn reject_wrong_hook(_ctx: *mut u64) -> i32 {
    let mut val = core::mem::MaybeUninit::<bpf_dynptr>::uninit();
    bpf_dynptr_from_mem(core::ptr::addr_of_mut!(value_buf) as *mut c_void, 8, 0, val.as_mut_ptr() as *mut c_void);
    unsafe { bpf_inode_init_xattr(core::ptr::null_mut(), core::ptr::addr_of_mut!(scratch_count) as *mut c_void, core::ptr::addr_of!(xattr_zone) as *mut c_void, val.as_mut_ptr() as *mut c_void) };
    0
}
