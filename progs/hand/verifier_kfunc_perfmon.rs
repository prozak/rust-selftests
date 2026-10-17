// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_kfunc_perfmon.c, translated
// by hand; include!d by the generated progs/verifier_kfunc_perfmon.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::bpf_dynptr_from_mem;

// HAND: rdonly_cast_noperfmon -- translate the C below (see the file comment)
//   SEC("socket")
//   __success
//   __caps_unpriv(CAP_BPF)
//   __failure_unpriv
//   __msg_unpriv("bpf_rdonly_cast is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
//   int rdonly_cast_noperfmon(void *ctx)
//   {
//       char *p = bpf_rdonly_cast(0, 0);
//
//       return p[0x7fff];
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn rdonly_cast_noperfmon(_ctx: *mut c_void) -> i32 {
    let p = unsafe { bpf_rdonly_cast(core::ptr::null_mut(), 0) } as *mut i8;
    unsafe { *p.add(0x7fff) as i32 }
}

// HAND: probe_read_kernel_dynptr_noperfmon -- translate the C below (see the file comment)
//   SEC("socket")
//   __success
//   __caps_unpriv(CAP_BPF)
//   __failure_unpriv
//   __msg_unpriv("bpf_probe_read_kernel_dynptr is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
//   int probe_read_kernel_dynptr_noperfmon(void *ctx)
//   {
//       struct bpf_dynptr dptr;
//
//       bpf_dynptr_from_mem(dynptr_buf, sizeof(dynptr_buf), 0, &dptr);
//       bpf_probe_read_kernel_dynptr(&dptr, 0, sizeof(dynptr_buf), user_ptr);
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn probe_read_kernel_dynptr_noperfmon(_ctx: *mut c_void) -> i32 {
    let mut dptr = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    bpf_dynptr_from_mem(core::ptr::addr_of_mut!(dynptr_buf) as *mut c_void, 8, 0, dptr.as_mut_ptr() as *mut c_void);
    unsafe { bpf_probe_read_kernel_dynptr(dptr.as_mut_ptr() as *mut c_void, 0, 8, user_ptr) };
    0
}

// HAND: stream_vprintk_noperfmon -- translate the C below (see the file comment)
//   SEC("socket")
//   __success
//   __caps_unpriv(CAP_BPF)
//   __failure_unpriv
//   __msg_unpriv("bpf_stream_vprintk is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
//   int stream_vprintk_noperfmon(void *ctx)
//   {
//       bpf_stream_printk(BPF_STDOUT, "%pB", (void *)kaddr);
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn stream_vprintk_noperfmon(_ctx: *mut c_void) -> i32 {
    // bpf_stream_printk(BPF_STDOUT, "%pB", (void *)kaddr): the format is the
    // function's `___fmt` static, the one argument an 8-byte array
    let param: [u64; 1] = [unsafe { kaddr }];
    unsafe {
        bpf_stream_vprintk(1, core::ptr::addr_of!(stream_vprintk_noperfmon____fmt) as *mut c_void, param.as_ptr() as *mut c_void, 8);
    }
    0
}

// HAND: get_kmem_cache_noperfmon -- translate the C below (see the file comment)
//   SEC("socket")
//   __success
//   __caps_unpriv(CAP_BPF)
//   __failure_unpriv
//   __msg_unpriv("bpf_get_kmem_cache is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
//   int get_kmem_cache_noperfmon(void *ctx)
//   {
//       return !!bpf_get_kmem_cache(kaddr);
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn get_kmem_cache_noperfmon(_ctx: *mut c_void) -> i32 {
    if unsafe { bpf_get_kmem_cache(kaddr) }.is_null() { 0 } else { 1 }
}

// HAND: subprog_untrusted_read -- translate the C below (see the file comment)
//   __weak int subprog_untrusted_read(void *p __arg_untrusted)
//   {
//       return *(char *)p;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_untrusted_read(p: *mut c_void) -> i32 {
    unsafe { *(p as *mut i8) as i32 }
}

// HAND: arg_untrusted_read_noperfmon -- translate the C below (see the file comment)
//   SEC("socket")
//   __success
//   __caps_unpriv(CAP_BPF)
//   __failure_unpriv
//   __msg_unpriv("rdonly_untrusted_mem access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
//   int arg_untrusted_read_noperfmon(void *ctx)
//   {
//       return subprog_untrusted_read(0);
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn arg_untrusted_read_noperfmon(_ctx: *mut c_void) -> i32 {
    subprog_untrusted_read(core::ptr::null_mut())
}
