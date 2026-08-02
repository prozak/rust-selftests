#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_probe_user.c
// (bpf-rs-core idiom). Only the "ksyscall/connect" program is translated:
// the C source's second program ("ksyscall/socketcall") only exists
// `#if defined(bpf_target_s390)`, so it is never part of this object on any
// other arch (including UML/x86_64, which this build targets).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user, bpf_probe_write_user,
};
use core::ffi::c_void;

/// Mirrors C's `struct test_pro_bss { struct sockaddr_in old; __u32 test_pid; }`.
/// `old` is kept as an opaque 16-byte buffer (sizeof(struct sockaddr_in)): the
/// program only ever copies it by size (bpf_probe_read_user/memcmp on the
/// userspace side), never through named fields.
#[repr(C)]
pub struct TestProBss {
    pub old: [u8; 16],
    pub test_pid: u32,
}

#[no_mangle]
static mut bss: TestProBss = TestProBss {
    old: [0; 16],
    test_pid: 0,
};

fn handle_sys_connect_common(uservaddr: *mut c_void) -> i32 {
    let cur = (bpf_get_current_pid_tgid() >> 32) as u32;
    let test_pid = unsafe { bss.test_pid };

    if test_pid != 0 && cur != test_pid {
        return 0;
    }

    unsafe {
        bpf_probe_read_user(
            core::ptr::addr_of_mut!(bss.old) as *mut c_void,
            16,
            uservaddr,
        );
    }

    let new = [0xabu8; 16];
    bpf_probe_write_user(uservaddr, new.as_ptr() as *const c_void, 16);

    0
}

/// BPF_KSYSCALL(handle_sys_connect, int fd, struct sockaddr_in *uservaddr,
/// int addrlen): ctx is `struct pt_regs *`. LINUX_HAS_SYSCALL_WRAPPER is a
/// `__kconfig` extern the macro branches on; rustc can't emit `__kconfig`
/// BTF VARs, so the branch is hardcoded here to match this build's kernel
/// (.config has CONFIG_ARCH_HAS_SYSCALL_WRAPPER=y for x86_64), i.e. the
/// "read pt_regs via the wrapper's inner regs pointer" branch.
/// ctx is the kprobe pt_regs at the entry of `__x64_sys_connect(struct
/// pt_regs *regs)`; x86_64's `struct pt_regs` is 21 `long`-sized fields
/// (r15,r14,r13,r12,bp,bx,r11,r10,r9,r8,ax,cx,dx,si,di,orig_ax,ip,cs,flags,
/// sp,ss), so it doubles as a `*const u64` register-slot array.
/// PT_REGS_PARM1(ctx) = ctx->di (slot 14) is the real syscall pt_regs
/// pointer; this is a direct ctx-relative load, which the verifier
/// auto-converts to a fault-tolerant PROBE_MEM read. That pointer is then
/// a plain scalar (not ctx-relative), so PT_REGS_PARM2_CORE_SYSCALL(regs)
/// = regs->si (slot 13, uservaddr, the second syscall arg) must go through
/// bpf_probe_read_kernel rather than a direct dereference.
#[link_section = "ksyscall/connect"]
#[no_mangle]
extern "C" fn handle_sys_connect(ctx: *const u64) -> i32 {
    let regs = unsafe { *ctx.add(14) } as *const u64;
    let mut uservaddr: u64 = 0;
    bpf_probe_read_kernel(&mut uservaddr, 8, unsafe { regs.add(13) } as *const c_void);
    handle_sys_connect_common(uservaddr as *mut c_void)
}

bpf_object!("GPL");
