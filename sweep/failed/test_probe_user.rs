#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_probe_user.c
// (bpf-rs-core idiom). Only the "ksyscall/connect" program is translated:
// the C source's second program ("ksyscall/socketcall") only exists
// `#if defined(bpf_target_s390)`, so it is never part of this object on any
// other arch (including UML/x86_64, which this build targets).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_write_user};
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
/// kconfig extern that resolves false here (arch/um never selects
/// CONFIG_ARCH_HAS_SYSCALL_WRAPPER), so the macro always takes the
/// "read syscall args straight off pt_regs" branch (PT_REGS_PARMn_SYSCALL).
/// UML's `struct pt_regs` is `{ struct uml_pt_regs regs; }`, whose first
/// field is `gp: [unsigned long; N]` at offset 0 (arch/x86/um), so ctx
/// doubles as a `*const u64` register-slot array; PARM1/2/3_SYSCALL are
/// gp[14]/gp[13]/gp[12] (di/si/dx) per tools/lib/bpf/bpf_tracing.h's
/// __UML_PT_REGS__ block. uservaddr is the second syscall arg (si).
#[link_section = "ksyscall/connect"]
#[no_mangle]
extern "C" fn handle_sys_connect(ctx: *const u64) -> i32 {
    let uservaddr = unsafe { *ctx.add(13) } as *mut c_void;
    handle_sys_connect_common(uservaddr)
}

bpf_object!("GPL");
