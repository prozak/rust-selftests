// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_lsm.c, translated
// by hand; include!d by the generated progs/verifier_lsm.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use btf_macros::btf;

/// struct file's f_inode, read with CO-RE (the kernel's layout).
#[btf]
struct file {
    f_inode: *mut inode,
}

#[btf]
struct inode {}

// HAND: no_null_check -- translate the C below (see the file comment)
//   SEC("lsm/mmap_file")
//   __description("not null checking nullable pointer in bpf_lsm_mmap_file")
//   __failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
//   int BPF_PROG(no_null_check, struct file *file)
//   {
//       struct inode *inode;
//
//       inode = file->f_inode;
//       __sink(inode);
//
//       return 0;
//   }
// BPF_PROG(no_null_check, struct file *file): ctx[0] is the file
#[link_section = "lsm/mmap_file"]
#[no_mangle]
extern "C" fn no_null_check(ctx: *mut u64) -> i32 {
    let fp = unsafe { *ctx } as *mut file;
    let ino = *unsafe { &*fp }.f_inode().get().unwrap();
    unsafe { core::arch::asm!("{0} = {0}", inout(reg) ino => _, options(nostack, preserves_flags)) };
    0
}

// HAND: null_check -- translate the C below (see the file comment)
//   SEC("lsm/mmap_file")
//   __description("null checking nullable pointer in bpf_lsm_mmap_file")
//   __success
//   int BPF_PROG(null_check, struct file *file)
//   {
//       struct inode *inode;
//
//       if (file) {
//           inode = file->f_inode;
//           __sink(inode);
//       }
//
//       return 0;
//   }
#[link_section = "lsm/mmap_file"]
#[no_mangle]
extern "C" fn null_check(ctx: *mut u64) -> i32 {
    let fp = unsafe { *ctx } as *mut file;
    if !fp.is_null() {
        let ino = *unsafe { &*fp }.f_inode().get().unwrap();
        unsafe { core::arch::asm!("{0} = {0}", inout(reg) ino => _, options(nostack, preserves_flags)) };
    }
    0
}

// HAND: sleepable_lsm_cgroup -- translate the C below (see the file comment)
//   SEC("lsm_cgroup/file_open")
//   __description("sleepable lsm_cgroup program is rejected")
//   __failure __msg("Program of this type cannot be sleepable")
//   __flag(BPF_F_SLEEPABLE)
//   int BPF_PROG(sleepable_lsm_cgroup)
//   {
//       return 0;
//   }
#[link_section = "lsm_cgroup/file_open"]
#[no_mangle]
extern "C" fn sleepable_lsm_cgroup(_ctx: *mut u64) -> i32 {
    0
}
