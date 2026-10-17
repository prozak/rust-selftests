// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_vfs_accept.c, translated
// by hand; include!d by the generated progs/verifier_vfs_accept.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::bpf_get_current_task_btf;
use btf_macros::btf;

// The kernel structs the programs walk, read with CO-RE.
#[btf]
struct path {}

#[btf]
struct file {
    f_path: path,
}

#[btf]
struct inode {
    i_ino: u64,
}

#[btf]
struct dentry {
    d_inode: *mut inode,
}

// HAND: get_task_exe_file_and_put_kfunc_from_current_sleepable -- translate the C below (see the file comment)
//   SEC("lsm.s/file_open")
//   __success
//   int BPF_PROG(get_task_exe_file_and_put_kfunc_from_current_sleepable)
//   {
//       struct file *acquired;
//
//       acquired = bpf_get_task_exe_file(bpf_get_current_task_btf());
//       if (!acquired)
//           return 0;
//
//       bpf_put_file(acquired);
//       return 0;
//   }
#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn get_task_exe_file_and_put_kfunc_from_current_sleepable(_ctx: *mut u64) -> i32 {
    unsafe {
        let acquired = bpf_get_task_exe_file(bpf_get_current_task_btf::<c_void>());
        if acquired.is_null() {
            return 0;
        }
        bpf_put_file(acquired);
    }
    0
}

// HAND: get_task_exe_file_and_put_kfunc_from_current_non_sleepable -- translate the C below (see the file comment)
//   SEC("lsm/file_open")
//   __success
//   int BPF_PROG(get_task_exe_file_and_put_kfunc_from_current_non_sleepable, struct file *file)
//   {
//       struct file *acquired;
//
//       acquired = bpf_get_task_exe_file(bpf_get_current_task_btf());
//       if (!acquired)
//           return 0;
//
//       bpf_put_file(acquired);
//       return 0;
//   }
#[link_section = "lsm/file_open"]
#[no_mangle]
extern "C" fn get_task_exe_file_and_put_kfunc_from_current_non_sleepable(_ctx: *mut u64) -> i32 {
    unsafe {
        let acquired = bpf_get_task_exe_file(bpf_get_current_task_btf::<c_void>());
        if acquired.is_null() {
            return 0;
        }
        bpf_put_file(acquired);
    }
    0
}

// HAND: get_task_exe_file_and_put_kfunc_from_argument -- translate the C below (see the file comment)
//   SEC("lsm.s/task_alloc")
//   __success
//   int BPF_PROG(get_task_exe_file_and_put_kfunc_from_argument,
//            struct task_struct *task)
//   {
//       struct file *acquired;
//
//       acquired = bpf_get_task_exe_file(task);
//       if (!acquired)
//           return 0;
//
//       bpf_put_file(acquired);
//       return 0;
//   }
// BPF_PROG(..., struct task_struct *task)
#[link_section = "lsm.s/task_alloc"]
#[no_mangle]
extern "C" fn get_task_exe_file_and_put_kfunc_from_argument(ctx: *mut u64) -> i32 {
    unsafe {
        let task = *ctx as *mut c_void;
        let acquired = bpf_get_task_exe_file(task);
        if acquired.is_null() {
            return 0;
        }
        bpf_put_file(acquired);
    }
    0
}

// HAND: path_d_path_from_path_argument -- translate the C below (see the file comment)
//   SEC("lsm.s/inode_getattr")
//   __success
//   int BPF_PROG(path_d_path_from_path_argument, struct path *path)
//   {
//       int ret;
//
//       ret = bpf_path_d_path(path, buf, sizeof(buf));
//       __sink(ret);
//       return 0;
//   }
// BPF_PROG(..., struct path *path)
#[link_section = "lsm.s/inode_getattr"]
#[no_mangle]
extern "C" fn path_d_path_from_path_argument(ctx: *mut u64) -> i32 {
    let pth = unsafe { *ctx } as *mut c_void;
    let ret = unsafe { bpf_path_d_path(pth, core::ptr::addr_of_mut!(buf) as *mut c_void, 64) };
    unsafe { core::arch::asm!("{0} = {0}", inout(reg) ret => _, options(nostack, preserves_flags)) };
    0
}

// HAND: path_d_path_from_file_argument -- translate the C below (see the file comment)
//   SEC("lsm.s/file_open")
//   __success
//   int BPF_PROG(path_d_path_from_file_argument, struct file *file)
//   {
//       int ret;
//       const struct path *path;
//
//       /* The f_path member is a path which is embedded directly within a
//        * file. Therefore, a pointer to such embedded members are still
//        * recognized by the BPF verifier as being PTR_TRUSTED as it's
//        * essentially PTR_TRUSTED w/ a non-zero fixed offset.
//        */
//       path = &file->f_path;
//       ret = bpf_path_d_path(path, buf, sizeof(buf));
//       __sink(ret);
//       return 0;
//   }
// BPF_PROG(..., struct file *file)
#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn path_d_path_from_file_argument(ctx: *mut u64) -> i32 {
    // &file->f_path: a pointer to an embedded member of a PTR_TRUSTED is
    // still PTR_TRUSTED, at a non-zero fixed offset
    let fp = unsafe { *ctx } as *mut file;
    let pth = unsafe { &*fp }.f_path().field.as_mut_ptr();
    let ret = unsafe { bpf_path_d_path(pth as *mut c_void, core::ptr::addr_of_mut!(buf) as *mut c_void, 64) };
    unsafe { core::arch::asm!("{0} = {0}", inout(reg) ret => _, options(nostack, preserves_flags)) };
    0
}

// HAND: inode_rename -- translate the C below (see the file comment)
//   SEC("lsm.s/inode_rename")
//   __success
//   int BPF_PROG(inode_rename, struct inode *old_dir, struct dentry *old_dentry,
//            struct inode *new_dir, struct dentry *new_dentry,
//            unsigned int flags)
//   {
//       struct inode *inode = new_dentry->d_inode;
//       ino_t ino;
//
//       if (!inode)
//           return 0;
//       ino = inode->i_ino;
//       if (ino == 0)
//           return -EACCES;
//       return 0;
//   }
// BPF_PROG(inode_rename, struct inode *old_dir, struct dentry *old_dentry,
//          struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
#[link_section = "lsm.s/inode_rename"]
#[no_mangle]
extern "C" fn inode_rename(ctx: *mut u64) -> i32 {
    let new_dentry = unsafe { *ctx.add(3) } as *mut dentry;
    let ino_p = *unsafe { &*new_dentry }.d_inode().get().unwrap();
    if ino_p.is_null() {
        return 0;
    }
    let ino = *unsafe { &*ino_p }.i_ino().get().unwrap();
    if ino == 0 {
        return -13; // -EACCES
    }
    0
}
