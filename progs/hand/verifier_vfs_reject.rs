// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_vfs_reject.c, translated
// by hand; include!d by the generated progs/verifier_vfs_reject.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// Negative tests: the kernel structs the programs walk are CO-RE views
// (verifier_vfs_accept.rs), a BPF_PROG argument is the context slot.

use bpf_rs_core::helpers::bpf_get_current_task_btf;
use btf_macros::btf;

const PATH_MAX: u64 = 4096;
const EACCES: i32 = 13;

#[btf]
struct path {}

#[btf]
struct callback_head {}

#[btf]
struct file {
    f_path: path,
    f_task_work: callback_head,
}

#[btf]
struct fs_struct {
    root: path,
    pwd: path,
}

#[btf]
struct task_struct {
    parent: *mut task_struct,
    fs: *mut fs_struct,
}

#[btf]
struct inode {
    i_ino: u64,
}

#[btf]
struct dentry {
    d_inode: *mut inode,
}

#[inline(always)]
unsafe fn d_path(p: *mut c_void, size: u64) {
    bpf_path_d_path(p, core::ptr::addr_of_mut!(buf) as *mut c_void, size);
}

// HAND: get_task_exe_file_kfunc_null -- translate the C below (see the file comment)
//   SEC("lsm.s/file_open")
//   __failure __msg("Possibly NULL pointer passed to trusted R1")
//   int BPF_PROG(get_task_exe_file_kfunc_null)
//   {
//       struct file *acquired;
//
//       /* Can't pass a NULL pointer to bpf_get_task_exe_file(). */
//       acquired = bpf_get_task_exe_file(NULL);
//       if (!acquired)
//           return 0;
//
//       bpf_put_file(acquired);
//       return 0;
//   }
#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn get_task_exe_file_kfunc_null(_ctx: *mut u64) -> i32 {
    unsafe {
        // Can't pass a NULL pointer to bpf_get_task_exe_file().
        let acquired = bpf_get_task_exe_file(core::ptr::null_mut());
        if acquired.is_null() {
            return 0;
        }

        bpf_put_file(acquired);
    }
    0
}

// HAND: get_task_exe_file_kfunc_fp -- translate the C below (see the file comment)
//   SEC("lsm.s/inode_getxattr")
//   __failure __msg("R1 type=fp expected=ptr_, trusted_ptr_, rcu_ptr_")
//   int BPF_PROG(get_task_exe_file_kfunc_fp)
//   {
//       u64 x;
//       struct file *acquired;
//       struct task_struct *task;
//
//       task = (struct task_struct *)&x;
//       /* Can't pass random frame pointer to bpf_get_task_exe_file(). */
//       acquired = bpf_get_task_exe_file(task);
//       if (!acquired)
//           return 0;
//
//       bpf_put_file(acquired);
//       return 0;
//   }
#[link_section = "lsm.s/inode_getxattr"]
#[no_mangle]
extern "C" fn get_task_exe_file_kfunc_fp(_ctx: *mut u64) -> i32 {
    let mut x = core::mem::MaybeUninit::<u64>::uninit();

    unsafe {
        let task = x.as_mut_ptr() as *mut c_void;
        // Can't pass random frame pointer to bpf_get_task_exe_file().
        let acquired = bpf_get_task_exe_file(task);
        if acquired.is_null() {
            return 0;
        }

        bpf_put_file(acquired);
    }
    0
}

// HAND: get_task_exe_file_kfunc_untrusted -- translate the C below (see the file comment)
//   SEC("lsm.s/file_open")
//   __failure __msg("R1 must be referenced or trusted")
//   int BPF_PROG(get_task_exe_file_kfunc_untrusted)
//   {
//       struct file *acquired;
//       struct task_struct *parent;
//
//       /* Walking a trusted struct task_struct returned from
//        * bpf_get_current_task_btf() yields an untrusted pointer.
//        */
//       parent = bpf_get_current_task_btf()->parent;
//       /* Can't pass untrusted pointer to bpf_get_task_exe_file(). */
//       acquired = bpf_get_task_exe_file(parent);
//       if (!acquired)
//           return 0;
//
//       bpf_put_file(acquired);
//       return 0;
//   }
#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn get_task_exe_file_kfunc_untrusted(_ctx: *mut u64) -> i32 {
    unsafe {
        // Walking a trusted struct task_struct returned from
        // bpf_get_current_task_btf() yields an untrusted pointer.
        let parent: *mut task_struct = *(*bpf_get_current_task_btf::<task_struct>()).parent().get().unwrap();
        // Can't pass untrusted pointer to bpf_get_task_exe_file().
        let acquired = bpf_get_task_exe_file(parent as *mut c_void);
        if acquired.is_null() {
            return 0;
        }

        bpf_put_file(acquired);
    }
    0
}

// HAND: get_task_exe_file_kfunc_unreleased -- translate the C below (see the file comment)
//   SEC("lsm.s/file_open")
//   __failure __msg("Unreleased reference")
//   int BPF_PROG(get_task_exe_file_kfunc_unreleased)
//   {
//       struct file *acquired;
//
//       acquired = bpf_get_task_exe_file(bpf_get_current_task_btf());
//       if (!acquired)
//           return 0;
//
//       /* Acquired but never released. */
//       return 0;
//   }
#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn get_task_exe_file_kfunc_unreleased(_ctx: *mut u64) -> i32 {
    unsafe {
        let acquired = bpf_get_task_exe_file(bpf_get_current_task_btf::<c_void>());
        if acquired.is_null() {
            return 0;
        }
    }

    // Acquired but never released.
    0
}

// HAND: put_file_kfunc_unacquired -- translate the C below (see the file comment)
//   SEC("lsm.s/file_open")
//   __failure __msg("release function bpf_put_file expects referenced PTR_TO_BTF_ID passed to R1")
//   int BPF_PROG(put_file_kfunc_unacquired, struct file *file)
//   {
//       /* Can't release an unacquired pointer. */
//       bpf_put_file(file);
//       return 0;
//   }
#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn put_file_kfunc_unacquired(ctx: *mut u64) -> i32 {
    unsafe {
        let f = *ctx as *mut c_void;
        // Can't release an unacquired pointer.
        bpf_put_file(f);
    }
    0
}

// HAND: path_d_path_kfunc_null -- translate the C below (see the file comment)
//   SEC("lsm.s/file_open")
//   __failure __msg("Possibly NULL pointer passed to trusted R1")
//   int BPF_PROG(path_d_path_kfunc_null)
//   {
//       /* Can't pass NULL value to bpf_path_d_path() kfunc. */
//       bpf_path_d_path(NULL, buf, sizeof(buf));
//       return 0;
//   }
#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn path_d_path_kfunc_null(_ctx: *mut u64) -> i32 {
    // Can't pass NULL value to bpf_path_d_path() kfunc.
    unsafe { d_path(core::ptr::null_mut(), PATH_MAX) };
    0
}

// HAND: path_d_path_kfunc_untrusted_from_argument -- translate the C below (see the file comment)
//   SEC("lsm.s/task_alloc")
//   __failure __msg("dereference of modified untrusted_ptr_")
//   int BPF_PROG(path_d_path_kfunc_untrusted_from_argument, struct task_struct *task)
//   {
//       struct path *root;
//
//       /* Walking a trusted argument typically yields an untrusted
//        * pointer. This is one example of that.
//        */
//       root = &task->fs->root;
//       bpf_path_d_path(root, buf, sizeof(buf));
//       return 0;
//   }
#[link_section = "lsm.s/task_alloc"]
#[no_mangle]
extern "C" fn path_d_path_kfunc_untrusted_from_argument(ctx: *mut u64) -> i32 {
    unsafe {
        let task = *ctx as *mut task_struct;
        // Walking a trusted argument typically yields an untrusted
        // pointer. This is one example of that.
        let fs: *mut fs_struct = *(*task).fs().get().unwrap();
        let root = (*fs).root().field.as_mut_ptr();
        d_path(root as *mut c_void, PATH_MAX);
    }
    0
}

// HAND: path_d_path_kfunc_untrusted_from_current -- translate the C below (see the file comment)
//   SEC("lsm.s/file_open")
//   __failure __msg("dereference of modified untrusted_ptr_")
//   int BPF_PROG(path_d_path_kfunc_untrusted_from_current)
//   {
//       struct path *pwd;
//       struct task_struct *current;
//
//       current = bpf_get_current_task_btf();
//       /* Walking a trusted pointer returned from bpf_get_current_task_btf()
//        * yields an untrusted pointer.
//        */
//       pwd = &current->fs->pwd;
//       bpf_path_d_path(pwd, buf, sizeof(buf));
//       return 0;
//   }
#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn path_d_path_kfunc_untrusted_from_current(_ctx: *mut u64) -> i32 {
    unsafe {
        let current = bpf_get_current_task_btf::<task_struct>();
        // Walking a trusted pointer returned from bpf_get_current_task_btf()
        // yields an untrusted pointer.
        let fs: *mut fs_struct = *(*current).fs().get().unwrap();
        let pwd = (*fs).pwd().field.as_mut_ptr();
        d_path(pwd as *mut c_void, PATH_MAX);
    }
    0
}

// HAND: path_d_path_kfunc_type_mismatch -- translate the C below (see the file comment)
//   SEC("lsm.s/file_open")
//   __failure __msg("bpf_path_d_path R1 expected pointer to STRUCT path but R1 has a pointer to STRUCT file")
//   int BPF_PROG(path_d_path_kfunc_type_mismatch, struct file *file)
//   {
//       bpf_path_d_path((struct path *)&file->f_task_work, buf, sizeof(buf));
//       return 0;
//   }
#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn path_d_path_kfunc_type_mismatch(ctx: *mut u64) -> i32 {
    unsafe {
        let f = *ctx as *mut file;
        d_path((*f).f_task_work().field.as_mut_ptr() as *mut c_void, PATH_MAX);
    }
    0
}

// HAND: path_d_path_kfunc_invalid_buf_sz -- translate the C below (see the file comment)
//   SEC("lsm.s/file_open")
//   __failure __msg("invalid access to map value, value_size=4096 off=0 size=8192")
//   int BPF_PROG(path_d_path_kfunc_invalid_buf_sz, struct file *file)
//   {
//       /* bpf_path_d_path() enforces a constraint on the buffer size supplied
//        * by the BPF LSM program via the __sz annotation. buf here is set to
//        * PATH_MAX, so let's ensure that the BPF verifier rejects BPF_PROG_LOAD
//        * attempts if the supplied size and the actual size of the buffer
//        * mismatches.
//        */
//       bpf_path_d_path(&file->f_path, buf, PATH_MAX * 2);
//       return 0;
//   }
#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn path_d_path_kfunc_invalid_buf_sz(ctx: *mut u64) -> i32 {
    unsafe {
        let f = *ctx as *mut file;
        // bpf_path_d_path() enforces a constraint on the buffer size supplied
        // by the BPF LSM program via the __sz annotation. buf here is set to
        // PATH_MAX, so let's ensure that the BPF verifier rejects BPF_PROG_LOAD
        // attempts if the supplied size and the actual size of the buffer
        // mismatches.
        d_path((*f).f_path().field.as_mut_ptr() as *mut c_void, PATH_MAX * 2);
    }
    0
}

// HAND: path_d_path_kfunc_non_lsm -- translate the C below (see the file comment)
//   SEC("fentry/vfs_open")
//   __failure __msg("calling kernel function bpf_path_d_path is not allowed")
//   int BPF_PROG(path_d_path_kfunc_non_lsm, struct path *path, struct file *f)
//   {
//       /* Calling bpf_path_d_path() from a non-LSM BPF program isn't permitted.
//        */
//       bpf_path_d_path(path, buf, sizeof(buf));
//       return 0;
//   }
#[link_section = "fentry/vfs_open"]
#[no_mangle]
extern "C" fn path_d_path_kfunc_non_lsm(ctx: *mut u64) -> i32 {
    unsafe {
        let p = *ctx as *mut c_void;
        // Calling bpf_path_d_path() from a non-LSM BPF program isn't permitted.
        d_path(p, PATH_MAX);
    }
    0
}

// HAND: inode_rename -- translate the C below (see the file comment)
//   SEC("lsm.s/inode_rename")
//   __failure __msg("invalid mem access 'trusted_ptr_or_null_'")
//   int BPF_PROG(inode_rename, struct inode *old_dir, struct dentry *old_dentry,
//            struct inode *new_dir, struct dentry *new_dentry,
//            unsigned int flags)
//   {
//       struct inode *inode = new_dentry->d_inode;
//       ino_t ino;
//
//       ino = inode->i_ino;
//       if (ino == 0)
//           return -EACCES;
//       return 0;
//   }
#[link_section = "lsm.s/inode_rename"]
#[no_mangle]
extern "C" fn inode_rename(ctx: *mut u64) -> i32 {
    unsafe {
        let new_dentry = *ctx.add(3) as *mut dentry;
        let ino_p: *mut inode = *(*new_dentry).d_inode().get().unwrap();

        let ino = *(*ino_p).i_ino().get().unwrap();
        if ino == 0 {
            return -EACCES;
        }
    }
    0
}
