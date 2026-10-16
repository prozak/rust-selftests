// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// BTF_C_CHAR: u8

// Direct translation of tools/testing/selftests/bpf/progs/test_d_path.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_d_path, bpf_get_current_pid_tgid};
use bpf_rs_core::progs::fentry_arg;
use btf::{BtfType, Field};
use btf_macros::btf;

const MAX_PATH_LEN: usize = 128;
const MAX_FILES: usize = 7;

// `bpf_d_path` only ever needs `&file->f_path`'s address (it is never read
// through here), so `f_path` is declared as this opaque zero-sized STRUCT
// stand-in rather than a full `#[btf] struct path` field chain: CO-RE field
// relocation only requires the local/target member kinds to match
// (STRUCT<->STRUCT), same idea as test_core_reloc_primitives.rs's manual
// `BtfType` impl for its enum field. A manual impl gives this field's
// accessor `Field`'s `.as_ptr()`/`.as_mut_ptr()` directly, instead of the
// macro's chainable aggregate view (which has no address accessor).
#[repr(C)]
struct path_opaque {
    _priv: [u8; 0],
}

impl BtfType for path_opaque {
    type Carrier = Self;

    type View<'a, Root, Path, Mode>
        = Field<'a, Root, Self, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a;

    #[inline(always)]
    fn __btf_view<'a, Root, Path, Mode>(
        field: Field<'a, Root, Self, Path, Mode>,
    ) -> Self::View<'a, Root, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a,
    {
        field
    }
}

#[btf]
struct file {
    f_path: path_opaque,
}

fn file_f_path_ptr(file_ref: &file) -> *mut path_opaque {
    file_ref.f_path().as_mut_ptr()
}

#[no_mangle]
static mut my_pid: i32 = 0;
#[no_mangle]
static mut cnt_stat: u32 = 0;
#[no_mangle]
static mut cnt_close: u32 = 0;
#[no_mangle]
static mut paths_stat: [[u8; MAX_PATH_LEN]; MAX_FILES] = [[0; MAX_PATH_LEN]; MAX_FILES];
#[no_mangle]
static mut paths_close: [[u8; MAX_PATH_LEN]; MAX_FILES] = [[0; MAX_PATH_LEN]; MAX_FILES];
#[no_mangle]
static mut rets_stat: [i32; MAX_FILES] = [0; MAX_FILES];
#[no_mangle]
static mut rets_close: [i32; MAX_FILES] = [0; MAX_FILES];

#[no_mangle]
static mut called_stat: i32 = 0;
#[no_mangle]
static mut called_close: i32 = 0;
#[no_mangle]
static mut path_match_fallocate: i32 = 0;

#[link_section = "fentry/security_inode_getattr"]
#[no_mangle]
extern "C" fn prog_stat(ctx: *const u64) -> i32 {
    let path_ptr = fentry_arg(ctx, 0) as *mut path_opaque;

    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    let cnt = unsafe { cnt_stat };

    unsafe { called_stat = 1 };

    if pid != unsafe { my_pid } {
        return 0;
    }
    if cnt as usize >= MAX_FILES {
        return 0;
    }

    let buf = unsafe { paths_stat.as_mut_ptr().add(cnt as usize) };
    let ret = bpf_d_path(path_ptr, buf as *mut core::ffi::c_void, MAX_PATH_LEN as u32);

    unsafe { *rets_stat.as_mut_ptr().add(cnt as usize) = ret as i32 };
    unsafe { cnt_stat += 1 };
    0
}

#[link_section = "fentry/filp_close"]
#[no_mangle]
extern "C" fn prog_close(ctx: *const u64) -> i32 {
    let file_ptr = fentry_arg(ctx, 0) as *mut file;
    let file_ref = unsafe { &*file_ptr };

    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    let cnt = unsafe { cnt_close };

    unsafe { called_close = 1 };

    if pid != unsafe { my_pid } {
        return 0;
    }
    if cnt as usize >= MAX_FILES {
        return 0;
    }

    let path_ptr = file_f_path_ptr(file_ref);
    let buf = unsafe { paths_close.as_mut_ptr().add(cnt as usize) };
    let ret = bpf_d_path(path_ptr, buf as *mut core::ffi::c_void, MAX_PATH_LEN as u32);

    unsafe { *rets_close.as_mut_ptr().add(cnt as usize) = ret as i32 };
    unsafe { cnt_close += 1 };
    0
}

#[link_section = "fentry/vfs_fallocate"]
#[no_mangle]
extern "C" fn prog_fallocate(ctx: *const u64) -> i32 {
    let file_ptr = fentry_arg(ctx, 0) as *mut file;
    let file_ref = unsafe { &*file_ptr };

    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    if pid != unsafe { my_pid } {
        return 0;
    }

    let mut path_fallocate: [u8; MAX_PATH_LEN] = [0; MAX_PATH_LEN];

    let path_ptr = file_f_path_ptr(file_ref);
    let ret = bpf_d_path(
        path_ptr,
        path_fallocate.as_mut_ptr() as *mut core::ffi::c_void,
        MAX_PATH_LEN as u32,
    );
    if ret < 0 {
        return 0;
    }

    if path_fallocate[0] == 0 {
        return 0;
    }

    unsafe { path_match_fallocate = 1 };
    0
}

bpf_object!("GPL");
