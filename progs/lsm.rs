#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/lsm.c
// bpf-rs-core idiom, sibling in style to progs/lsm_bdev.rs (same
// arg(ctx, i)-over-fentry-style-ctx idiom for lsm/lsm.s hooks).
//
// Each nontrivial program's body is factored into its own #[inline(never)]
// fn (BPF_PSEUDO_CALL subprog) per [[rel-btf-shinfo-corruption-workaround-shared-fn]]:
// an object with 2+ program sections where at least one has real branching
// logic reliably corrupts .rel.BTF's sh_info during btf_rename, and routing
// the branchy body through a real subprog call (thin single-block extern
// "C" wrapper) dodges it.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_copy_from_user, bpf_get_current_pid_tgid, bpf_map_lookup_elem, bpf_probe_read_kernel,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

const EPERM: i32 = 1;
const EFAULT: i64 = -14;

// enum bpf_map_type values not exported by bpf_rs_core::maps.
const ARRAY_OF_MAPS: usize = 12;
const HASH_OF_MAPS: usize = 13;

// x86-64: struct pt_regs register-slot byte offsets (see
// progs/test_vmlinux.rs's GP_DI/GP_SI -- same fixed-offset
// bpf_probe_read_kernel idiom, here used from a u64 address rather than a
// raw_tp ctx slot index).
const GP_DI_OFF: u64 = 14 * 8; // PARM1_SYSCALL (di)
const GP_SI_OFF: u64 = 13 * 8; // PARM2_SYSCALL (si)

#[btf]
struct mm_struct {
    start_stack: u64,
    arg_start: u64,
}

#[btf]
struct vm_area_struct {
    vm_start: u64,
    vm_end: u64,
    vm_mm: *mut mm_struct,
}

#[btf]
struct linux_binprm {
    vma: *mut vm_area_struct,
    mm: *mut mm_struct,
}

type InnerMapDef = BpfMap<i32, u64, { maps::ARRAY }, 1>;

#[link_section = ".maps"]
#[no_mangle]
static array: BpfMap<u32, u64, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static hash: BpfMap<u32, u64, { maps::HASH }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static lru_hash: BpfMap<u32, u64, { maps::LRU_HASH }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static percpu_array: BpfMap<u32, u64, { maps::PERCPU_ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static percpu_hash: BpfMap<u32, u64, { maps::PERCPU_HASH }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static lru_percpu_hash: BpfMap<u32, u64, { maps::LRU_PERCPU_HASH }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static inner_map: InnerMapDef = BpfMap::new();

// Map-in-map static `.values = { [0] = &inner_map }` initializer: per
// [[prog-array-static-values-init-unfixable]], rustc cannot diverge a
// static's codegen type from its debug type the way clang's flexible-array
// trick requires, so the values slot stays unpopulated at load time. This
// is harmless here: test_lsm.c never asserts on outer_arr/outer_hash
// contents, only that test_void_hook's null-checked lookups don't crash.
#[repr(C)]
struct outer_arr_def {
    r#type: *const [i32; ARRAY_OF_MAPS],
    max_entries: *const [i32; 1],
    key_size: *const [i32; 4],
    value_size: *const [i32; 4],
    values: [*const InnerMapDef; 0],
}
unsafe impl Sync for outer_arr_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_arr: outer_arr_def = outer_arr_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    value_size: core::ptr::null(),
    values: [],
};

#[repr(C)]
struct outer_hash_def {
    r#type: *const [i32; HASH_OF_MAPS],
    max_entries: *const [i32; 1],
    key_size: *const [i32; 4],
    values: [*const InnerMapDef; 0],
}
unsafe impl Sync for outer_hash_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_hash: outer_hash_def = outer_hash_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [],
};

#[no_mangle]
static mut monitored_pid: i32 = 0;
#[no_mangle]
static mut mprotect_count: i32 = 0;
#[no_mangle]
static mut bprm_count: i32 = 0;
#[no_mangle]
static mut copy_test: i32 = 0;

#[inline(never)]
fn int_hook_body(ctx: *const u64) -> i32 {
    let vma = arg(ctx, 0) as *const vm_area_struct;
    let ret = arg(ctx, 3) as i32;

    let mm = unsafe { *(&*vma).vm_mm().as_ptr() };
    if ret != 0 || mm.is_null() {
        return ret;
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    let vm_start = unsafe { *(&*vma).vm_start().as_ptr() };
    let vm_end = unsafe { *(&*vma).vm_end().as_ptr() };
    let start_stack = unsafe { *(&*mm).start_stack().as_ptr() };

    let is_stack = vm_start <= start_stack && vm_end >= start_stack;

    let mut result = ret;
    if is_stack && unsafe { monitored_pid } == pid {
        unsafe {
            mprotect_count += 1;
        }
        result = -EPERM;
    }
    result
}

#[link_section = "lsm/file_mprotect"]
#[no_mangle]
extern "C" fn test_int_hook(ctx: *const u64) -> i32 {
    int_hook_body(ctx)
}

#[inline(never)]
fn void_hook_body(ctx: *const u64) {
    let bprm = arg(ctx, 0) as *const linux_binprm;

    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    if unsafe { monitored_pid } == pid {
        unsafe {
            bprm_count += 1;
        }
    }

    let mut args_buf: [u8; 64] = [0; 64];

    let vma = unsafe { *(&*bprm).vma().as_ptr() };
    let mm1 = unsafe { *(&*vma).vm_mm().as_ptr() };
    let arg_start1 = unsafe { *(&*mm1).arg_start().as_ptr() };
    bpf_copy_from_user(
        args_buf.as_mut_ptr() as *mut c_void,
        64,
        arg_start1 as *const c_void,
    );

    let mm2 = unsafe { *(&*bprm).mm().as_ptr() };
    let arg_start2 = unsafe { *(&*mm2).arg_start().as_ptr() };
    bpf_copy_from_user(
        args_buf.as_mut_ptr() as *mut c_void,
        64,
        arg_start2 as *const c_void,
    );

    let key: u32 = 0;

    let v = bpf_map_lookup_elem(&array, &key) as *mut u64;
    if !v.is_null() {
        unsafe {
            *v = 0;
        }
    }
    let v = bpf_map_lookup_elem(&hash, &key) as *mut u64;
    if !v.is_null() {
        unsafe {
            *v = 0;
        }
    }
    let v = bpf_map_lookup_elem(&lru_hash, &key) as *mut u64;
    if !v.is_null() {
        unsafe {
            *v = 0;
        }
    }
    let v = bpf_map_lookup_elem(&percpu_array, &key) as *mut u64;
    if !v.is_null() {
        unsafe {
            *v = 0;
        }
    }
    let v = bpf_map_lookup_elem(&percpu_hash, &key) as *mut u64;
    if !v.is_null() {
        unsafe {
            *v = 0;
        }
    }
    let v = bpf_map_lookup_elem(&lru_percpu_hash, &key) as *mut u64;
    if !v.is_null() {
        unsafe {
            *v = 0;
        }
    }

    let inner = bpf_map_lookup_elem(&outer_arr, &key) as *mut c_void;
    if !inner.is_null() {
        let v = bpf_map_lookup_elem(inner, &key) as *mut u64;
        if !v.is_null() {
            unsafe {
                *v = 0;
            }
        }
    }
    let inner = bpf_map_lookup_elem(&outer_hash, &key) as *mut c_void;
    if !inner.is_null() {
        let v = bpf_map_lookup_elem(inner, &key) as *mut u64;
        if !v.is_null() {
            unsafe {
                *v = 0;
            }
        }
    }
}

#[link_section = "lsm.s/bprm_committed_creds"]
#[no_mangle]
extern "C" fn test_void_hook(ctx: *const u64) -> i32 {
    void_hook_body(ctx);
    0
}

#[link_section = "lsm/task_free"] // lsm/ is ok, lsm.s/ fails
#[no_mangle]
extern "C" fn test_task_free(_ctx: *const u64) -> i32 {
    0
}

#[inline(never)]
fn sys_setdomainname_body(ctx: *const u64) {
    let regs = arg(ctx, 0);

    let mut ptr: u64 = 0;
    bpf_probe_read_kernel(&mut ptr, 8, (regs + GP_DI_OFF) as *const c_void);
    let mut len_raw: u64 = 0;
    bpf_probe_read_kernel(&mut len_raw, 8, (regs + GP_SI_OFF) as *const c_void);
    let len = len_raw as i32;

    let mut buf: i32 = 0;
    let ret = bpf_copy_from_user(&mut buf as *mut i32 as *mut c_void, 4, ptr as *const c_void);

    if len == -2 && ret == 0 && buf == 1234 {
        unsafe {
            copy_test += 1;
        }
    }
    if len == -3 && ret == EFAULT {
        unsafe {
            copy_test += 1;
        }
    }
    if len == -4 && ret == EFAULT {
        unsafe {
            copy_test += 1;
        }
    }
}

#[link_section = "fentry.s/__x64_sys_setdomainname"]
#[no_mangle]
extern "C" fn test_sys_setdomainname(ctx: *const u64) -> i32 {
    sys_setdomainname_body(ctx);
    0
}

bpf_object!("GPL");
