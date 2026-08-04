#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_task_local_data.c
// plus the inline library from progs/task_local_data.bpf.h (tld_object_init,
// __tld_fetch_key, tld_get_data), bpf-rs-core idiom.
//
// task_local_data.bpf.h's map values (struct tld_map_value) carry
// `struct tld_data_u __uptr *data;` / `struct tld_meta_u __uptr *meta;`
// fields. `__uptr` is a Clang BTF_KIND_TYPE_TAG that rustc cannot emit (see
// sweep/failed/uptr_map_failure.rs), so the kernel never classifies these
// fields as BPF_UPTR and direct LDX dereferences of the pointee (the C
// original's `tld_obj->data_map->meta->cnt`-style chains) get rejected as
// "invalid mem access 'scalar'" since the field is just an opaque u64 to the
// verifier. Reading the pointer *field itself* out of the map value is fine
// (it's an ordinary PTR_TO_MAP_VALUE load); only the follow-on read through
// that user-space address needs help, so every dereference of `.data`/`.meta`
// contents below goes through bpf_probe_read_user() instead of a raw LDX.

use core::ffi::c_void;
use core::mem::size_of;

use bpf_rs_core::helpers::{
    bpf_get_current_task_btf, bpf_probe_read_user, bpf_strncmp, bpf_task_storage_get,
};
use bpf_rs_core::{bpf_map, bpf_object};

const BPF_MAP_TYPE_TASK_STORAGE: i32 = 29;
const BPF_F_NO_PREALLOC: i32 = 1;
const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;

const PAGE_SIZE: i32 = 4096;
const TLD_NAME_LEN: usize = 62;
const TLD_METADATA_SIZE: i32 = 64; // sizeof(struct tld_metadata): name[62] + u16 size
const TLD_MAX_DATA_CNT: i32 = PAGE_SIZE / TLD_METADATA_SIZE - 1; // 63
const TLD_KEY_MAP_CREATE_RETRY: i32 = 10;

struct task_struct;

#[repr(C)]
struct TldKeyT {
    off: i16,
}

#[repr(C)]
struct TldMetadata {
    name: [u8; TLD_NAME_LEN],
    size: u16,
}

#[repr(C)]
struct TldMetaU {
    cnt: u16,
    size: u16,
    metadata: [TldMetadata; TLD_MAX_DATA_CNT as usize],
}

#[repr(C)]
struct TldDataU {
    unused: u64,
    data: [u8; (PAGE_SIZE - 8) as usize],
}

#[repr(C)]
struct TldMapValue {
    data: *mut TldDataU,
    meta: *mut TldMetaU,
    start: u16,
}

#[repr(C)]
struct TldKeys {
    value0: TldKeyT,
    value1: TldKeyT,
    value2: TldKeyT,
    value_not_exist: TldKeyT,
}

bpf_map! {
    tld_data_map {
        r#type: *const [i32; BPF_MAP_TYPE_TASK_STORAGE as usize],
        map_flags: *const [i32; BPF_F_NO_PREALLOC as usize],
        key: *const i32,
        value: *const TldMapValue,
    }
}

bpf_map! {
    tld_key_map {
        r#type: *const [i32; BPF_MAP_TYPE_TASK_STORAGE as usize],
        map_flags: *const [i32; BPF_F_NO_PREALLOC as usize],
        key: *const i32,
        value: *const TldKeys,
    }
}

struct TldObject {
    data_map: *mut TldMapValue,
    key_map: *mut TldKeys,
}

#[repr(C)]
struct test_tld_struct {
    a: u64,
    b: u64,
    c: u64,
    d: u64,
}

#[no_mangle]
static mut test_value0: i32 = 0;
#[no_mangle]
static mut test_value1: i32 = 0;
#[no_mangle]
static mut test_value2: test_tld_struct = test_tld_struct { a: 0, b: 0, c: 0, d: 0 };

#[inline(never)]
fn tld_object_init(task: *mut task_struct, tld_obj: &mut TldObject) -> i32 {
    tld_obj.data_map = bpf_task_storage_get(&tld_data_map, task, core::ptr::null_mut(), 0)
        as *mut TldMapValue;
    if tld_obj.data_map.is_null() {
        return -61; // -ENODATA
    }

    let mut i = 0;
    while i < TLD_KEY_MAP_CREATE_RETRY {
        tld_obj.key_map = bpf_task_storage_get(
            &tld_key_map,
            task,
            core::ptr::null_mut(),
            BPF_LOCAL_STORAGE_GET_F_CREATE,
        ) as *mut TldKeys;
        if !tld_obj.key_map.is_null() {
            break;
        }
        i += 1;
    }
    if tld_obj.key_map.is_null() {
        return -12; // -ENOMEM
    }

    0
}

#[inline(always)]
fn tld_round_up(x: i32, y: i32) -> i32 {
    ((x - 1) | (y - 1)) + 1
}

#[inline(always)]
unsafe fn read_meta_cnt(meta_ptr: *const c_void) -> i32 {
    let mut cnt: u16 = 0;
    bpf_probe_read_user(
        &mut cnt as *mut u16 as *mut c_void,
        size_of::<u16>() as u32,
        meta_ptr,
    );
    cnt as i32
}

#[inline(never)]
fn tld_fetch_key(tld_obj: &TldObject, name: *const u8, i_start: i32) -> i32 {
    let data_map = tld_obj.data_map;
    if data_map.is_null() {
        return 0;
    }
    let data_ptr = unsafe { (*data_map).data } as *const c_void;
    let meta_ptr = unsafe { (*data_map).meta } as *const c_void;
    if data_ptr.is_null() || meta_ptr.is_null() {
        return 0;
    }

    let start = unsafe { (*data_map).start } as i32;
    let cnt = unsafe { read_meta_cnt(meta_ptr) };
    // offset of `metadata` within tld_meta_u: cnt(u16) + size(u16) = 4 bytes
    let base = unsafe { (meta_ptr as *const u8).add(4) };

    let mut off: i32 = 0;
    let mut i: i32 = 0;
    while i < cnt {
        if i >= TLD_MAX_DATA_CNT {
            break;
        }

        let elem = unsafe { base.add((i as usize) * (TLD_METADATA_SIZE as usize)) };
        if i >= i_start {
            let mut namebuf = [0u8; TLD_NAME_LEN];
            unsafe {
                bpf_probe_read_user(
                    namebuf.as_mut_ptr() as *mut c_void,
                    TLD_NAME_LEN as u32,
                    elem as *const c_void,
                )
            };
            if bpf_strncmp(namebuf.as_ptr() as *const c_void, TLD_NAME_LEN as u32, name as *const c_void) == 0 {
                return start + off;
            }
        }

        let mut sz: u16 = 0;
        unsafe {
            bpf_probe_read_user(
                &mut sz as *mut u16 as *mut c_void,
                size_of::<u16>() as u32,
                elem.add(TLD_NAME_LEN) as *const c_void,
            )
        };
        off += tld_round_up(sz as i32, 8);
        i += 1;
    }

    -cnt
}

#[inline(never)]
fn tld_get_data(tld_obj: &TldObject, key: *mut TldKeyT, name: *const u8, size: i32) -> *mut c_void {
    let mut data: *mut c_void = core::ptr::null_mut();

    let data_map = tld_obj.data_map;
    let raw_data = unsafe { (*data_map).data } as *mut u8;
    if raw_data.is_null() {
        return data;
    }

    let mut off = unsafe { (*key).off } as i32;
    if off > 0 {
        if off < PAGE_SIZE - size {
            data = unsafe { raw_data.add(off as usize) } as *mut c_void;
        }
    } else {
        let cnt = -off;
        let meta_ptr = unsafe { (*data_map).meta } as *const c_void;
        if !meta_ptr.is_null() && cnt < unsafe { read_meta_cnt(meta_ptr) } {
            off = tld_fetch_key(tld_obj, name, cnt);
            unsafe { (*key).off = off as i16 };

            if off < PAGE_SIZE - size && off > 0 {
                data = unsafe { raw_data.add(off as usize) } as *mut c_void;
            }
        }
    }

    data
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn task_main(_ctx: *const c_void) -> i32 {
    let task = bpf_get_current_task_btf() as *mut task_struct;

    let mut tld_obj = TldObject {
        data_map: core::ptr::null_mut(),
        key_map: core::ptr::null_mut(),
    };
    if tld_object_init(task, &mut tld_obj) != 0 {
        return 1;
    }

    let key0 = unsafe { core::ptr::addr_of_mut!((*tld_obj.key_map).value0) };
    let p0 = tld_get_data(&tld_obj, key0, b"value0\0".as_ptr(), core::mem::size_of::<i32>() as i32);
    if !p0.is_null() {
        unsafe {
            bpf_probe_read_user(
                core::ptr::addr_of_mut!(test_value0) as *mut c_void,
                size_of::<i32>() as u32,
                p0 as *const c_void,
            )
        };
    } else {
        return 2;
    }

    let key1 = unsafe { core::ptr::addr_of_mut!((*tld_obj.key_map).value1) };
    let p1 = tld_get_data(&tld_obj, key1, b"value1\0".as_ptr(), core::mem::size_of::<i32>() as i32);
    if !p1.is_null() {
        unsafe {
            bpf_probe_read_user(
                core::ptr::addr_of_mut!(test_value1) as *mut c_void,
                size_of::<i32>() as u32,
                p1 as *const c_void,
            )
        };
    } else {
        return 3;
    }

    let key2 = unsafe { core::ptr::addr_of_mut!((*tld_obj.key_map).value2) };
    let p2 = tld_get_data(
        &tld_obj,
        key2,
        b"value2\0".as_ptr(),
        core::mem::size_of::<test_tld_struct>() as i32,
    );
    if !p2.is_null() {
        unsafe {
            bpf_probe_read_user(
                core::ptr::addr_of_mut!(test_value2) as *mut c_void,
                size_of::<test_tld_struct>() as u32,
                p2 as *const c_void,
            )
        };
    } else {
        return 4;
    }

    let key3 = unsafe { core::ptr::addr_of_mut!((*tld_obj.key_map).value_not_exist) };
    let p3 = tld_get_data(
        &tld_obj,
        key3,
        b"value_not_exist\0".as_ptr(),
        core::mem::size_of::<i32>() as i32,
    );
    if !p3.is_null() {
        return 5;
    }

    0
}

bpf_object!("GPL");
