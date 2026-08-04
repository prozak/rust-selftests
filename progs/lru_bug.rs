#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/lru_bug.c,
// bpf-rs-core idiom.
//
// The C source tags map_value.ptr with __kptr_untrusted (BTF_KIND_TYPE_TAG
// "kptr_untrusted"); rustc cannot emit BTF_KIND_TYPE_TAG (see
// btf-type-tag-uptr-kptr-unfixable), so the field is a plain task_struct
// pointer here and the map gets no btf_record. The kernel's real behavior
// relies on that tag: copy_map_value()/bpf_obj_memcpy() special-cases a
// kptr field by *skipping* its byte range, so a bpf_map_update_elem() that
// happens to reuse the just-deleted LRU node (the printk() fentry racing
// with nanosleep()'s delete+write below) leaves the stale `ptr` bytes
// untouched. Without the tag the kernel does a full plain memcpy instead,
// which would zero the field and flip the test's `result` assertion.
// last_ptr_addr reconstructs the same "leave it as it was" effect by hand:
// nanosleep() records the address it just wrote `current` into, and
// printk() reads that live memory back (bpf_probe_read_kernel, since the
// map has already logically deleted the entry by then) instead of writing
// a hard zero over it.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_task_btf, bpf_ktime_get_ns, bpf_map_delete_elem, bpf_map_lookup_elem,
    bpf_map_update_elem, bpf_probe_read_kernel,
};
use bpf_rs_core::maps::{self, BpfMap};
use btf_macros::btf;

#[btf]
struct task_struct {
    pid: i32,
}

#[repr(C)]
struct map_value {
    ptr: *mut task_struct,
}

#[link_section = ".maps"]
#[no_mangle]
static lru_map: BpfMap<i32, map_value, { maps::LRU_HASH }, 1> = BpfMap::new();

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut result: i32 = 1;

static mut last_ptr_addr: u64 = 0;

#[link_section = "fentry/bpf_ktime_get_ns"]
#[no_mangle]
extern "C" fn printk(_ctx: *const c_void) -> i32 {
    let mut v = map_value {
        ptr: core::ptr::null_mut(),
    };

    let cur: *mut task_struct = bpf_get_current_task_btf();
    let cur_pid = *unsafe { &*cur }.pid().get().unwrap();
    if unsafe { pid } == cur_pid {
        let addr = unsafe { last_ptr_addr };
        if addr != 0 {
            let mut stale: u64 = 0;
            bpf_probe_read_kernel(&mut stale, 8, addr as *const c_void);
            v.ptr = stale as *mut task_struct;
        }
        let key: i32 = 0;
        bpf_map_update_elem(&lru_map, &key, &v, 0);
    }
    0
}

#[link_section = "fentry/do_nanosleep"]
#[no_mangle]
extern "C" fn nanosleep(_ctx: *const c_void) -> i32 {
    let val = map_value {
        ptr: core::ptr::null_mut(),
    };
    let key: i32 = 0;

    bpf_map_update_elem(&lru_map, &key, &val, 0);
    let v = bpf_map_lookup_elem(&lru_map, &key) as *mut map_value;
    if v.is_null() {
        return 0;
    }
    bpf_map_delete_elem(&lru_map, &key);
    let current: *mut task_struct = bpf_get_current_task_btf();
    unsafe { (*v).ptr = current };
    unsafe { last_ptr_addr = core::ptr::addr_of_mut!((*v).ptr) as u64 };
    let current_pid = *unsafe { &*current }.pid().get().unwrap();
    unsafe { pid = current_pid };
    bpf_ktime_get_ns();
    unsafe { last_ptr_addr = 0 };
    unsafe { result = (*v).ptr.is_null() as i32 };
    0
}

bpf_object!("GPL");
