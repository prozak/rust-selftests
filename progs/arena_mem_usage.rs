#![no_std]
#![no_main]

use core::{ffi::c_void, ptr::addr_of};

#[repr(u64)]
enum ArenaAddress { Start = 1u64 << 44 }

#[repr(C)]
struct ArenaMap {
    r#type: *const [i32; 33],
    map_flags: *const [i32; 1024],
    max_entries: *const [i32; 1000],
    map_extra: ArenaAddress,
}
unsafe impl Sync for ArenaMap {}

#[no_mangle]
#[link_section = ".maps"]
static arena: ArenaMap = ArenaMap {
    r#type: core::ptr::null(), map_flags: core::ptr::null(),
    max_entries: core::ptr::null(), map_extra: ArenaAddress::Start,
};

extern "C" {
    fn bpf_arena_alloc_pages(map: *const ArenaMap, addr: *mut c_void, page_cnt: u32, node_id: i32, flags: u64) -> *mut c_void;
    fn bpf_arena_free_pages(map: *const ArenaMap, ptr: *mut c_void, page_cnt: u32);
}

#[no_mangle]
static mut ptr: *mut char = core::ptr::null_mut();
#[no_mangle]
static mut alloc_cnt: i32 = 0;
#[no_mangle]
static mut free_byte_off: isize = 0;
#[no_mangle]
static mut free_cnt: i32 = 0;

#[no_mangle]
#[link_section = "syscall"]
extern "C" fn alloc(_arg0: *const c_void) -> i32 {
    unsafe { ptr = bpf_arena_alloc_pages(addr_of!(arena), core::ptr::null_mut(), alloc_cnt as u32, -1, 0).cast(); }
    0
}

#[no_mangle]
#[link_section = "syscall"]
extern "C" fn free_pages(_arg1: *const c_void) -> i32 {
    unsafe {
        if ptr.is_null() { return 1; }
        bpf_arena_free_pages(addr_of!(arena), (ptr as *mut u8).wrapping_offset(free_byte_off).cast(), free_cnt as u32);
    }
    0
}

bpf_rs_core::bpf_object!("GPL");
