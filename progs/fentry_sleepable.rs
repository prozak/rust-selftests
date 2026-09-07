#![no_std]
#![no_main]

use bpf_rs_core::helpers::bpf_copy_from_user;

#[no_mangle]
// Only passed through to the helper, never dereferenced here. Rust's
// c_void becomes enum c_void in BTF; the C consumer assigns a char buffer.
static mut user_ptr: *const char = core::ptr::null();
#[no_mangle]
static mut retval: i32 = 0;

#[no_mangle]
#[link_section = "fentry.s"]
extern "C" fn fentry_xdp(_arg0: *const u64) -> i32 {
    let mut buff = core::mem::MaybeUninit::<[u8; 64]>::uninit();
    unsafe { retval = bpf_copy_from_user(buff.as_mut_ptr().cast(), 64, user_ptr.cast()) as i32; }
    0
}

#[no_mangle]
#[link_section = "license"]
static LICENSE: [u8; 4] = *b"GPL\0";
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
