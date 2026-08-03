#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/string_kfuncs_failure2.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

const XATTR_SIZE_MAX: usize = 65536;

#[no_mangle]
static mut long_str: [u8; XATTR_SIZE_MAX + 1] = [0; XATTR_SIZE_MAX + 1];

extern "C" {
    fn bpf_strcmp(s1: *const u8, s2: *const u8) -> i32;
    fn bpf_strcasecmp(s1: *const u8, s2: *const u8) -> i32;
    fn bpf_strncasecmp(s1: *const u8, s2: *const u8, len: usize) -> i32;
    fn bpf_strchr(s: *const u8, c: i32) -> i32;
    fn bpf_strchrnul(s: *const u8, c: i32) -> i32;
    fn bpf_strnchr(s: *const u8, count: usize, c: i32) -> i32;
    fn bpf_strrchr(s: *const u8, c: i32) -> i32;
    fn bpf_strlen(s: *const u8) -> i32;
    fn bpf_strnlen(s: *const u8, count: usize) -> i32;
    fn bpf_strspn(s: *const u8, accept: *const u8) -> i32;
    fn bpf_strcspn(s: *const u8, reject: *const u8) -> i32;
    fn bpf_strstr(s1: *const u8, s2: *const u8) -> i32;
    fn bpf_strcasestr(s1: *const u8, s2: *const u8) -> i32;
    fn bpf_strnstr(s1: *const u8, s2: *const u8, len: usize) -> i32;
    fn bpf_strncasestr(s1: *const u8, s2: *const u8, len: usize) -> i32;
}

#[inline(always)]
fn long_str_ptr() -> *const u8 {
    core::ptr::addr_of!(long_str) as *const u8
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcmp_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcmp(long_str_ptr(), long_str_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasecmp_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasecmp(long_str_ptr(), long_str_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasecmp_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasecmp(long_str_ptr(), long_str_ptr(), XATTR_SIZE_MAX + 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strchr_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strchr(long_str_ptr(), 'b' as i32) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strchrnul_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strchrnul(long_str_ptr(), 'b' as i32) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnchr_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnchr(long_str_ptr(), XATTR_SIZE_MAX + 1, 'b' as i32) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strrchr_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strrchr(long_str_ptr(), 'b' as i32) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strlen_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strlen(long_str_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnlen_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnlen(long_str_ptr(), XATTR_SIZE_MAX + 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strspn_str_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strspn(long_str_ptr(), b"a\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strspn_accept_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strspn(b"b\0".as_ptr(), long_str_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcspn_str_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcspn(long_str_ptr(), b"b\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcspn_reject_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcspn(b"b\0".as_ptr(), long_str_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strstr_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strstr(long_str_ptr(), b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasestr_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasestr(long_str_ptr(), b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnstr_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnstr(long_str_ptr(), b"hello\0".as_ptr(), XATTR_SIZE_MAX + 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasestr_too_long(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasestr(long_str_ptr(), b"hello\0".as_ptr(), XATTR_SIZE_MAX + 1) }
}

bpf_object!("GPL");
