#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/string_kfuncs_success.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

extern "C" {
    fn bpf_strcmp(s1: *const u8, s2: *const u8) -> i32;
    fn bpf_strcasecmp(s1: *const u8, s2: *const u8) -> i32;
    fn bpf_strncasecmp(s1: *const u8, s2: *const u8, len: usize) -> i32;
    fn bpf_strnchr(s: *const u8, count: usize, c: i8) -> i32;
    fn bpf_strchr(s: *const u8, c: i8) -> i32;
    fn bpf_strchrnul(s: *const u8, c: i8) -> i32;
    fn bpf_strrchr(s: *const u8, c: i32) -> i32;
    fn bpf_strnlen(s: *const u8, count: usize) -> i32;
    fn bpf_strlen(s: *const u8) -> i32;
    fn bpf_strspn(s: *const u8, accept: *const u8) -> i32;
    fn bpf_strcspn(s: *const u8, reject: *const u8) -> i32;
    fn bpf_strstr(s1: *const u8, s2: *const u8) -> i32;
    fn bpf_strcasestr(s1: *const u8, s2: *const u8) -> i32;
    fn bpf_strnstr(s1: *const u8, s2: *const u8, len: usize) -> i32;
    fn bpf_strncasestr(s1: *const u8, s2: *const u8, len: usize) -> i32;
}

#[no_mangle]
static mut str: [u8; 12] = *b"hello world\0";

macro_rules! s {
    ($ptr:expr) => {
        $ptr as *const u8
    };
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcmp_eq(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcmp(s!(core::ptr::addr_of!(str)), s!(b"hello world\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcmp_neq(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcmp(s!(core::ptr::addr_of!(str)), s!(b"hello\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasecmp_eq1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasecmp(s!(core::ptr::addr_of!(str)), s!(b"hello world\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasecmp_eq2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasecmp(s!(core::ptr::addr_of!(str)), s!(b"HELLO WORLD\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasecmp_eq3(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasecmp(s!(core::ptr::addr_of!(str)), s!(b"HELLO world\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasecmp_neq1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasecmp(s!(core::ptr::addr_of!(str)), s!(b"hello\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasecmp_neq2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasecmp(s!(core::ptr::addr_of!(str)), s!(b"HELLO\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasecmp_eq1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasecmp(s!(core::ptr::addr_of!(str)), s!(b"hello world\0"), 11) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasecmp_eq2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasecmp(s!(core::ptr::addr_of!(str)), s!(b"HELLO WORLD\0"), 11) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasecmp_eq3(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasecmp(s!(core::ptr::addr_of!(str)), s!(b"HELLO world\0"), 11) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasecmp_eq4(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasecmp(s!(core::ptr::addr_of!(str)), s!(b"hello\0"), 5) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasecmp_eq5(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasecmp(s!(core::ptr::addr_of!(str)), s!(b"hello world!\0"), 11) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasecmp_neq1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasecmp(s!(core::ptr::addr_of!(str)), s!(b"hello!\0"), 6) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasecmp_neq2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasecmp(s!(core::ptr::addr_of!(str)), s!(b"abc\0"), 3) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strchr_found(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strchr(s!(core::ptr::addr_of!(str)), b'e' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strchr_null(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strchr(s!(core::ptr::addr_of!(str)), 0i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strchr_notfound(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strchr(s!(core::ptr::addr_of!(str)), b'x' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strchrnul_found(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strchrnul(s!(core::ptr::addr_of!(str)), b'e' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strchrnul_notfound(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strchrnul(s!(core::ptr::addr_of!(str)), b'x' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnchr_found(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnchr(s!(core::ptr::addr_of!(str)), 5, b'e' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnchr_null(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnchr(s!(core::ptr::addr_of!(str)), 12, 0i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnchr_notfound(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnchr(s!(core::ptr::addr_of!(str)), 5, b'w' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strrchr_found(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strrchr(s!(core::ptr::addr_of!(str)), b'l' as i32) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strrchr_null(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strrchr(s!(core::ptr::addr_of!(str)), 0i32) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strrchr_notfound(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strrchr(s!(core::ptr::addr_of!(str)), b'x' as i32) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strlen(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strlen(s!(core::ptr::addr_of!(str))) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnlen(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnlen(s!(core::ptr::addr_of!(str)), 12) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strspn(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strspn(s!(core::ptr::addr_of!(str)), s!(b"ehlo\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcspn(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcspn(s!(core::ptr::addr_of!(str)), s!(b"lo\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strstr_found(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strstr(s!(core::ptr::addr_of!(str)), s!(b"world\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasestr_found(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasestr(s!(core::ptr::addr_of!(str)), s!(b"woRLD\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strstr_notfound(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strstr(s!(core::ptr::addr_of!(str)), s!(b"hi\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasestr_notfound(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasestr(s!(core::ptr::addr_of!(str)), s!(b"hi\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strstr_empty(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strstr(s!(core::ptr::addr_of!(str)), s!(b"\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasestr_empty(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasestr(s!(core::ptr::addr_of!(str)), s!(b"\0")) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnstr_found1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnstr(s!(b"\0"), s!(b"\0"), 0) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnstr_found2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnstr(s!(core::ptr::addr_of!(str)), s!(b"hello\0"), 5) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnstr_found3(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnstr(s!(core::ptr::addr_of!(str)), s!(b"hello\0"), 6) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnstr_notfound1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnstr(s!(core::ptr::addr_of!(str)), s!(b"hi\0"), 10) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnstr_notfound2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnstr(s!(core::ptr::addr_of!(str)), s!(b"hello\0"), 4) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnstr_notfound3(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnstr(s!(b"\0"), s!(b"a\0"), 0) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnstr_empty(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnstr(s!(core::ptr::addr_of!(str)), s!(b"\0"), 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasestr_found1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasestr(s!(b"\0"), s!(b"\0"), 0) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasestr_found2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasestr(s!(core::ptr::addr_of!(str)), s!(b"heLLO\0"), 5) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasestr_found3(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasestr(s!(core::ptr::addr_of!(str)), s!(b"heLLO\0"), 6) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasestr_notfound1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasestr(s!(core::ptr::addr_of!(str)), s!(b"hi\0"), 10) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasestr_notfound2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasestr(s!(core::ptr::addr_of!(str)), s!(b"hello\0"), 4) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasestr_notfound3(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasestr(s!(b"\0"), s!(b"a\0"), 0) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasestr_empty(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasestr(s!(core::ptr::addr_of!(str)), s!(b"\0"), 1) }
}

bpf_object!("GPL");
