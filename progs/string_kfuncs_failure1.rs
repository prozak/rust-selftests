#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

#[no_mangle]
static mut user_ptr: *mut u8 = 1 as *mut u8;

#[no_mangle]
static mut invalid_kern_ptr: *mut u8 = usize::MAX as *mut u8;

extern "C" {
    fn bpf_strcmp(s1: *const u8, s2: *const u8) -> i32;
    fn bpf_strcasecmp(s1: *const u8, s2: *const u8) -> i32;
    fn bpf_strncasecmp(s1: *const u8, s2: *const u8, len: usize) -> i32;
    fn bpf_strchr(s: *const u8, c: i8) -> i32;
    fn bpf_strchrnul(s: *const u8, c: i8) -> i32;
    fn bpf_strnchr(s: *const u8, count: usize, c: i8) -> i32;
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

/* Passing NULL to string kfuncs (treated as a userspace ptr) */

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcmp_null1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcmp(core::ptr::null(), b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcmp_null2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcmp(b"hello\0".as_ptr(), core::ptr::null()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasecmp_null1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasecmp(core::ptr::null(), b"HELLO\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasecmp_null2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasecmp(b"HELLO\0".as_ptr(), core::ptr::null()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasecmp_null1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasecmp(core::ptr::null(), b"HELLO\0".as_ptr(), 5) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasecmp_null2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasecmp(b"HELLO\0".as_ptr(), core::ptr::null(), 5) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strchr_null(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strchr(core::ptr::null(), b'a' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strchrnul_null(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strchrnul(core::ptr::null(), b'a' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnchr_null(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnchr(core::ptr::null(), 1, b'a' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strrchr_null(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strrchr(core::ptr::null(), b'a' as i32) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strlen_null(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strlen(core::ptr::null()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnlen_null(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnlen(core::ptr::null(), 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strspn_null1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strspn(core::ptr::null(), b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strspn_null2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strspn(b"hello\0".as_ptr(), core::ptr::null()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcspn_null1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcspn(core::ptr::null(), b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcspn_null2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcspn(b"hello\0".as_ptr(), core::ptr::null()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strstr_null1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strstr(core::ptr::null(), b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strstr_null2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strstr(b"hello\0".as_ptr(), core::ptr::null()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasestr_null1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasestr(core::ptr::null(), b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasestr_null2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasestr(b"hello\0".as_ptr(), core::ptr::null()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnstr_null1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnstr(core::ptr::null(), b"hello\0".as_ptr(), 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnstr_null2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnstr(b"hello\0".as_ptr(), core::ptr::null(), 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasestr_null1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasestr(core::ptr::null(), b"hello\0".as_ptr(), 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasestr_null2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasestr(b"hello\0".as_ptr(), core::ptr::null(), 1) }
}

/* Passing userspace ptr to string kfuncs */

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcmp_user_ptr1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcmp(user_ptr, b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcmp_user_ptr2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcmp(b"hello\0".as_ptr(), user_ptr) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasecmp_user_ptr1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasecmp(user_ptr, b"HELLO\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasecmp_user_ptr2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasecmp(b"HELLO\0".as_ptr(), user_ptr) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasecmp_user_ptr1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasecmp(user_ptr, b"HELLO\0".as_ptr(), 5) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasecmp_user_ptr2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasecmp(b"HELLO\0".as_ptr(), user_ptr, 5) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strchr_user_ptr(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strchr(user_ptr, b'a' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strchrnul_user_ptr(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strchrnul(user_ptr, b'a' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnchr_user_ptr(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnchr(user_ptr, 1, b'a' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strrchr_user_ptr(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strrchr(user_ptr, b'a' as i32) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strlen_user_ptr(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strlen(user_ptr) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnlen_user_ptr(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnlen(user_ptr, 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strspn_user_ptr1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strspn(user_ptr, b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strspn_user_ptr2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strspn(b"hello\0".as_ptr(), user_ptr) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcspn_user_ptr1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcspn(user_ptr, b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcspn_user_ptr2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcspn(b"hello\0".as_ptr(), user_ptr) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strstr_user_ptr1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strstr(user_ptr, b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strstr_user_ptr2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strstr(b"hello\0".as_ptr(), user_ptr) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasestr_user_ptr1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasestr(user_ptr, b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasestr_user_ptr2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasestr(b"hello\0".as_ptr(), user_ptr) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnstr_user_ptr1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnstr(user_ptr, b"hello\0".as_ptr(), 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnstr_user_ptr2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnstr(b"hello\0".as_ptr(), user_ptr, 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasestr_user_ptr1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasestr(user_ptr, b"hello\0".as_ptr(), 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasestr_user_ptr2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasestr(b"hello\0".as_ptr(), user_ptr, 1) }
}

/* Passing invalid kernel ptr to string kfuncs should always return -EFAULT */

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcmp_pagefault1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcmp(invalid_kern_ptr, b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcmp_pagefault2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcmp(b"hello\0".as_ptr(), invalid_kern_ptr) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasecmp_pagefault1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasecmp(invalid_kern_ptr, b"HELLO\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasecmp_pagefault2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasecmp(b"HELLO\0".as_ptr(), invalid_kern_ptr) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasecmp_pagefault1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasecmp(invalid_kern_ptr, b"HELLO\0".as_ptr(), 5) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasecmp_pagefault2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasecmp(b"HELLO\0".as_ptr(), invalid_kern_ptr, 5) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strchr_pagefault(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strchr(invalid_kern_ptr, b'a' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strchrnul_pagefault(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strchrnul(invalid_kern_ptr, b'a' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnchr_pagefault(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnchr(invalid_kern_ptr, 1, b'a' as i8) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strrchr_pagefault(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strrchr(invalid_kern_ptr, b'a' as i32) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strlen_pagefault(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strlen(invalid_kern_ptr) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnlen_pagefault(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnlen(invalid_kern_ptr, 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strspn_pagefault1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strspn(invalid_kern_ptr, b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strspn_pagefault2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strspn(b"hello\0".as_ptr(), invalid_kern_ptr) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcspn_pagefault1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcspn(invalid_kern_ptr, b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcspn_pagefault2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcspn(b"hello\0".as_ptr(), invalid_kern_ptr) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strstr_pagefault1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strstr(invalid_kern_ptr, b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strstr_pagefault2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strstr(b"hello\0".as_ptr(), invalid_kern_ptr) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasestr_pagefault1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasestr(invalid_kern_ptr, b"hello\0".as_ptr()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strcasestr_pagefault2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strcasestr(b"hello\0".as_ptr(), invalid_kern_ptr) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnstr_pagefault1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnstr(invalid_kern_ptr, b"hello\0".as_ptr(), 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strnstr_pagefault2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strnstr(b"hello\0".as_ptr(), invalid_kern_ptr, 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasestr_pagefault1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasestr(invalid_kern_ptr, b"hello\0".as_ptr(), 1) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_strncasestr_pagefault2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_strncasestr(b"hello\0".as_ptr(), invalid_kern_ptr, 1) }
}

bpf_object!("GPL");
