#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

#[path = "common/arena.rs"]
mod arena_cast;
use arena_cast::cast_kern;
use core::{ffi::c_void, ptr::{addr_of_mut, read_volatile, write_volatile}};
use bpf_rs_core::bpf_map;
bpf_map! { arena { r#type: *const [i32; 33], map_flags: *const [i32; 1024], max_entries: *const [i32; 1], } }
#[no_mangle]
static mut stash: u64 = 0;
extern "C" {
    fn bpf_arena_alloc_pages(map: *const c_void, addr: *mut c_void, count: u32, node: i32, flags: u64) -> *mut u64;
    fn bpf_kfunc_arena_cap_test(p: *mut u64) -> u64;
    fn bpf_kfunc_arena_cap_nullable_test(p: *mut u64) -> u64;
    fn bpf_kfunc_arena_args5_test(a: *mut u64, b: *mut u64, c: *mut u64, d: *mut u64, e: *mut u64) -> u64;
}
#[inline(always)]
unsafe fn alloc_page() -> *mut u64 { bpf_arena_alloc_pages(&arena as *const _ as *const c_void, core::ptr::null_mut(), 1, -1, 0) }
#[no_mangle]
#[link_section = "syscall"]
extern "C" fn arena_arg_jit_rebase(_ctx: *const c_void) -> i32 {
    unsafe {
        write_volatile(addr_of_mut!(stash), alloc_page() as u64);
        bpf_kfunc_arena_cap_test(read_volatile(addr_of_mut!(stash)) as *mut u64);
    }
    0
}
#[no_mangle]
#[link_section = "syscall"]
extern "C" fn arena_arg_jit_nullable(_ctx: *const c_void) -> i32 {
    unsafe {
        write_volatile(addr_of_mut!(stash), alloc_page() as u64);
        bpf_kfunc_arena_cap_nullable_test(read_volatile(addr_of_mut!(stash)) as *mut u64);
    }
    0
}
#[no_mangle]
#[link_section = "syscall"]
extern "C" fn arena_arg_jit_args5(_ctx: *const c_void) -> i32 {
    unsafe {
        let val = alloc_page();
        if val.is_null() { return 1; }
        let p = cast_kern(val);
        *p = 1; *p.add(1) = 2; *p.add(2) = 4; *p.add(3) = 8; *p.add(4) = 16;
        bpf_kfunc_arena_args5_test(val, val.wrapping_add(1), val.wrapping_add(2), val.wrapping_add(3), val.wrapping_add(4));
    }
    0
}
bpf_rs_core::bpf_object!("GPL");
bpf_rs_core::test_tags! {
    arena_arg_jit_rebase: __arch_x86_64, __jited("..."), __jited("\tmovl\t%edi, %edi"), __jited("\taddq\t%r12, %rdi"), __jited("..."), __jited("\tcallq\t{{.*}}"), __arch_arm64, __jited("..."), __jited("\tadd\tx0, x28, w0, uxtw"), __jited("\t{{(bl|mov)\t.*}}"), __success;
    arena_arg_jit_nullable: __arch_x86_64, __jited("..."), __jited("\tmovl\t%edi, %edi"), __jited("\ttestl\t%edi, %edi"), __jited("\tje\tL0"), __jited("\taddq\t%r12, %rdi"), __jited("L0:\tcallq\t{{.*}}"), __arch_arm64, __jited("..."), __jited("\tmov\tw0, w0"), __jited("\tcbz\tw0, L0"), __jited("\tadd\tx0, x28, w0, uxtw"), __jited("L0:\t{{.*}}"), __success;
    arena_arg_jit_args5: __arch_x86_64, __jited("..."), __jited("\tmovl\t%edi, %edi"), __jited("\taddq\t%r12, %rdi"), __jited("\tmovl\t%esi, %esi"), __jited("\taddq\t%r12, %rsi"), __jited("\tmovl\t%edx, %edx"), __jited("\taddq\t%r12, %rdx"), __jited("\tmovl\t%ecx, %ecx"), __jited("\taddq\t%r12, %rcx"), __jited("\tmovl\t%r8d, %r8d"), __jited("\ttestl\t%r8d, %r8d"), __jited("\tje\tL0"), __jited("\taddq\t%r12, %r8"), __jited("L0:\tcallq\t{{.*}}"), __arch_arm64, __jited("..."), __jited("\tadd\tx0, x28, w0, uxtw"), __jited("\tadd\tx1, x28, w1, uxtw"), __jited("\tadd\tx2, x28, w2, uxtw"), __jited("\tadd\tx3, x28, w3, uxtw"), __jited("\tmov\tw4, w4"), __jited("\tcbz\tw4, L0"), __jited("\tadd\tx4, x28, w4, uxtw"), __jited("L0:\t{{.*}}"), __success;
}
