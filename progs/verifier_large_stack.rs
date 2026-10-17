// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]

// Translation of tools/testing/selftests/bpf/progs/verifier_large_stack.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_large_stack` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: single_frame_2048 single_frame_2048_no_large_stack frame_512_leaf frame_512_depth_2 frame_512_depth_3 frame_512_depth_4 four_frames_of_512 five_frames_of_512 frame_1536_leaf uneven_frames_fit uneven_frames_exceed frame_2048_with_may_goto var_off_write_to_2048 var_off_write_to_2056 priv_stack_frame_2048 private_stack_two_frames tail_call_from_large_frame clone_redirect_keeps_512 redirect_keeps_2048 global_frame_1536 global_subprog_fits global_subprog_exceeds loop_cb_1536 loop_callback_fits loop_callback_exceeds

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    single_frame_2048:
        __description("single frame of 2048 bytes"),
        __load_if_large_stack,
        __success,
        __success_unpriv,
        __retval("42");
    single_frame_2048_no_large_stack:
        __description("single frame of 2048 bytes without large stack support"),
        __load_if_no_large_stack,
        __failure,
        __msg("invalid write to stack R1 off=-2048 size=8");
    four_frames_of_512:
        __description("four frames of 512 bytes fit the 2 KiB budget"),
        __load_if_large_stack,
        __success,
        __log_level("4"),
        __msg("stack depth max 2048");
    five_frames_of_512:
        __description("five frames of 512 bytes exceed the 2 KiB budget"),
        __load_if_large_stack,
        __failure,
        __msg("combined stack size of 5 calls is 2560. Too large");
    uneven_frames_fit:
        __description("512-byte frame calling a 1536-byte frame"),
        __load_if_large_stack,
        __success,
        __log_level("4"),
        __msg("stack depth max 2048");
    uneven_frames_exceed:
        __description("520-byte frame calling a 1536-byte frame"),
        __load_if_large_stack,
        __failure,
        __msg("combined stack size of 2 calls is 2064. Too large");
    frame_2048_with_may_goto:
        __description("frame of 2048 bytes with may_goto"),
        __load_if_large_stack,
        __success,
        __retval("42");
    var_off_write_to_2048:
        __description("variable offset write reaching 2048 bytes deep"),
        __load_if_large_stack,
        __success;
    var_off_write_to_2056:
        __description("variable offset write reaching 2056 bytes deep"),
        __load_if_large_stack,
        __failure,
        __msg("invalid variable-offset write to stack R2");
    private_stack_two_frames:
        __description("private stack: two frames of 2048 bytes"),
        __load_if_large_stack,
        __arch_x86_64,
        __arch_arm64,
        __success,
        __log_level("4"),
        __msg("stack depth max 2048"),
        __msg("subprog 0 (private_stack_two_frames) main {{.*}} stack 2048"),
        __msg("subprog 1 (priv_stack_frame_2048) static {{.*}} stack 2048");
    tail_call_from_large_frame:
        __description("tail call from a 1 KiB frame"),
        __load_if_large_stack,
        __success;
    clone_redirect_keeps_512:
        __description("1 KiB frame with bpf_clone_redirect keeps the 512-byte budget"),
        __load_if_large_stack,
        __failure,
        __msg("invalid write to stack R1 off=-1024 size=8");
    redirect_keeps_2048:
        __description("1 KiB frame with bpf_redirect keeps the 2 KiB budget"),
        __load_if_large_stack,
        __success;
    global_subprog_fits:
        __description("512-byte frame calling a 1536-byte global subprog"),
        __load_if_large_stack,
        __success,
        __log_level("4"),
        __msg("stack depth max 2048");
    global_subprog_exceeds:
        __description("520-byte frame calling a 1536-byte global subprog"),
        __load_if_large_stack,
        __failure,
        __msg("combined stack size of 2 calls is 2064. Too large");
    loop_callback_fits:
        __description("512-byte frame with a 1536-byte bpf_loop callback"),
        __load_if_large_stack,
        __success,
        __log_level("4"),
        __msg("stack depth max 2048");
    loop_callback_exceeds:
        __description("520-byte frame with a 1536-byte bpf_loop callback"),
        __load_if_large_stack,
        __failure,
        __msg("combined stack size of 2 calls is 2064. Too large");
}

bpf_map! {
    jmp_table {
        r#type: *const [i32; 3],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: single_frame_2048
extern "C" fn single_frame_2048() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -2048;",
            "r0 = 42;",
            "*(u64*)(r1 + 0) = r0;",
            "r0 = *(u64*)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: single_frame_2048_no_large_stack
extern "C" fn single_frame_2048_no_large_stack() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -2048;",
            "r0 = 42;",
            "*(u64*)(r1 + 0) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: frame_512_leaf
extern "C" fn frame_512_leaf() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 512) = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: frame_512_depth_2
extern "C" fn frame_512_depth_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 2;",
            "*(u64 *)(r10 - 512) = r1;",
            "call {frame_512_leaf};",
            "exit;",
            frame_512_leaf = sym frame_512_leaf,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: frame_512_depth_3
extern "C" fn frame_512_depth_3() {
    unsafe {
        core::arch::asm!(
            "r1 = 3;",
            "*(u64 *)(r10 - 512) = r1;",
            "call {frame_512_depth_2};",
            "exit;",
            frame_512_depth_2 = sym frame_512_depth_2,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: frame_512_depth_4
extern "C" fn frame_512_depth_4() {
    unsafe {
        core::arch::asm!(
            "r1 = 4;",
            "*(u64 *)(r10 - 512) = r1;",
            "call {frame_512_depth_3};",
            "exit;",
            frame_512_depth_3 = sym frame_512_depth_3,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: four_frames_of_512
extern "C" fn four_frames_of_512() {
    unsafe {
        core::arch::asm!(
            "call {frame_512_depth_4};",
            "r0 = 0;",
            "exit;",
            frame_512_depth_4 = sym frame_512_depth_4,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: five_frames_of_512
extern "C" fn five_frames_of_512() {
    unsafe {
        core::arch::asm!(
            "r1 = 5;",
            "*(u64 *)(r10 - 512) = r1;",
            "call {frame_512_depth_4};",
            "r0 = 0;",
            "exit;",
            frame_512_depth_4 = sym frame_512_depth_4,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: frame_1536_leaf
extern "C" fn frame_1536_leaf() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 1536) = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: uneven_frames_fit
extern "C" fn uneven_frames_fit() {
    unsafe {
        core::arch::asm!(
            "r1 = 2;",
            "*(u64 *)(r10 - 512) = r1;",
            "call {frame_1536_leaf};",
            "r0 = 0;",
            "exit;",
            frame_1536_leaf = sym frame_1536_leaf,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: uneven_frames_exceed
extern "C" fn uneven_frames_exceed() {
    unsafe {
        core::arch::asm!(
            "r1 = 2;",
            "*(u64 *)(r10 - 520) = r1;",
            "call {frame_1536_leaf};",
            "r0 = 0;",
            "exit;",
            frame_1536_leaf = sym frame_1536_leaf,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: frame_2048_with_may_goto
extern "C" fn frame_2048_with_may_goto() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -2048;",
            "r0 = 42;",
            "*(u32*)(r1 + 0) = r0;",
            "may_goto l0_0;",
            "r2 = 100;",
            "l0_0:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: var_off_write_to_2048
extern "C" fn var_off_write_to_2048() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 8;",
            "r2 = r10;",
            "r2 += -2048;",
            "r2 += r0;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: var_off_write_to_2056
extern "C" fn var_off_write_to_2056() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 8;",
            "r2 = r10;",
            "r2 += -2056;",
            "r2 += r0;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: priv_stack_frame_2048
extern "C" fn priv_stack_frame_2048() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 2048) = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "kprobe"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: private_stack_two_frames
extern "C" fn private_stack_two_frames() {
    unsafe {
        core::arch::asm!(
            "r1 = 2;",
            "*(u64 *)(r10 - 2048) = r1;",
            "call {priv_stack_frame_2048};",
            "r0 = 0;",
            "exit;",
            priv_stack_frame_2048 = sym priv_stack_frame_2048,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tail_call_from_large_frame
extern "C" fn tail_call_from_large_frame() {
    unsafe {
        core::arch::asm!(
            "r2 = 42;",
            "*(u64 *)(r10 - 1024) = r2;",
            "r2 = {jmp_table} ll;",
            "r3 = 0;",
            "call 12;",
            "r0 = 0;",
            "exit;",
            jmp_table = sym jmp_table,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: clone_redirect_keeps_512
extern "C" fn clone_redirect_keeps_512() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = r10;",
            "r1 += -1024;",
            "r0 = 42;",
            "*(u64 *)(r1 + 0) = r0;",
            "r1 = r6;",
            "r2 = 1;",
            "r3 = 0;",
            "call 13;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: redirect_keeps_2048
extern "C" fn redirect_keeps_2048() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -1024;",
            "r0 = 42;",
            "*(u64 *)(r1 + 0) = r0;",
            "r1 = 1;",
            "r2 = 0;",
            "call 23;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_frame_1536
extern "C" fn global_frame_1536() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 1536) = r1;",
            "r0 = 0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_subprog_fits
extern "C" fn global_subprog_fits() {
    unsafe {
        core::arch::asm!(
            "r1 = 2;",
            "*(u64 *)(r10 - 512) = r1;",
            "call {global_frame_1536};",
            "r0 = 0;",
            "exit;",
            global_frame_1536 = sym global_frame_1536,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_subprog_exceeds
extern "C" fn global_subprog_exceeds() {
    unsafe {
        core::arch::asm!(
            "r1 = 2;",
            "*(u64 *)(r10 - 520) = r1;",
            "call {global_frame_1536};",
            "r0 = 0;",
            "exit;",
            global_frame_1536 = sym global_frame_1536,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_cb_1536
extern "C" fn loop_cb_1536() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 1536) = r1;",
            "r0 = 0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_callback_fits
extern "C" fn loop_callback_fits() {
    unsafe {
        core::arch::asm!(
            "r1 = 2;",
            "*(u64 *)(r10 - 512) = r1;",
            "r1 = 1;",
            "r2 = {loop_cb_1536};",
            "r3 = 0;",
            "r4 = 0;",
            "call 181;",
            "r0 = 0;",
            "exit;",
            loop_cb_1536 = in(reg) loop_cb_1536 as usize,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_callback_exceeds
extern "C" fn loop_callback_exceeds() {
    unsafe {
        core::arch::asm!(
            "r1 = 2;",
            "*(u64 *)(r10 - 520) = r1;",
            "r1 = 1;",
            "r2 = {loop_cb_1536};",
            "r3 = 0;",
            "r4 = 0;",
            "call 181;",
            "r0 = 0;",
            "exit;",
            loop_cb_1536 = in(reg) loop_cb_1536 as usize,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
