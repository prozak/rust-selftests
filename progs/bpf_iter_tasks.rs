#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_tasks.c
// (bpf-rs-core idiom).
//
// `bpf_copy_from_user_task` is a real numbered helper (BPF_FUNC id 191,
// added to bpf-rs-core/src/helpers.rs). `bpf_copy_from_user_task_str` has
// no BPF_FUNC id -- it's a KF_SLEEPABLE kfunc (kernel/bpf/helpers.c) -- so
// it's declared `extern "C"` and resolved via the pipeline's add_ksyms ksym
// relocation, per TRANSLATING.md's kfunc rule.
//
// PT_REGS_IP(regs) reuses test_sleepable_tracepoints.rs's fixed-offset
// `bpf_probe_read_kernel` idiom (the `regs` pointer returned by
// bpf_task_pt_regs is an untrusted scalar under a sleepable iter program,
// same as under tp_btf/raw_tp there) rather than a direct field
// dereference: GP_IP = 16*8, one slot past GP_DI (14*8) + orig_rax (15*8)
// in the x86_64 `struct pt_regs` GPR array
// (r15,r14,r13,r12,rbp,rbx,r11,r10,r9,r8,rax,rcx,rdx,rsi,rdi,orig_rax,rip,...).
//
// bpf_strncmp's second string arg must be a compile-time constant address
// into a read-only map value with a NUL byte somewhere in its tail
// (verifier's check_arg_const_str); each C string literal here becomes a
// `b"...\0"` byte-string with exactly one trailing NUL -- reproducing the C
// compiler's single implicit string-literal terminator, same convention
// test_attach_probe.rs's verify_sleepable_user_copy_str established.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_copy_from_user_task, bpf_probe_read_kernel, bpf_seq_printf, bpf_strncmp, bpf_task_pt_regs,
};
use btf_macros::btf;

const BPF_F_PAD_ZEROS: u64 = 1;
const GP_IP: u64 = 16 * 8;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__task {
    meta: *mut bpf_iter_meta,
    task: *mut task_struct,
}

#[btf]
struct task_struct {
    pid: i32,
    tgid: i32,
}

extern "C" {
    fn bpf_copy_from_user_task_str(
        dst: *mut c_void,
        dst_sz: u32,
        unsafe_ptr: *const c_void,
        tsk: *mut task_struct,
        flags: u64,
    ) -> i32;
}

#[no_mangle]
static mut tid: u32 = 0;
#[no_mangle]
static mut num_unknown_tid: i32 = 0;
#[no_mangle]
static mut num_known_tid: i32 = 0;
// `void *user_ptr = 0;` in C. rustc has no genuine `void` type to give a raw
// pointer as pointee; `*mut char` reaches the same BTF `PTR type_id=0` shape
// real `void *` gets (see test_attach_probe.rs's `user_ptr` for the full
// explanation) -- `char` is never read as a value, purely a pointee marker.
#[no_mangle]
static mut user_ptr: *mut char = core::ptr::null_mut();
#[no_mangle]
static mut user_ptr_long: *mut char = core::ptr::null_mut();
#[no_mangle]
static mut pid: u32 = 0;

static mut big_str1: [u8; 5000] = [0; 5000];
static mut big_str2: [u8; 5005] = [0; 5005];
static mut big_str3: [u8; 4996] = [0; 4996];

#[no_mangle]
static mut num_expected_failure_copy_from_user_task: i32 = 0;
#[no_mangle]
static mut num_expected_failure_copy_from_user_task_str: i32 = 0;
#[no_mangle]
static mut num_success_copy_from_user_task: i32 = 0;
#[no_mangle]
static mut num_success_copy_from_user_task_str: i32 = 0;

// C's dump_task declares `static char info[]` (MUTABLE -> .data) while
// dump_task_sleepable declares `static const char info[]` (-> .rodata).
// That difference is observable to the prover: a .data global becomes a
// writable map the loader exposes as skel->data->info, so it is modelled
// as a shared observable with symbolic initial contents, and reading the
// same text out of .rodata instead would compare concrete bytes against
// that symbolic array. Mirror the split rather than share one array.
#[allow(non_upper_case_globals)]
#[no_mangle]
static mut info: [u8; 16] = *b"    === END ===\0";

#[inline(always)]
fn print_end_data(seq: *mut c_void) -> i32 {
    static FMT: [u8; 4] = *b"%s\n\0";
    let params: [u64; 1] = [core::ptr::addr_of!(info) as u64];
    bpf_seq_printf(
        seq,
        FMT.as_ptr() as *const c_void,
        FMT.len() as u32,
        params.as_ptr() as *const c_void,
        core::mem::size_of_val(&params) as u32,
    );
    0
}

#[inline(always)]
fn print_end(seq: *mut c_void) -> i32 {
    static FMT: [u8; 4] = *b"%s\n\0";
    static INFO: [u8; 16] = *b"    === END ===\0";
    let params: [u64; 1] = [INFO.as_ptr() as u64];
    bpf_seq_printf(
        seq,
        FMT.as_ptr() as *const c_void,
        FMT.len() as u32,
        params.as_ptr() as *const c_void,
        core::mem::size_of_val(&params) as u32,
    );
    0
}

#[link_section = "iter/task"]
#[no_mangle]
extern "C" fn dump_task(ctx: *const bpf_iter__task) -> i32 {
    let ctx = unsafe { &*ctx };
    let task = ctx.task;
    let meta = unsafe { &*ctx.meta };
    let seq = meta.seq;

    if task.is_null() {
        return print_end_data(seq);
    }

    let task_ref = unsafe { &*task };
    let task_pid = unsafe { *task_ref.pid().as_ptr() };
    let task_tgid = unsafe { *task_ref.tgid().as_ptr() };

    if task_pid != unsafe { tid } as i32 {
        unsafe { num_unknown_tid += 1 };
    } else {
        unsafe { num_known_tid += 1 };
    }

    if meta.seq_num == 0 {
        static FMT0: [u8; 19] = *b"    tgid      gid\n\0";
        bpf_seq_printf(
            seq,
            FMT0.as_ptr() as *const c_void,
            FMT0.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    static FMT1: [u8; 9] = *b"%8d %8d\n\0";
    let params: [u64; 2] = [task_tgid as i64 as u64, task_pid as i64 as u64];
    bpf_seq_printf(
        seq,
        FMT1.as_ptr() as *const c_void,
        FMT1.len() as u32,
        params.as_ptr() as *const c_void,
        core::mem::size_of_val(&params) as u32,
    );

    0
}

#[inline(always)]
fn read_ip(regs: u64) -> u64 {
    let mut v: u64 = 0;
    bpf_probe_read_kernel(&mut v, 8, (regs + GP_IP) as *const c_void);
    v
}

#[link_section = "iter.s/task"]
#[no_mangle]
extern "C" fn dump_task_sleepable(ctx: *const bpf_iter__task) -> i32 {
    let ctx = unsafe { &*ctx };
    let task = ctx.task;
    let meta = unsafe { &*ctx.meta };
    let seq = meta.seq;

    if task.is_null() {
        return print_end(seq);
    }

    let mut task_str1: [u8; 10] = [b'a'; 10];
    let mut task_str2: [u8; 10] = [0; 10];
    let mut task_str3: [u8; 2] = [0; 2];
    let mut task_str4: [u8; 20] = [b'a'; 20];
    let mut user_data: u32 = 0;

    // Read an invalid pointer and ensure we get an error.
    let ptr: *const c_void = core::ptr::null();
    let ret = bpf_copy_from_user_task(
        &mut user_data as *mut u32 as *mut c_void,
        4,
        ptr,
        task,
        0,
    );
    if ret != 0 {
        unsafe { num_expected_failure_copy_from_user_task += 1 };
    } else {
        return print_end(seq);
    }

    // Try to read the contents of the task's instruction pointer from the
    // remote task's address space.
    let regs = bpf_task_pt_regs(task) as *mut c_void;
    if regs.is_null() {
        return print_end(seq);
    }
    let ip = read_ip(regs as u64);
    let ptr = ip as *const c_void;

    let ret = bpf_copy_from_user_task(
        &mut user_data as *mut u32 as *mut c_void,
        4,
        ptr,
        task,
        0,
    );
    if ret != 0 {
        return print_end(seq);
    }
    unsafe { num_success_copy_from_user_task += 1 };

    // Read an invalid pointer and ensure we get an error.
    let ptr: *const c_void = core::ptr::null();
    let ret = unsafe {
        bpf_copy_from_user_task_str(
            task_str1.as_mut_ptr() as *mut c_void,
            10,
            ptr,
            task,
            0,
        )
    };
    if ret >= 0 || task_str1[9] != b'a' || task_str1[0] != 0 {
        return print_end(seq);
    }

    // Read an invalid pointer and ensure we get error with pad zeros flag.
    let ptr: *const c_void = core::ptr::null();
    let ret = unsafe {
        bpf_copy_from_user_task_str(
            task_str1.as_mut_ptr() as *mut c_void,
            10,
            ptr,
            task,
            BPF_F_PAD_ZEROS,
        )
    };
    if ret >= 0 || task_str1[9] != 0 || task_str1[0] != 0 {
        return print_end(seq);
    }
    unsafe { num_expected_failure_copy_from_user_task_str += 1 };

    // Same length as the string; only need to do the task pid check once.
    let up = unsafe { user_ptr } as *const c_void;
    let ret = unsafe {
        bpf_copy_from_user_task_str(task_str2.as_mut_ptr() as *mut c_void, 10, up, task, 0)
    };
    if bpf_strncmp(
        task_str2.as_ptr() as *const c_void,
        10,
        b"test_data\0".as_ptr() as *const c_void,
    ) != 0
        || ret != 10
        || task_tgid_of(task) as u32 != unsafe { pid }
    {
        return print_end(seq);
    }

    // Shorter length than the string.
    let ret = unsafe {
        bpf_copy_from_user_task_str(task_str3.as_mut_ptr() as *mut c_void, 2, up, task, 0)
    };
    if bpf_strncmp(
        task_str3.as_ptr() as *const c_void,
        2,
        b"t\0".as_ptr() as *const c_void,
    ) != 0
        || ret != 2
    {
        return print_end(seq);
    }

    // Longer length than the string.
    let ret = unsafe {
        bpf_copy_from_user_task_str(task_str4.as_mut_ptr() as *mut c_void, 20, up, task, 0)
    };
    if bpf_strncmp(
        task_str4.as_ptr() as *const c_void,
        10,
        b"test_data\0".as_ptr() as *const c_void,
    ) != 0
        || ret != 10
        || task_str4[19] != b'a'
    {
        return print_end(seq);
    }

    // Longer length than the string with pad zeros flag.
    let ret = unsafe {
        bpf_copy_from_user_task_str(
            task_str4.as_mut_ptr() as *mut c_void,
            20,
            up,
            task,
            BPF_F_PAD_ZEROS,
        )
    };
    if bpf_strncmp(
        task_str4.as_ptr() as *const c_void,
        10,
        b"test_data\0".as_ptr() as *const c_void,
    ) != 0
        || ret != 10
        || task_str4[19] != 0
    {
        return print_end(seq);
    }

    // Longer length than the string past a page boundary.
    let big1 = core::ptr::addr_of_mut!(big_str1);
    let ret = unsafe {
        bpf_copy_from_user_task_str(big1 as *mut c_void, 5000, up, task, 0)
    };
    if bpf_strncmp(
        big1 as *const c_void,
        10,
        b"test_data\0".as_ptr() as *const c_void,
    ) != 0
        || ret != 10
    {
        return print_end(seq);
    }

    // String that crosses a page boundary.
    let up_long = unsafe { user_ptr_long } as *const c_void;
    let ret = unsafe {
        bpf_copy_from_user_task_str(big1 as *mut c_void, 5000, up_long, task, BPF_F_PAD_ZEROS)
    };
    let big1_tail = unsafe { (big1 as *const u8).add(4996) as *const c_void };
    if bpf_strncmp(big1 as *const c_void, 4, b"baba\0".as_ptr() as *const c_void) != 0
        || ret != 5000
        || bpf_strncmp(big1_tail, 4, b"bab\0".as_ptr() as *const c_void) != 0
    {
        return print_end(seq);
    }

    let base = big1 as *const u8;
    let mut i: usize = 0;
    while i < 4999 {
        let c = unsafe { *base.add(i) };
        if i % 2 == 0 {
            if c != b'b' {
                return print_end(seq);
            }
        } else if c != b'a' {
            return print_end(seq);
        }
        i += 1;
    }

    // Longer length than the string that crosses a page boundary.
    let big2 = core::ptr::addr_of_mut!(big_str2);
    let ret = unsafe {
        bpf_copy_from_user_task_str(big2 as *mut c_void, 5005, up_long, task, BPF_F_PAD_ZEROS)
    };
    let big2_tail = unsafe { (big2 as *const u8).add(4996) as *const c_void };
    if bpf_strncmp(big2 as *const c_void, 4, b"baba\0".as_ptr() as *const c_void) != 0
        || ret != 5000
        || bpf_strncmp(big2_tail, 5, b"bab\0\0".as_ptr() as *const c_void) != 0
    {
        return print_end(seq);
    }

    // Shorter length than the string that crosses a page boundary.
    let big3 = core::ptr::addr_of_mut!(big_str3);
    let ret = unsafe {
        bpf_copy_from_user_task_str(big3 as *mut c_void, 4996, up_long, task, 0)
    };
    let big3_tail = unsafe { (big3 as *const u8).add(4992) as *const c_void };
    if bpf_strncmp(big3 as *const c_void, 4, b"baba\0".as_ptr() as *const c_void) != 0
        || ret != 4996
        || bpf_strncmp(big3_tail, 4, b"bab\0".as_ptr() as *const c_void) != 0
    {
        return print_end(seq);
    }

    unsafe { num_success_copy_from_user_task_str += 1 };

    if meta.seq_num == 0 {
        static FMT2: [u8; 28] = *b"    tgid      gid     data\n\0";
        bpf_seq_printf(
            seq,
            FMT2.as_ptr() as *const c_void,
            FMT2.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    let task_ref = unsafe { &*task };
    let task_tgid = unsafe { *task_ref.tgid().as_ptr() };
    let task_pid = unsafe { *task_ref.pid().as_ptr() };
    static FMT3: [u8; 13] = *b"%8d %8d %8d\n\0";
    let params: [u64; 3] = [
        task_tgid as i64 as u64,
        task_pid as i64 as u64,
        user_data as u64,
    ];
    bpf_seq_printf(
        seq,
        FMT3.as_ptr() as *const c_void,
        FMT3.len() as u32,
        params.as_ptr() as *const c_void,
        core::mem::size_of_val(&params) as u32,
    );

    0
}

#[inline(always)]
fn task_tgid_of(task: *mut task_struct) -> i32 {
    unsafe { *(&*task).tgid().as_ptr() }
}

bpf_object!("GPL");
