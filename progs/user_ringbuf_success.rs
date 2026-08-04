#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/user_ringbuf_success.c, bpf-rs-core
// idiom.
//
// `record_sample`'s C-side `static int num_calls;` function-local static is
// a LOCAL-bind symbol in the clang object (not part of the keep-list), so it
// becomes an ordinary private Rust static here instead of a `#[no_mangle]`
// global.

use core::ffi::c_void;

use bpf_rs_core::helpers::{
    bpf_dynptr_data, bpf_dynptr_read, bpf_get_current_pid_tgid, bpf_loop, bpf_ringbuf_discard,
    bpf_ringbuf_reserve, bpf_ringbuf_submit, bpf_user_ringbuf_drain, sync_fetch_and_add_u32,
};
use bpf_rs_core::{bpf_map, bpf_object};

bpf_map! {
    user_ringbuf {
        r#type: *const [i32; 31], // BPF_MAP_TYPE_USER_RINGBUF
    }
}

bpf_map! {
    kernel_ringbuf {
        r#type: *const [i32; 27], // BPF_MAP_TYPE_RINGBUF
    }
}

/* inputs */
#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut err: i32 = 0;
#[no_mangle]
static mut val: i32 = 0;

#[no_mangle]
static mut read: i32 = 0;

/* Counter used for end-to-end protocol test */
#[no_mangle]
static mut kern_mutated: u64 = 0;
#[no_mangle]
static mut user_mutated: u64 = 0;
#[no_mangle]
static mut expected_user_mutated: u64 = 0;

const TEST_OP_64: i32 = 4;
const TEST_OP_32: i32 = 2;

const TEST_MSG_OP_INC64: u32 = 0;
const TEST_MSG_OP_INC32: u32 = 1;
const TEST_MSG_OP_MUL64: u32 = 2;
const TEST_MSG_OP_MUL32: u32 = 3;
const TEST_MSG_OP_NUM_OPS: u32 = 4;

#[repr(C)]
union TestMsgOperand {
    operand_64: i64,
    operand_32: i32,
}

#[repr(C)]
struct TestMsg {
    msg_op: u32,
    operand: TestMsgOperand,
}

#[repr(C)]
struct Sample {
    pid: i32,
    seq: i32,
    value: i64,
    comm: [u8; 16],
}

fn is_test_process() -> bool {
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    cur_pid == unsafe { pid }
}

static mut RECORD_SAMPLE_NUM_CALLS: i32 = 0;

extern "C" fn record_sample(dynptr: *mut c_void, _context: *mut c_void) -> i64 {
    let n = unsafe { RECORD_SAMPLE_NUM_CALLS };
    unsafe { RECORD_SAMPLE_NUM_CALLS = n.wrapping_add(1) };

    if n % 2 == 0 {
        let mut stack_sample = Sample {
            pid: 0,
            seq: 0,
            value: 0,
            comm: [0; 16],
        };
        let status = bpf_dynptr_read(
            &mut stack_sample as *mut Sample as *mut c_void,
            core::mem::size_of::<Sample>() as u64,
            dynptr as *const c_void,
            0,
            0,
        );
        if status != 0 {
            unsafe { err = 1 };
            return 1;
        }
    } else {
        let sample = bpf_dynptr_data(
            dynptr as *const c_void,
            0,
            core::mem::size_of::<Sample>() as u64,
        );
        if sample.is_null() {
            unsafe { err = 2 };
            return 1;
        }
    }

    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(read) as *mut u32, 1);
    0
}

fn handle_sample_msg(msg: *const TestMsg) {
    let msg_op = unsafe { (*msg).msg_op };
    unsafe {
        match msg_op {
            TEST_MSG_OP_INC64 => kern_mutated += (*msg).operand.operand_64 as u64,
            TEST_MSG_OP_INC32 => kern_mutated += (*msg).operand.operand_32 as u64,
            TEST_MSG_OP_MUL64 => kern_mutated *= (*msg).operand.operand_64 as u64,
            TEST_MSG_OP_MUL32 => kern_mutated *= (*msg).operand.operand_32 as u64,
            _ => err = 2,
        }
    }
}

extern "C" fn read_protocol_msg(dynptr: *mut c_void, _context: *mut c_void) -> i64 {
    let msg = bpf_dynptr_data(
        dynptr as *const c_void,
        0,
        core::mem::size_of::<TestMsg>() as u64,
    ) as *const TestMsg;
    if msg.is_null() {
        unsafe { err = 1 };
        return 0;
    }

    handle_sample_msg(msg);

    0
}

extern "C" fn publish_next_kern_msg(index: u64, _context: *mut c_void) -> i64 {
    let operand_64: i32 = TEST_OP_64;
    let operand_32: i32 = TEST_OP_32;

    let msg =
        bpf_ringbuf_reserve(&kernel_ringbuf, core::mem::size_of::<TestMsg>() as u64, 0) as *mut TestMsg;
    if msg.is_null() {
        unsafe { err = 4 };
        return 1;
    }

    match (index as u32) % TEST_MSG_OP_NUM_OPS {
        TEST_MSG_OP_INC64 => unsafe {
            (*msg).operand.operand_64 = operand_64 as i64;
            (*msg).msg_op = TEST_MSG_OP_INC64;
            expected_user_mutated += operand_64 as u64;
        },
        TEST_MSG_OP_INC32 => unsafe {
            (*msg).operand.operand_32 = operand_32;
            (*msg).msg_op = TEST_MSG_OP_INC32;
            expected_user_mutated += operand_32 as u64;
        },
        TEST_MSG_OP_MUL64 => unsafe {
            (*msg).operand.operand_64 = operand_64 as i64;
            (*msg).msg_op = TEST_MSG_OP_MUL64;
            expected_user_mutated *= operand_64 as u64;
        },
        TEST_MSG_OP_MUL32 => unsafe {
            (*msg).operand.operand_32 = operand_32;
            (*msg).msg_op = TEST_MSG_OP_MUL32;
            expected_user_mutated *= operand_32 as u64;
        },
        _ => {
            bpf_ringbuf_discard(msg as *mut c_void, 0);
            unsafe { err = 5 };
            return 1;
        }
    }

    bpf_ringbuf_submit(msg as *mut c_void, 0);

    0
}

fn publish_kern_messages() {
    if unsafe { expected_user_mutated != user_mutated } {
        unsafe { err = 3 };
        return;
    }

    bpf_loop(8, publish_next_kern_msg, core::ptr::null_mut(), 0);
}

#[link_section = "fentry/__x64_sys_prctl"]
#[no_mangle]
extern "C" fn test_user_ringbuf_protocol(_ctx: *const c_void) -> i32 {
    if !is_test_process() {
        return 0;
    }

    let status = bpf_user_ringbuf_drain(&user_ringbuf, read_protocol_msg, core::ptr::null_mut(), 0);
    if status < 0 {
        unsafe { err = 1 };
        return 0;
    }

    publish_kern_messages();

    0
}

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn test_user_ringbuf(_ctx: *const c_void) -> i32 {
    if !is_test_process() {
        return 0;
    }

    let status = bpf_user_ringbuf_drain(&user_ringbuf, record_sample, core::ptr::null_mut(), 0);
    unsafe { err = status as i32 };

    0
}

extern "C" fn do_nothing_cb(_dynptr: *mut c_void, _context: *mut c_void) -> i64 {
    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(read) as *mut u32, 1);
    0
}

#[link_section = "fentry/__x64_sys_prlimit64"]
#[no_mangle]
extern "C" fn test_user_ringbuf_epoll(_ctx: *const c_void) -> i32 {
    if !is_test_process() {
        return 0;
    }

    let num_samples = bpf_user_ringbuf_drain(&user_ringbuf, do_nothing_cb, core::ptr::null_mut(), 0);
    if num_samples <= 0 {
        unsafe { err = 1 };
    }

    0
}

bpf_object!("GPL");
