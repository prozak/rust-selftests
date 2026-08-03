#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/pyperf_subprogs.c
// (pyperf.h with STACK_MAX_LEN 50, SUBPROGS defined), bpf-rs-core idiom.
//
// SUBPROGS makes get_thread_state() and __on_event() `static __noinline` in
// the C source (real, non-inlined subprograms) instead of always_inline;
// mirrored here with #[inline(never)] so on_event's 5 calls compile to 5
// calls into one verified subprogram body, not 5x inlined copies.
//
// The only consumer is bpf_verif_scale.c's test_verif_scale_pyperf_subprogs(),
// which just check_load()s the object (BPF_PROG_TYPE_RAW_TRACEPOINT) — no
// runtime behavior is asserted, so the contract is: same maps/globals/
// section, and the object must pass the kernel verifier.

use core::ffi::c_void;

use bpf_rs_core::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_smp_processor_id,
    bpf_get_stackid, bpf_map_lookup_elem, bpf_map_update_elem, bpf_perf_event_output,
    bpf_probe_read_user, bpf_probe_read_user_str,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::bpf_object;

const STACK_MAX_LEN: usize = 50;
const FUNCTION_NAME_LEN: usize = 64;
const FILE_NAME_LEN: usize = 128;
const TASK_COMM_LEN: usize = 16;
const PERF_MAX_STACK_DEPTH: usize = 127;
const BPF_F_USER_STACK: u64 = 1 << 8;

#[derive(Clone, Copy)]
#[repr(C)]
struct OffsetConfig {
    py_thread_state_frame: i32,
    py_thread_state_thread: i32,
    py_frame_object_back: i32,
    py_frame_object_code: i32,
    py_frame_object_lineno: i32,
    py_code_object_filename: i32,
    py_code_object_name: i32,
    string_data: i32,
    string_size: i32,
}

#[repr(C)]
struct PidData {
    current_state_addr: u64,
    tls_key_addr: u64,
    offsets: OffsetConfig,
    use_tls: bool,
}

#[repr(C)]
struct Stats {
    success: u32,
}

#[repr(C)]
struct Symbol {
    name: [u8; FUNCTION_NAME_LEN],
    file: [u8; FILE_NAME_LEN],
}

#[repr(C)]
struct Event {
    pid: u32,
    tid: u32,
    comm: [u8; TASK_COMM_LEN],
    kernel_stack_id: i32,
    user_stack_id: i32,
    thread_current: bool,
    pthread_match: bool,
    stack_complete: bool,
    stack_len: i16,
    stack: [i32; STACK_MAX_LEN],
    has_meta: i32,
    metadata: i32,
    dummy_safeguard: u8,
}

#[repr(C)]
struct FrameData {
    f_back: *mut c_void,
    f_code: *mut c_void,
    co_filename: *mut c_void,
    co_name: *mut c_void,
}

#[link_section = ".maps"]
#[no_mangle]
static pidmap: BpfMap<i32, PidData, { maps::HASH }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static eventmap: BpfMap<i32, Event, { maps::HASH }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static symbolmap: BpfMap<Symbol, i32, { maps::HASH }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static statsmap: BpfMap<i32, Stats, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static perfmap: BpfMap<i32, i32, { maps::PERF_EVENT_ARRAY }, 32> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static stackmap: BpfMap<i32, [i64; PERF_MAX_STACK_DEPTH], { maps::STACK_TRACE }, 1000> =
    BpfMap::new();

#[inline(never)]
fn get_thread_state(tls_base: *mut c_void, pid_data: *const PidData) -> *mut c_void {
    let mut key: i32 = 0;
    bpf_probe_read_user(
        &mut key as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as u32,
        unsafe { (*pid_data).tls_key_addr } as *const c_void,
    );

    let mut thread_state: *mut c_void = core::ptr::null_mut();
    bpf_probe_read_user(
        &mut thread_state as *mut *mut c_void as *mut c_void,
        core::mem::size_of::<*mut c_void>() as u32,
        unsafe { (tls_base as *mut u8).offset(0x310 + (key as isize) * 0x10 + 0x08) }
            as *const c_void,
    );
    thread_state
}

fn get_frame_data(
    frame_ptr: *mut c_void,
    pid_data: *const PidData,
    frame: *mut FrameData,
    symbol: *mut Symbol,
) -> bool {
    let offsets = unsafe { (*pid_data).offsets };

    bpf_probe_read_user(
        unsafe { core::ptr::addr_of_mut!((*frame).f_back) } as *mut c_void,
        core::mem::size_of::<*mut c_void>() as u32,
        unsafe { (frame_ptr as *mut u8).offset(offsets.py_frame_object_back as isize) }
            as *const c_void,
    );
    bpf_probe_read_user(
        unsafe { core::ptr::addr_of_mut!((*frame).f_code) } as *mut c_void,
        core::mem::size_of::<*mut c_void>() as u32,
        unsafe { (frame_ptr as *mut u8).offset(offsets.py_frame_object_code as isize) }
            as *const c_void,
    );

    let f_code = unsafe { (*frame).f_code };
    if f_code.is_null() {
        return false;
    }

    bpf_probe_read_user(
        unsafe { core::ptr::addr_of_mut!((*frame).co_filename) } as *mut c_void,
        core::mem::size_of::<*mut c_void>() as u32,
        unsafe { (f_code as *mut u8).offset(offsets.py_code_object_filename as isize) }
            as *const c_void,
    );
    bpf_probe_read_user(
        unsafe { core::ptr::addr_of_mut!((*frame).co_name) } as *mut c_void,
        core::mem::size_of::<*mut c_void>() as u32,
        unsafe { (f_code as *mut u8).offset(offsets.py_code_object_name as isize) }
            as *const c_void,
    );

    let co_filename = unsafe { (*frame).co_filename };
    if !co_filename.is_null() {
        bpf_probe_read_user_str(
            unsafe { core::ptr::addr_of_mut!((*symbol).file) } as *mut c_void,
            FILE_NAME_LEN as u32,
            unsafe { (co_filename as *mut u8).offset(offsets.string_data as isize) }
                as *const c_void,
        );
    }
    let co_name = unsafe { (*frame).co_name };
    if !co_name.is_null() {
        bpf_probe_read_user_str(
            unsafe { core::ptr::addr_of_mut!((*symbol).name) } as *mut c_void,
            FUNCTION_NAME_LEN as u32,
            unsafe { (co_name as *mut u8).offset(offsets.string_data as isize) } as *const c_void,
        );
    }

    true
}

#[inline(never)]
fn on_event_once(ctx: *const c_void) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as i32;
    let pid_data = bpf_map_lookup_elem(&pidmap, &pid) as *const PidData;
    if pid_data.is_null() {
        return 0;
    }

    let zero: i32 = 0;
    let event = bpf_map_lookup_elem(&eventmap, &zero) as *mut Event;
    if event.is_null() {
        return 0;
    }

    unsafe {
        (*event).pid = pid as u32;
        (*event).tid = pid_tgid as u32;
    }

    bpf_get_current_comm(
        unsafe { core::ptr::addr_of_mut!((*event).comm) } as *mut c_void,
        TASK_COMM_LEN as u32,
    );

    unsafe {
        (*event).user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK) as i32;
        (*event).kernel_stack_id = bpf_get_stackid(ctx, &stackmap, 0) as i32;
    }

    let mut thread_state_current: *mut c_void = core::ptr::null_mut();
    bpf_probe_read_user(
        &mut thread_state_current as *mut *mut c_void as *mut c_void,
        core::mem::size_of::<*mut c_void>() as u32,
        unsafe { (*pid_data).current_state_addr } as *const c_void,
    );

    let task = bpf_get_current_task() as *mut c_void;
    let tls_base = task;

    let use_tls = unsafe { (*pid_data).use_tls };
    let thread_state = if use_tls {
        get_thread_state(tls_base, pid_data)
    } else {
        thread_state_current
    };
    unsafe {
        (*event).thread_current = thread_state == thread_state_current;
    }

    let pthread_match;
    if use_tls {
        let mut pthread_self: u64 = 0;
        bpf_probe_read_user(
            &mut pthread_self as *mut u64 as *mut c_void,
            core::mem::size_of::<u64>() as u32,
            unsafe { (tls_base as *mut u8).offset(0x10) } as *const c_void,
        );

        let mut pthread_created: u64 = 0;
        let offset = unsafe { (*pid_data).offsets.py_thread_state_thread };
        bpf_probe_read_user(
            &mut pthread_created as *mut u64 as *mut c_void,
            core::mem::size_of::<u64>() as u32,
            unsafe { (thread_state as *mut u8).offset(offset as isize) } as *const c_void,
        );
        pthread_match = pthread_created == pthread_self;
        unsafe {
            (*event).pthread_match = pthread_match;
        }
    } else {
        pthread_match = true;
        unsafe {
            (*event).pthread_match = true;
        }
    }

    if pthread_match || !use_tls {
        let offsets = unsafe { (*pid_data).offsets };
        let mut frame_ptr: *mut c_void = core::ptr::null_mut();
        bpf_probe_read_user(
            &mut frame_ptr as *mut *mut c_void as *mut c_void,
            core::mem::size_of::<*mut c_void>() as u32,
            unsafe { (thread_state as *mut u8).offset(offsets.py_thread_state_frame as isize) }
                as *const c_void,
        );

        let mut frame = FrameData {
            f_back: core::ptr::null_mut(),
            f_code: core::ptr::null_mut(),
            co_filename: core::ptr::null_mut(),
            co_name: core::ptr::null_mut(),
        };
        let mut sym = Symbol {
            name: [0; FUNCTION_NAME_LEN],
            file: [0; FILE_NAME_LEN],
        };
        let cur_cpu = bpf_get_smp_processor_id() as i32;

        let symbol_counter = bpf_map_lookup_elem(&symbolmap, &sym) as *mut i32;
        if symbol_counter.is_null() {
            return 0;
        }

        for i in 0..STACK_MAX_LEN {
            if !frame_ptr.is_null()
                && get_frame_data(
                    frame_ptr,
                    pid_data,
                    &mut frame as *mut FrameData,
                    &mut sym as *mut Symbol,
                )
            {
                let sc = unsafe { *symbol_counter };
                let new_symbol_id = sc * 64 + cur_cpu;
                let mut symbol_id = bpf_map_lookup_elem(&symbolmap, &sym) as *mut i32;
                if symbol_id.is_null() {
                    bpf_map_update_elem(&symbolmap, &sym, &zero, 0);
                    symbol_id = bpf_map_lookup_elem(&symbolmap, &sym) as *mut i32;
                    if symbol_id.is_null() {
                        return 0;
                    }
                }
                if unsafe { *symbol_id } == new_symbol_id {
                    unsafe {
                        *symbol_counter += 1;
                    }
                }
                unsafe {
                    *(core::ptr::addr_of_mut!((*event).stack) as *mut i32).add(i) = *symbol_id;
                    (*event).stack_len = (i + 1) as i16;
                }
                frame_ptr = frame.f_back;
            }
        }
        unsafe {
            (*event).stack_complete = frame_ptr.is_null();
        }
    } else {
        unsafe {
            (*event).stack_complete = true;
        }
    }

    let stats = bpf_map_lookup_elem(&statsmap, &zero) as *mut Stats;
    if !stats.is_null() {
        unsafe {
            (*stats).success += 1;
        }
    }

    unsafe {
        (*event).has_meta = 0;
    }
    bpf_perf_event_output(
        ctx,
        &perfmap,
        0,
        unsafe { &*event },
        core::mem::offset_of!(Event, metadata) as u64,
    );

    0
}

#[link_section = "raw_tracepoint/kfree_skb"]
#[no_mangle]
extern "C" fn on_event(ctx: *const c_void) -> i32 {
    let mut ret: i32 = 0;
    ret |= on_event_once(ctx);
    ret |= on_event_once(ctx);
    ret |= on_event_once(ctx);
    ret |= on_event_once(ctx);
    ret |= on_event_once(ctx);
    ret
}

bpf_object!("GPL");
