#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/pyperf_global.c
// (STACK_MAX_LEN=50, #include "pyperf.h" with GLOBAL_FUNC defined -> unlike
// pyperf100/50/180's __always_inline __on_event(), here __on_event is a
// real noinline *global* (external-linkage) BPF function, called five times
// from on_event(); the pristine object's symtab shows __on_event as a
// GLOBAL FUNC in .text, distinct from the raw_tracepoint/kfree_skb-section
// on_event().
//
// The only consumer is bpf_verif_scale.c's test_verif_scale_pyperf_global(),
// which just check_load()s the object (BPF_PROG_TYPE_RAW_TRACEPOINT) — no
// runtime behavior is asserted, so the contract is: same maps/globals/
// sections/global-function shape, and the object must pass the kernel
// verifier.

use core::ffi::c_void;

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_smp_processor_id,
    bpf_get_stackid, bpf_map_lookup_elem, bpf_map_update_elem, bpf_perf_event_output,
    bpf_probe_read_user, bpf_probe_read_user_str,
};
use bpf_rs_core::maps::{self, BpfMap};

const STACK_MAX_LEN: usize = 50;
const FUNCTION_NAME_LEN: usize = 64;
const FILE_NAME_LEN: usize = 128;
const TASK_COMM_LEN: usize = 16;
const BPF_F_USER_STACK: u64 = 1 << 8;

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

struct FrameData {
    f_back: *mut c_void,
    f_code: *mut c_void,
    co_filename: *mut c_void,
    co_name: *mut c_void,
}

// Kernel UAPI struct bpf_raw_tracepoint_args (flexible-array `args[0]`).
// __on_event is a real global BPF function (GLOBAL_FUNC), so the verifier
// checks its call from on_event() via BTF: the parameter type must match
// this exact struct name for the raw_tracepoint ctx register to be
// recognized (otherwise it demands a stack/fp pointer instead of ctx).
#[repr(C)]
struct bpf_raw_tracepoint_args {
    args: [u64; 0],
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

bpf_map! {
    perfmap {
        r#type: *const [i32; 4],      // BPF_MAP_TYPE_PERF_EVENT_ARRAY
        max_entries: *const [i32; 32],
        key_size: *const [i32; 4],    // sizeof(int)
        value_size: *const [i32; 4],  // sizeof(int)
    }
}

bpf_map! {
    stackmap {
        r#type: *const [i32; 7],          // BPF_MAP_TYPE_STACK_TRACE
        max_entries: *const [i32; 1000],
        key_size: *const [i32; 4],        // sizeof(int)
        value_size: *const [i32; 8 * 127], // sizeof(long long) * 127
    }
}

fn get_thread_state(tls_base: *mut c_void, pid_data: *const PidData) -> *mut c_void {
    let mut key: i32 = 0;
    bpf_probe_read_user(
        &mut key as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as u32,
        unsafe { (*pid_data).tls_key_addr as *const c_void },
    );

    let mut thread_state: *mut c_void = core::ptr::null_mut();
    let offset: isize = 0x310 + (key as isize) * 0x10 + 0x08;
    let addr = unsafe { (tls_base as *mut u8).offset(offset) };
    bpf_probe_read_user(
        &mut thread_state as *mut *mut c_void as *mut c_void,
        core::mem::size_of::<*mut c_void>() as u32,
        addr as *const c_void,
    );
    thread_state
}

fn get_frame_data(
    frame_ptr: *mut c_void,
    pid_data: *const PidData,
    frame: *mut FrameData,
    symbol: *mut Symbol,
) -> bool {
    let offsets = unsafe { core::ptr::addr_of!((*pid_data).offsets) };

    bpf_probe_read_user(
        unsafe { core::ptr::addr_of_mut!((*frame).f_back) as *mut c_void },
        core::mem::size_of::<*mut c_void>() as u32,
        unsafe { (frame_ptr as *mut u8).offset((*offsets).py_frame_object_back as isize) }
            as *const c_void,
    );
    bpf_probe_read_user(
        unsafe { core::ptr::addr_of_mut!((*frame).f_code) as *mut c_void },
        core::mem::size_of::<*mut c_void>() as u32,
        unsafe { (frame_ptr as *mut u8).offset((*offsets).py_frame_object_code as isize) }
            as *const c_void,
    );

    let f_code = unsafe { (*frame).f_code };
    if f_code.is_null() {
        return false;
    }

    bpf_probe_read_user(
        unsafe { core::ptr::addr_of_mut!((*frame).co_filename) as *mut c_void },
        core::mem::size_of::<*mut c_void>() as u32,
        unsafe { (f_code as *mut u8).offset((*offsets).py_code_object_filename as isize) }
            as *const c_void,
    );
    bpf_probe_read_user(
        unsafe { core::ptr::addr_of_mut!((*frame).co_name) as *mut c_void },
        core::mem::size_of::<*mut c_void>() as u32,
        unsafe { (f_code as *mut u8).offset((*offsets).py_code_object_name as isize) }
            as *const c_void,
    );

    let co_filename = unsafe { (*frame).co_filename };
    if !co_filename.is_null() {
        bpf_probe_read_user_str(
            unsafe { core::ptr::addr_of_mut!((*symbol).file) as *mut c_void },
            FILE_NAME_LEN as u32,
            unsafe { (co_filename as *mut u8).offset((*offsets).string_data as isize) }
                as *const c_void,
        );
    }
    let co_name = unsafe { (*frame).co_name };
    if !co_name.is_null() {
        bpf_probe_read_user_str(
            unsafe { core::ptr::addr_of_mut!((*symbol).name) as *mut c_void },
            FUNCTION_NAME_LEN as u32,
            unsafe { (co_name as *mut u8).offset((*offsets).string_data as isize) }
                as *const c_void,
        );
    }
    true
}

// C: GLOBAL_FUNC -> `__noinline int __on_event(...)` with external linkage
// (no `static`), a real global BPF subprogram distinct from the section
// program. #[no_mangle] keeps the external-linkage global-FUNC symbol in
// the object's keep-list; #[inline(never)] mirrors C's __noinline.
#[no_mangle]
#[inline(never)]
extern "C" fn __on_event(ctx: *const bpf_raw_tracepoint_args) -> i32 {
    let ctx = ctx as *const c_void;
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
        unsafe { core::ptr::addr_of_mut!((*event).comm) as *mut c_void },
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
        unsafe { (*pid_data).current_state_addr as *const c_void },
    );

    let task = bpf_get_current_task() as *mut c_void;
    let tls_base = task;

    let use_tls = unsafe { (*pid_data).use_tls };
    let thread_state = if use_tls {
        get_thread_state(tls_base, pid_data)
    } else {
        thread_state_current
    };
    unsafe { (*event).thread_current = thread_state == thread_state_current };

    if use_tls {
        let mut pthread_self: u64 = 0;
        bpf_probe_read_user(
            &mut pthread_self as *mut u64 as *mut c_void,
            core::mem::size_of::<u64>() as u32,
            unsafe { (tls_base as *mut u8).offset(0x10) } as *const c_void,
        );

        let mut pthread_created: u64 = 0;
        let thread_off = unsafe { (*pid_data).offsets.py_thread_state_thread };
        bpf_probe_read_user(
            &mut pthread_created as *mut u64 as *mut c_void,
            core::mem::size_of::<u64>() as u32,
            unsafe { (thread_state as *mut u8).offset(thread_off as isize) } as *const c_void,
        );
        unsafe { (*event).pthread_match = pthread_created == pthread_self };
    } else {
        unsafe { (*event).pthread_match = true };
    }

    let pthread_match = unsafe { (*event).pthread_match };
    if pthread_match || !use_tls {
        let mut frame_ptr: *mut c_void = core::ptr::null_mut();
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

        let frame_off = unsafe { (*pid_data).offsets.py_thread_state_frame };
        bpf_probe_read_user(
            &mut frame_ptr as *mut *mut c_void as *mut c_void,
            core::mem::size_of::<*mut c_void>() as u32,
            unsafe { (thread_state as *mut u8).offset(frame_off as isize) } as *const c_void,
        );

        let symbol_counter = bpf_map_lookup_elem(&symbolmap, &sym) as *mut i32;
        if symbol_counter.is_null() {
            return 0;
        }

        let stack_base = unsafe { core::ptr::addr_of_mut!((*event).stack) as *mut i32 };

        for i in 0..STACK_MAX_LEN {
            if !frame_ptr.is_null()
                && get_frame_data(frame_ptr, pid_data, &mut frame, &mut sym)
            {
                let counter = unsafe { *symbol_counter };
                let new_symbol_id = counter.wrapping_mul(64).wrapping_add(cur_cpu);
                let mut symbol_id = bpf_map_lookup_elem(&symbolmap, &sym) as *mut i32;
                if symbol_id.is_null() {
                    bpf_map_update_elem(&symbolmap, &sym, &zero, 0);
                    symbol_id = bpf_map_lookup_elem(&symbolmap, &sym) as *mut i32;
                    if symbol_id.is_null() {
                        return 0;
                    }
                }
                if unsafe { *symbol_id } == new_symbol_id {
                    unsafe { *symbol_counter += 1 };
                }

                unsafe {
                    *stack_base.add(i) = *symbol_id;
                    (*event).stack_len = (i + 1) as i16;
                }
                frame_ptr = frame.f_back;
            }
        }

        unsafe { (*event).stack_complete = frame_ptr.is_null() };
    } else {
        unsafe { (*event).stack_complete = true };
    }

    let stats = bpf_map_lookup_elem(&statsmap, &zero) as *mut Stats;
    if !stats.is_null() {
        unsafe { (*stats).success += 1 };
    }

    unsafe { (*event).has_meta = 0 };

    let event_size = core::mem::offset_of!(Event, metadata) as u64;
    bpf_perf_event_output(ctx, &perfmap, 0, unsafe { &*event }, event_size);

    0
}

#[link_section = "raw_tracepoint/kfree_skb"]
#[no_mangle]
extern "C" fn on_event(ctx: *const bpf_raw_tracepoint_args) -> i32 {
    let mut ret = 0i32;
    ret |= __on_event(ctx);
    ret |= __on_event(ctx);
    ret |= __on_event(ctx);
    ret |= __on_event(ctx);
    ret |= __on_event(ctx);
    ret
}

bpf_object!("GPL");
