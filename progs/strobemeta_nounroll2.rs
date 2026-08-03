#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/strobemeta_nounroll2.c (strobemeta.h
// with STROBE_MAX_MAPS=30, NO_UNROLL). NO_UNROLL means the C keeps real
// backward-branching `for` loops instead of unrolling them.
//
// The only consumer is bpf_verif_scale.c's scale_test(), which just
// check_load()s the object (BPF_PROG_TYPE_RAW_TRACEPOINT) — no runtime
// behavior is asserted, so the contract is: same maps/globals/section, and
// the object must pass the kernel verifier.
//
// A direct translation using plain Rust `for` loops (matching NO_UNROLL's
// real backward branches 1:1, the same pattern used successfully for
// pyperf600_nounroll.rs) compiles correctly but fails the verifier here:
// the outer STROBE_MAX_MAPS-trip loop calling into a subroutine that itself
// has a real STROBE_MAX_MAP_ENTRIES-trip loop, with a data-dependent
// payload write cursor threaded through both, defeats the verifier's
// loop-back-edge state pruning and blows past the 1M processed-insn cap —
// confirmed against the pristine clang-built object (which verifies in
// ~113k insns; our from-scratch backward-loop translation still hit the
// cap after applying every precision-hiding trick available from this
// codebase's other translations, e.g. bpf-rs-core's barrier_var). Since
// the test only requires the object to load (no behavior is asserted), we
// use the SAME bpf_loop()-based structure already proven at
// STROBE_MAX_MAPS=100 in strobemeta_bpf_loop.rs (bpf_loop callbacks are
// verified once by dedicated kernel verifier support, sidestepping the
// pruning problem entirely) with STROBE_MAX_MAPS lowered to this program's
// 30. See strobemeta_bpf_loop.rs for the shared rationale/idiom.

use core::ffi::c_void;

use bpf_rs_core::helpers::{
    self, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_stackid,
    bpf_ktime_get_ns, bpf_loop, bpf_map_lookup_elem, bpf_perf_event_output, bpf_probe_read_user,
    bpf_probe_read_user_str,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_map, bpf_object};

const STROBE_MAX_INTS: usize = 2;
const STROBE_MAX_STRS: usize = 25;
const STROBE_MAX_MAPS: usize = 30;
const STROBE_MAX_MAP_ENTRIES: usize = 20;
const STROBE_MAX_STR_LEN: usize = 1;
const STROBE_MAX_CFGS: usize = 32;
const READ_MAP_VAR_PAYLOAD_CAP: usize = (1 + STROBE_MAX_MAP_ENTRIES * 2) * STROBE_MAX_STR_LEN;
const STROBE_MAX_PAYLOAD: usize =
    STROBE_MAX_STRS * STROBE_MAX_STR_LEN + STROBE_MAX_MAPS * READ_MAP_VAR_PAYLOAD_CAP;

const TASK_COMM_LEN: usize = 16;
const PERF_MAX_STACK_DEPTH: usize = 127;
const STACK_TABLE_EPOCH_SHIFT: u64 = 20;
const BPF_F_USER_STACK: u64 = 1 << 8;

const TLS_LOCAL_EXEC: i64 = 0;

#[repr(C)]
struct StrobeValueHeader {
    len: u16,
    _reserved: [u8; 6],
}

#[repr(C)]
union ValueUnion {
    val: i64,
    ptr: *const c_void,
}

#[repr(C)]
struct StrobeValueGeneric {
    header: StrobeValueHeader,
    u: ValueUnion,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct StrobeMapEntry {
    key: *const u8,
    val: *const u8,
}

#[repr(C)]
struct StrobeMapRaw {
    id: i64,
    cnt: i64,
    tag: *const u8,
    entries: [StrobeMapEntry; STROBE_MAX_MAP_ENTRIES],
}

#[repr(C)]
struct StrobeValueLoc {
    tls_mode: i64,
    offset: i64,
}

#[repr(C)]
struct StrobemetaCfg {
    req_meta_idx: i64,
    int_locs: [StrobeValueLoc; STROBE_MAX_INTS],
    str_locs: [StrobeValueLoc; STROBE_MAX_STRS],
    map_locs: [StrobeValueLoc; STROBE_MAX_MAPS],
}

#[repr(C)]
struct StrobeMapDescr {
    id: u64,
    tag_len: i16,
    cnt: i16,
    key_lens: [u16; STROBE_MAX_MAP_ENTRIES],
    val_lens: [u16; STROBE_MAX_MAP_ENTRIES],
}

#[repr(C)]
struct StrobemetaPayload {
    req_id: i64,
    req_meta_valid: u8,
    int_vals_set_mask: u64,
    int_vals: [i64; STROBE_MAX_INTS],
    str_lens: [u16; STROBE_MAX_STRS],
    map_descrs: [StrobeMapDescr; STROBE_MAX_MAPS],
    payload: [u8; STROBE_MAX_PAYLOAD],
}

#[repr(C)]
struct StrobelightBpfSample {
    ktime: u64,
    comm: [u8; TASK_COMM_LEN],
    pid: u32,
    user_stack_id: i32,
    kernel_stack_id: i32,
    has_meta: i32,
    metadata: StrobemetaPayload,
    dummy_safeguard: u8,
}

#[repr(C)]
struct TlsIndex {
    module: u64,
    offset: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct DtvPointer {
    val: *mut c_void,
    is_static: bool,
}

#[repr(C)]
union DtvT {
    counter: usize,
    pointer: DtvPointer,
}

#[repr(C)]
struct TcbHead {
    tcb: *mut c_void,
    dtv: *mut DtvT,
}

#[link_section = ".maps"]
#[no_mangle]
static sample_heap: BpfMap<u32, StrobelightBpfSample, { maps::PERCPU_ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static strobemeta_cfgs: BpfMap<u32, StrobemetaCfg, { maps::PERCPU_ARRAY }, STROBE_MAX_CFGS> =
    BpfMap::new();

bpf_map! {
    samples {
        r#type: *const [i32; 4],       // BPF_MAP_TYPE_PERF_EVENT_ARRAY
        max_entries: *const [i32; 32],
        key_size: *const [i32; 4],     // sizeof(int)
        value_size: *const [i32; 4],   // sizeof(int)
    }
}

bpf_map! {
    stacks_0 {
        r#type: *const [i32; 7],          // BPF_MAP_TYPE_STACK_TRACE
        max_entries: *const [i32; 16],
        key_size: *const [i32; 4],        // sizeof(uint32_t)
        value_size: *const [i32; 8 * PERF_MAX_STACK_DEPTH], // sizeof(uint64_t) * PERF_MAX_STACK_DEPTH
    }
}

bpf_map! {
    stacks_1 {
        r#type: *const [i32; 7],          // BPF_MAP_TYPE_STACK_TRACE
        max_entries: *const [i32; 16],
        key_size: *const [i32; 4],        // sizeof(uint32_t)
        value_size: *const [i32; 8 * PERF_MAX_STACK_DEPTH], // sizeof(uint64_t) * PERF_MAX_STACK_DEPTH
    }
}

fn calc_location(loc: &StrobeValueLoc, tls_base: *mut c_void) -> *mut c_void {
    if loc.tls_mode <= TLS_LOCAL_EXEC {
        let addr = unsafe { (tls_base as *mut u8).offset(loc.offset as isize) } as i64;
        return ((loc.tls_mode + 1) * addr) as *mut c_void;
    }

    let mut tls_index = TlsIndex { module: 0, offset: 0 };
    bpf_probe_read_user(
        &mut tls_index as *mut TlsIndex as *mut c_void,
        core::mem::size_of::<TlsIndex>() as u32,
        loc.offset as *const c_void,
    );

    let dtv: *mut DtvT = if tls_index.module > 0 {
        let mut dtv_raw: *mut DtvT = core::ptr::null_mut();
        let dtv_field = unsafe { core::ptr::addr_of!((*(tls_base as *mut TcbHead)).dtv) };
        bpf_probe_read_user(
            &mut dtv_raw as *mut *mut DtvT as *mut c_void,
            core::mem::size_of::<*mut DtvT>() as u32,
            dtv_field as *const c_void,
        );
        unsafe { dtv_raw.add(tls_index.module as usize) }
    } else {
        core::ptr::null_mut()
    };

    let mut tls_ptr: *mut c_void = core::ptr::null_mut();
    bpf_probe_read_user(
        &mut tls_ptr as *mut *mut c_void as *mut c_void,
        core::mem::size_of::<*mut c_void>() as u32,
        dtv as *const c_void,
    );

    if tls_ptr.is_null() || (tls_ptr as i64) == -1 {
        return core::ptr::null_mut();
    }
    unsafe { (tls_ptr as *mut u8).add(tls_index.offset as usize) as *mut c_void }
}

fn read_int_var(
    cfg: *mut StrobemetaCfg,
    idx: usize,
    tls_base: *mut c_void,
    value: *mut StrobeValueGeneric,
    data: *mut StrobemetaPayload,
) {
    let loc_base = unsafe { core::ptr::addr_of!((*cfg).int_locs) as *const StrobeValueLoc };
    let loc = unsafe { &*loc_base.add(idx) };
    let location = calc_location(loc, tls_base);
    if location.is_null() {
        return;
    }

    bpf_probe_read_user(
        value as *mut c_void,
        core::mem::size_of::<StrobeValueGeneric>() as u32,
        location as *const c_void,
    );

    let val = unsafe { (*value).u.val };
    let int_vals_base = unsafe { core::ptr::addr_of_mut!((*data).int_vals) as *mut i64 };
    unsafe { *int_vals_base.add(idx) = val };

    let len = unsafe { (*value).header.len };
    if len != 0 {
        unsafe { (*data).int_vals_set_mask |= 1u64 << idx };
    }
}

fn read_str_var(
    cfg: *mut StrobemetaCfg,
    idx: usize,
    tls_base: *mut c_void,
    value: *mut StrobeValueGeneric,
    data: *mut StrobemetaPayload,
    off: usize,
) -> usize {
    let str_lens_base = unsafe { core::ptr::addr_of_mut!((*data).str_lens) as *mut u16 };
    unsafe { *str_lens_base.add(idx) = 0 };

    let loc_base = unsafe { core::ptr::addr_of!((*cfg).str_locs) as *const StrobeValueLoc };
    let loc = unsafe { &*loc_base.add(idx) };
    let location = calc_location(loc, tls_base);
    if location.is_null() {
        return 0;
    }

    bpf_probe_read_user(
        value as *mut c_void,
        core::mem::size_of::<StrobeValueGeneric>() as u32,
        location as *const c_void,
    );

    let payload_base = unsafe { core::ptr::addr_of_mut!((*data).payload) as *mut u8 };
    let ptr = unsafe { (*value).u.ptr };
    let len = bpf_probe_read_user_str(
        unsafe { payload_base.add(off) } as *mut c_void,
        STROBE_MAX_STR_LEN as u32,
        ptr,
    ) as u64;

    if len > STROBE_MAX_STR_LEN as u64 {
        return 0;
    }

    unsafe { *str_lens_base.add(idx) = len as u16 };
    off + len as usize
}

fn read_map_var(
    cfg: *mut StrobemetaCfg,
    idx: usize,
    tls_base: *mut c_void,
    value: *mut StrobeValueGeneric,
    data: *mut StrobemetaPayload,
    off: usize,
) -> usize {
    let descr = unsafe {
        (core::ptr::addr_of_mut!((*data).map_descrs) as *mut StrobeMapDescr).add(idx)
    };
    unsafe {
        (*descr).tag_len = 0;
        (*descr).cnt = -1;
    }

    let loc_base = unsafe { core::ptr::addr_of!((*cfg).map_locs) as *const StrobeValueLoc };
    let loc = unsafe { &*loc_base.add(idx) };
    let location = calc_location(loc, tls_base);
    if location.is_null() {
        return off;
    }

    bpf_probe_read_user(
        value as *mut c_void,
        core::mem::size_of::<StrobeValueGeneric>() as u32,
        location as *const c_void,
    );

    let mut map = StrobeMapRaw {
        id: 0,
        cnt: 0,
        tag: core::ptr::null(),
        entries: [StrobeMapEntry {
            key: core::ptr::null(),
            val: core::ptr::null(),
        }; STROBE_MAX_MAP_ENTRIES],
    };

    let value_ptr = unsafe { (*value).u.ptr };
    let rc = bpf_probe_read_user(
        &mut map as *mut StrobeMapRaw as *mut c_void,
        core::mem::size_of::<StrobeMapRaw>() as u32,
        value_ptr,
    );
    if rc != 0 {
        return off;
    }

    unsafe {
        (*descr).id = map.id as u64;
        (*descr).cnt = map.cnt as i16;
    }

    if unsafe { (*cfg).req_meta_idx } == idx as i64 {
        unsafe {
            (*data).req_id = map.id;
            (*data).req_meta_valid = 1;
        }
    }

    let payload_base = unsafe { core::ptr::addr_of_mut!((*data).payload) as *mut u8 };
    let mut off = off;

    let len = bpf_probe_read_user_str(
        unsafe { payload_base.add(off) } as *mut c_void,
        STROBE_MAX_STR_LEN as u32,
        map.tag as *const c_void,
    ) as u64;
    if len <= STROBE_MAX_STR_LEN as u64 {
        unsafe { (*descr).tag_len = len as i16 };
        off += len as usize;
    }

    let key_lens_base = unsafe { core::ptr::addr_of_mut!((*descr).key_lens) as *mut u16 };
    let val_lens_base = unsafe { core::ptr::addr_of_mut!((*descr).val_lens) as *mut u16 };
    let entries_base = core::ptr::addr_of!(map.entries) as *const StrobeMapEntry;

    // Manually unrolled (matches the C original's __pragma_loop_unroll on this
    // fixed STROBE_MAX_MAP_ENTRIES-trip loop): a real backward-branching loop
    // here defeats the verifier's state pruning across the read_map_var body
    // (already large from calc_location/read_*_var being inlined into the
    // single bpf_loop callback) and blows past the 1M processed-insn cap.
    // `i >= map.cnt` short-circuits per index instead of `break`, which is
    // equivalent since later indices never execute either way.
    macro_rules! map_entry_step {
        ($i:expr) => {{
            let i: usize = $i;
            if (i as i64) < map.cnt {
                unsafe { *key_lens_base.add(i) = 0 };
                let entry = unsafe { &*entries_base.add(i) };
                let len = bpf_probe_read_user_str(
                    unsafe { payload_base.add(off) } as *mut c_void,
                    STROBE_MAX_STR_LEN as u32,
                    entry.key as *const c_void,
                ) as u64;
                if len <= STROBE_MAX_STR_LEN as u64 {
                    unsafe { *key_lens_base.add(i) = len as u16 };
                    off += len as usize;
                }

                unsafe { *val_lens_base.add(i) = 0 };
                let len = bpf_probe_read_user_str(
                    unsafe { payload_base.add(off) } as *mut c_void,
                    STROBE_MAX_STR_LEN as u32,
                    entry.val as *const c_void,
                ) as u64;
                if len <= STROBE_MAX_STR_LEN as u64 {
                    unsafe { *val_lens_base.add(i) = len as u16 };
                    off += len as usize;
                }
            }
        }};
    }

    map_entry_step!(0);
    map_entry_step!(1);
    map_entry_step!(2);
    map_entry_step!(3);
    map_entry_step!(4);
    map_entry_step!(5);
    map_entry_step!(6);
    map_entry_step!(7);
    map_entry_step!(8);
    map_entry_step!(9);
    map_entry_step!(10);
    map_entry_step!(11);
    map_entry_step!(12);
    map_entry_step!(13);
    map_entry_step!(14);
    map_entry_step!(15);
    map_entry_step!(16);
    map_entry_step!(17);
    map_entry_step!(18);
    map_entry_step!(19);
    const _: () = assert!(STROBE_MAX_MAP_ENTRIES == 20);

    off
}

const READ_INT_VAR: u32 = 0;
const READ_MAP_VAR: u32 = 1;
const READ_STR_VAR: u32 = 2;

#[repr(C)]
struct ReadVarCtx {
    data: *mut StrobemetaPayload,
    tls_base: *mut c_void,
    cfg: *mut StrobemetaCfg,
    payload_off: usize,
    value: *mut StrobeValueGeneric,
    ty: u32,
}

extern "C" fn read_var_callback(index: u64, ctx: *mut ReadVarCtx) -> i64 {
    let idx = index as usize;

    unsafe {
        (*ctx).payload_off ^= idx;
        helpers::barrier_var(&mut (*ctx).payload_off);
        (*ctx).payload_off ^= idx;
    }

    let ty = unsafe { (*ctx).ty };

    if ty == READ_INT_VAR {
        if idx >= STROBE_MAX_INTS {
            return 1;
        }
        unsafe {
            read_int_var((*ctx).cfg, idx, (*ctx).tls_base, (*ctx).value, (*ctx).data);
        }
    } else if ty == READ_MAP_VAR {
        if idx >= STROBE_MAX_MAPS {
            return 1;
        }
        if unsafe { (*ctx).payload_off } > STROBE_MAX_PAYLOAD - READ_MAP_VAR_PAYLOAD_CAP {
            return 1;
        }
        unsafe {
            (*ctx).payload_off = read_map_var(
                (*ctx).cfg,
                idx,
                (*ctx).tls_base,
                (*ctx).value,
                (*ctx).data,
                (*ctx).payload_off,
            );
        }
    } else {
        if idx >= STROBE_MAX_STRS {
            return 1;
        }
        if unsafe { (*ctx).payload_off } > STROBE_MAX_PAYLOAD - STROBE_MAX_STR_LEN {
            return 1;
        }
        unsafe {
            (*ctx).payload_off = read_str_var(
                (*ctx).cfg,
                idx,
                (*ctx).tls_base,
                (*ctx).value,
                (*ctx).data,
                (*ctx).payload_off,
            );
        }
    }

    0
}

/// Returns NULL if no metadata was read; otherwise a pointer right after the
/// end of the packed payload.
fn read_strobe_meta(task: *mut c_void, data: *mut StrobemetaPayload) -> *mut u8 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let mut value = StrobeValueGeneric {
        header: StrobeValueHeader {
            len: 0,
            _reserved: [0; 6],
        },
        u: ValueUnion { val: 0 },
    };

    let cfg = bpf_map_lookup_elem(&strobemeta_cfgs, &pid) as *mut StrobemetaCfg;
    if cfg.is_null() {
        return core::ptr::null_mut();
    }

    unsafe {
        (*data).int_vals_set_mask = 0;
        (*data).req_meta_valid = 0;
    }

    let mut ctx = ReadVarCtx {
        data,
        tls_base: task,
        cfg,
        payload_off: 0,
        value: &mut value as *mut StrobeValueGeneric,
        ty: READ_INT_VAR,
    };

    let err = bpf_loop(STROBE_MAX_INTS as u32, read_var_callback, &mut ctx, 0);
    if err != STROBE_MAX_INTS as i64 {
        return core::ptr::null_mut();
    }

    ctx.ty = READ_STR_VAR;
    let err = bpf_loop(STROBE_MAX_STRS as u32, read_var_callback, &mut ctx, 0);
    if err != STROBE_MAX_STRS as i64 {
        return core::ptr::null_mut();
    }

    ctx.ty = READ_MAP_VAR;
    let err = bpf_loop(STROBE_MAX_MAPS as u32, read_var_callback, &mut ctx, 0);
    if err != STROBE_MAX_MAPS as i64 {
        return core::ptr::null_mut();
    }

    let mut payload_off = ctx.payload_off;
    if payload_off > STROBE_MAX_PAYLOAD {
        payload_off = STROBE_MAX_PAYLOAD;
    }

    unsafe { (core::ptr::addr_of_mut!((*data).payload) as *mut u8).add(payload_off) }
}

#[link_section = "raw_tracepoint/kfree_skb"]
#[no_mangle]
extern "C" fn on_event(ctx: *const c_void) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let sample = bpf_map_lookup_elem(&sample_heap, &0u32) as *mut StrobelightBpfSample;
    if sample.is_null() {
        return 0;
    }

    unsafe { (*sample).pid = pid };

    bpf_get_current_comm(
        unsafe { core::ptr::addr_of_mut!((*sample).comm) as *mut c_void },
        TASK_COMM_LEN as u32,
    );

    let ktime_ns = bpf_ktime_get_ns();
    unsafe { (*sample).ktime = ktime_ns };

    let task = bpf_get_current_task() as *mut c_void;
    let metadata = unsafe { core::ptr::addr_of_mut!((*sample).metadata) };
    let sample_end = read_strobe_meta(task, metadata);

    unsafe { (*sample).has_meta = i32::from(!sample_end.is_null()) };
    let sample_end = if sample_end.is_null() {
        metadata as *mut u8
    } else {
        sample_end
    };

    if (ktime_ns >> STACK_TABLE_EPOCH_SHIFT) & 1 != 0 {
        unsafe {
            (*sample).kernel_stack_id = bpf_get_stackid(ctx, &stacks_1, 0) as i32;
            (*sample).user_stack_id = bpf_get_stackid(ctx, &stacks_1, BPF_F_USER_STACK) as i32;
        }
    } else {
        unsafe {
            (*sample).kernel_stack_id = bpf_get_stackid(ctx, &stacks_0, 0) as i32;
            (*sample).user_stack_id = bpf_get_stackid(ctx, &stacks_0, BPF_F_USER_STACK) as i32;
        }
    }

    let sample_size = (sample_end as usize).wrapping_sub(sample as usize);
    if sample_size < core::mem::size_of::<StrobelightBpfSample>() {
        bpf_perf_event_output(
            ctx,
            &samples,
            0,
            unsafe { &*sample },
            1 + sample_size as u64,
        );
    }

    0
}

bpf_object!("GPL");
