#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_wakeup_source.c
// (bpf-rs-core idiom).
//
// The C original does `ws = bpf_core_cast((void *)pos - bpf_core_field_offset(
// struct wakeup_source, entry), struct wakeup_source)`, then reads every
// field as a plain `ws->field` dereference (the cast establishes a
// PTR_TO_BTF_ID|PTR_UNTRUSTED register, and the verifier rewrites those
// direct loads to fault-tolerant PROBE_MEM). `bpf_core_cast` expands to
// `bpf_rdonly_cast(ptr, bpf_core_type_id_kernel(...))`, a BPF_TYPE_ID_TARGET
// CO-RE relocation this pipeline's field_reloc pass cannot reproduce (only
// FIELD_BYTE_OFFSET/FIELD_EXISTS relocations exist here — see
// recvmsg_unix_prog.rs, tcp_ca_untrusted_btf_write.rs), and add_ksyms.py
// cannot mirror bpf_rdonly_cast's real 2-arg prototype either (it isn't a
// named FUNC entry in vmlinux BTF the way the three wakeup-source kfuncs
// below are), so any multi-arg call to it gets a bogus 0-arg proto and is
// rejected at load.
//
// Workaround: never establish PTR_TO_BTF_ID trust for `ws` at all. Instead,
// use a `#[btf] struct wakeup_source` purely to compute CO-RE-relocated
// *byte offsets* (`Field::as_ptr()` is pure pointer arithmetic — a linker
// marker call, not a memory access — so it works from any non-null,
// correctly-aligned base, trusted or not), then read every field explicitly
// through `bpf_probe_read_kernel`, exactly what `BPF_CORE_READ`/
// `bpf_core_read` already do under the hood. `pos` (a real, checked-non-null
// kernel address from the list walk) doubles as that base: offsetting
// `wakeup_source::entry`'s relocated address by `-pos` isolates the pure
// offset, matching `bpf_core_field_offset`'s null-pointer trick
// (`&((typeof(src)*)0)->field`) without ever creating a null reference.
//
// The `active`/`autosleep_enabled` fields are adjacent 1-bit bitfields
// packed into the byte immediately after `dev` (a real kernel pointer
// field) with no padding on this ABI (bits_offset 2240/2241, byte-aligned
// at byte 280 = dev's CO-RE offset + 8, confirmed via
// `bpftool btf dump file vmlinux`). `BPF_CORE_READ_BITFIELD` needs
// BYTE_SIZE/LSHIFT_U64/RSHIFT_U64 CO-RE relocs this pipeline doesn't
// implement (see core-reloc-bitfields-unfixable), so the containing byte is
// probe-read directly and the two bits extracted by hand.

use core::ffi::c_void;

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_str, bpf_ringbuf_reserve,
    bpf_ringbuf_submit,
};
use bpf_rs_core::maps;
use btf::{BtfType, Field};
use btf_macros::btf;

const MAX_LOOP_ITER: i32 = 1000;
const RB_SIZE: usize = 16384 * 4;
const WAKEUP_NAME_LEN: usize = 128;

bpf_map! {
    rb {
        r#type: *const [i32; maps::RINGBUF],
        max_entries: *const [i32; RB_SIZE],
    }
}

#[repr(C)]
struct WakeupEventT {
    active_count: u64,
    active_time_ns: i64,
    event_count: u64,
    expire_count: u64,
    last_time_ns: i64,
    max_time_ns: i64,
    prevent_sleep_time_ns: i64,
    total_time_ns: i64,
    wakeup_count: u64,
    name: [u8; WAKEUP_NAME_LEN],
}

// Opaque stand-in for `struct list_head entry`: only its address (i.e. its
// CO-RE byte offset within `wakeup_source`) is needed, never its contents.
// Same manual-BtfType shortcut as test_d_path's `path_opaque`.
#[repr(C)]
struct list_head_opaque {
    _priv: [u8; 0],
}

impl BtfType for list_head_opaque {
    type Carrier = Self;
    type View<'a, Root, Path, Mode>
        = Field<'a, Root, Self, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a;

    #[inline(always)]
    fn __btf_view<'a, Root, Path, Mode>(
        field: Field<'a, Root, Self, Path, Mode>,
    ) -> Self::View<'a, Root, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a,
    {
        field
    }
}

// Minimal local BTF view of `struct wakeup_source` (kernel/power/wakeup.c):
// only the fields this program reads. CO-RE field-byte-offset relocation
// matches these by name against the target kernel's real struct.
#[btf]
struct wakeup_source {
    entry: list_head_opaque,
    name: *const u8,
    dev: *const u8,
    total_time: i64,
    max_time: i64,
    last_time: i64,
    start_prevent_time: i64,
    prevent_sleep_time: i64,
    event_count: u64,
    active_count: u64,
    expire_count: u64,
    wakeup_count: u64,
}

#[repr(C)]
struct bpf_ws_lock {
    _priv: [u8; 0],
}

extern "C" {
    fn bpf_wakeup_sources_read_lock() -> *mut bpf_ws_lock;
    fn bpf_wakeup_sources_read_unlock(lock: *mut bpf_ws_lock);
    fn bpf_wakeup_sources_get_head() -> *mut c_void;
}

#[repr(C, align(8))]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

extern "C" {
    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32) -> i32;
    fn bpf_iter_num_next(it: *mut bpf_iter_num) -> *mut i32;
    fn bpf_iter_num_destroy(it: *mut bpf_iter_num);
}

#[inline(always)]
fn read_i64(addr: usize) -> i64 {
    let mut v: i64 = 0;
    bpf_probe_read_kernel(&mut v, 8, addr as *const c_void);
    v
}

#[inline(always)]
fn read_u64(addr: usize) -> u64 {
    let mut v: u64 = 0;
    bpf_probe_read_kernel(&mut v, 8, addr as *const c_void);
    v
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn iterate_wakeupsources(_ctx: *const c_void) -> i32 {
    let head = unsafe { bpf_wakeup_sources_get_head() } as usize;
    let mut pos = head;

    let lock = unsafe { bpf_wakeup_sources_read_lock() };
    if lock.is_null() {
        return 0;
    }

    let mut it = bpf_iter_num {
        __opaque: [0; 1],
    };
    unsafe { bpf_iter_num_new(&mut it, 0, MAX_LOOP_ITER) };

    loop {
        let t = unsafe { bpf_iter_num_next(&mut it) };
        if t.is_null() {
            break;
        }

        let mut next: usize = 0;
        let ret = bpf_probe_read_kernel(&mut next, 8, pos as *const c_void);
        if ret != 0 || next == 0 || next == head {
            break;
        }
        pos = next;

        // ws = pos - offsetof(wakeup_source, entry); isolate the pure
        // relocated offset by using `pos` itself as the CO-RE base (its
        // relocated `entry` address minus `pos` leaves only the offset),
        // matching `bpf_core_field_offset`'s null-pointer trick without a
        // null reference. `wakeup_source` is a macro-generated ZST, so
        // reinterpreting any non-null address as `&wakeup_source` never
        // touches memory by itself.
        let ws_ref: &wakeup_source = unsafe { &*(pos as *const wakeup_source) };
        let entry_offset = ws_ref.entry().as_ptr() as usize - pos;
        let ws_addr = pos - entry_offset;
        let ws_ref: &wakeup_source = unsafe { &*(ws_addr as *const wakeup_source) };

        let e = bpf_ringbuf_reserve(
            &rb,
            core::mem::size_of::<WakeupEventT>() as u64,
            0,
        ) as *mut WakeupEventT;
        if e.is_null() {
            break;
        }

        let dev_addr = ws_ref.dev().as_ptr() as usize;
        // `active`/`autosleep_enabled` immediately follow `dev` (a pointer
        // field) with no padding on this ABI — see module doc comment.
        let mut bitfield_byte: u8 = 0;
        bpf_probe_read_kernel(&mut bitfield_byte, 1, (dev_addr + 8) as *const c_void);
        let active = bitfield_byte & 0x1 != 0;
        let autosleep_enable = bitfield_byte & 0x2 != 0;

        let last_time = read_i64(ws_ref.last_time().as_ptr() as usize);
        let mut max_time = read_i64(ws_ref.max_time().as_ptr() as usize);
        let mut prevent_sleep_time = read_i64(ws_ref.prevent_sleep_time().as_ptr() as usize);
        let mut total_time = read_i64(ws_ref.total_time().as_ptr() as usize);
        let mut active_time: i64 = 0;

        if active {
            let curr_time = bpf_ktime_get_ns() as i64;
            let prevent_time = read_i64(ws_ref.start_prevent_time().as_ptr() as usize);

            if curr_time > last_time {
                active_time = curr_time - last_time;
            }

            total_time += active_time;
            if active_time > max_time {
                max_time = active_time;
            }
            if autosleep_enable && curr_time > prevent_time {
                prevent_sleep_time += curr_time - prevent_time;
            }
        }

        unsafe {
            (*e).active_count = read_u64(ws_ref.active_count().as_ptr() as usize);
            (*e).active_time_ns = active_time;
            (*e).event_count = read_u64(ws_ref.event_count().as_ptr() as usize);
            (*e).expire_count = read_u64(ws_ref.expire_count().as_ptr() as usize);
            (*e).last_time_ns = last_time;
            (*e).max_time_ns = max_time;
            (*e).prevent_sleep_time_ns = prevent_sleep_time;
            (*e).total_time_ns = total_time;
            (*e).wakeup_count = read_u64(ws_ref.wakeup_count().as_ptr() as usize);

            let name_ptr = ws_ref.name().as_ptr() as usize;
            let mut namep: usize = 0;
            bpf_probe_read_kernel(&mut namep, 8, name_ptr as *const c_void);
            if bpf_probe_read_kernel_str(
                (*e).name.as_mut_ptr() as *mut c_void,
                WAKEUP_NAME_LEN as u32,
                namep as *const c_void,
            ) < 0
            {
                (*e).name[0] = 0;
            }

            bpf_ringbuf_submit(e as *mut c_void, 0);
        }
    }

    unsafe { bpf_iter_num_destroy(&mut it) };
    unsafe { bpf_wakeup_sources_read_unlock(lock) };
    0
}

bpf_object!("GPL");
