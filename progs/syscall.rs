#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
// Function-local statics keep the C source's identifiers: the equivalence
// checker pairs globals BY NAME across the two objects, so SCREAMING_CASE
// here would leave each object's copy unpaired.
#![allow(non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/syscall.c
// (bpf-rs-core idiom).
//
// Both programs hand-encode `union bpf_attr` sub-views and a raw
// `struct bpf_insn` array as plain Rust structs/arrays instead of using
// the kernel's BTF_TYPE_ENC()-style macros (those are C-preprocessor-only).
// Every struct below only carries the fields this file actually sets; the
// syscall handler zero-extends any command's real struct fields beyond
// whatever `attr_size` we pass, so a right-sized prefix struct is
// byte-compatible with the real (much larger) `union bpf_attr` as long as
// the fields we DO set land at the same offsets the real union uses. Offsets
// below are taken directly from this tree's own
// tools/include/uapi/linux/bpf.h so they always match the target kernel.
//
// `((struct bpf_map *)&outer_array_map)->id`: reading a field off a `.maps`
// global's own address (CONST_PTR_TO_MAP register) needs the same
// hand-encoded single-BPF_LDX-with-baked-offset trick as
// verifier_arena_globals2's arena_base() (see
// [[arena-base-map-ptr-field-access-needs-hand-encoded-ldx]]): normal
// pointer arithmetic before the load is verifier-rejected
// ("R_ pointer arithmetic on map_ptr prohibited"), only the single in-place
// LDX form is allowed. `struct bpf_map.id` is at byte offset 84 in this
// tree's vmlinux BTF (bits_offset 672), confirmed via
// `bpftool btf dump file <vmlinux> -j`; `struct bpf_array` (used for both
// BPF_MAP_TYPE_ARRAY and BPF_MAP_TYPE_ARRAY_OF_MAPS) embeds `struct bpf_map`
// at offset 0, so the same offset applies to bpf_attr_array/outer_array_map.
//
// outer_array_map's `__array(values, ...)` static preload
// (`.values = { [0] = &inner_map }`) is the same flexible-array-member shape
// found unfixable in timer_mim.rs/[[prog-array-static-values-init-unfixable]]
// (rustc can't diverge codegen-size from debug-type for a flex array like
// clang can), so it's translated the same way: an empty `values: [..; 0]`
// array. This doesn't affect the update_outer_map subtest's correctness —
// unlike timer_mim, this program never relies on slot 0 being
// pre-populated: it looks up outer_array_map's own kernel map id, creates a
// fresh inner map via BPF_MAP_CREATE, wires it in via BPF_MAP_UPDATE_ELEM,
// then removes it again via BPF_MAP_DELETE_ELEM, entirely through syscalls
// at runtime.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_sys_bpf, bpf_sys_close};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

// enum bpf_cmd values used below (not exported by bpf_rs_core::maps).
const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_DELETE_ELEM: u32 = 3;
const BPF_PROG_LOAD: u32 = 5;
const BPF_MAP_GET_FD_BY_ID: u32 = 14;
const BPF_BTF_LOAD: u32 = 18;

// enum bpf_map_type / enum bpf_prog_type values used below.
const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const ARRAY_OF_MAPS: usize = 12; // BPF_MAP_TYPE_ARRAY_OF_MAPS
const BPF_PROG_TYPE_XDP: u32 = 6;

// BPF_FUNC_map_lookup_elem, baked into the hand-built insns[] below.
const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;

#[repr(C)]
struct Args {
    log_buf: u64,
    log_size: u32,
    max_entries: i32,
    map_fd: i32,
    prog_fd: i32,
    btf_fd: i32,
}

/// `struct bpf_insn` (8 bytes: opcode, dst_reg:4|src_reg:4, off, imm).
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

const fn regs(dst: u8, src: u8) -> u8 {
    (dst & 0xf) | ((src & 0xf) << 4)
}

/// `union bpf_attr`'s BPF_MAP_CREATE view, up through btf_value_type_id
/// (offsets 0/4/8/12/16/20/24/28/44/48/52/56 in the real union).
#[repr(C)]
struct MapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
}

/// `union bpf_attr`'s BPF_PROG_LOAD view, up through log_buf (offsets
/// 0/4/8/16/24/28/32 in the real union).
#[repr(C)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
}

/// `union bpf_attr`'s BPF_BTF_LOAD view, up through btf_size (offsets
/// 0/8/16 in the real union).
#[repr(C)]
struct BtfLoadAttr {
    btf: u64,
    btf_log_buf: u64,
    btf_size: u32,
}

/// `struct btf_header` (tools/include/uapi/linux/btf.h).
#[repr(C)]
struct BtfHeader {
    magic: u16,
    version: u8,
    flags: u8,
    hdr_len: u32,
    type_off: u32,
    type_len: u32,
    str_off: u32,
    str_len: u32,
    layout_off: u32,
    layout_len: u32,
}

/// Mirrors the C source's local `struct btf_blob`.
#[repr(C)]
struct BtfBlob {
    hdr: BtfHeader,
    types: [u32; 8],
    str: u32,
}

/// Reused by update_outer_map for both the BPF_MAP_GET_FD_BY_ID view
/// (`map_id` at offset 0) and the small BPF_MAP_CREATE view
/// (`map_type`/`key_size`/`value_size`/`max_entries` at offsets 0/4/8/12 —
/// same offsets, so one struct covers both) and the BPF_MAP_*_ELEM view
/// (`map_fd`/`key`/`value` at offsets 0/8/16). 24 bytes covers every view's
/// fields; the buffer is the value of a real map (bpf_attr_array), so its
/// size doubles as attr_size for every bpf_sys_bpf() call below (always
/// well under the real union's size, so the kernel zero-extends the rest —
/// see the file-level comment).
#[repr(C)]
struct BpfAttrBuf {
    _cells: [u64; 3],
}

#[repr(C)]
struct IdView {
    map_id: u32,
}

#[repr(C)]
struct CreateView {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
}

#[repr(C)]
struct ElemView {
    map_fd: u32,
    key: u64,
    value: u64,
}

bpf_map! {
    inner_map {
        r#type: *const [i32; maps::ARRAY],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
        max_entries: *const [i32; 1],
    }
}

#[repr(C)]
struct outer_array_map_def {
    r#type: *const [i32; ARRAY_OF_MAPS],
    key: *const i32,
    value: *const i32,
    max_entries: *const [i32; 1],
    values: [*const inner_map; 0],
}
unsafe impl Sync for outer_array_map_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_array_map: outer_array_map_def = outer_array_map_def {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
    values: [],
};

#[link_section = ".maps"]
#[no_mangle]
static bpf_attr_array: BpfMap<i32, BpfAttrBuf, { maps::ARRAY }, 1> = BpfMap::new();

/// Single in-place `BPF_LDX | BPF_MEM | BPF_W` insn (opcode 0x61), reading
/// `struct bpf_map.id` (byte offset 84) off a CONST_PTR_TO_MAP register into
/// that same register — the only shape the verifier permits for reading a
/// `.maps` global's own kernel struct fields (any ALU op on the map_ptr
/// register first is rejected). See the file-level comment.
#[inline(always)]
unsafe fn map_id(p: *const c_void) -> u32 {
    let mut p = p;
    core::arch::asm!(
        ".byte 0x61",
        ".ifc {0}, r0", ".byte 0x00", ".endif",
        ".ifc {0}, r1", ".byte 0x11", ".endif",
        ".ifc {0}, r2", ".byte 0x22", ".endif",
        ".ifc {0}, r3", ".byte 0x33", ".endif",
        ".ifc {0}, r4", ".byte 0x44", ".endif",
        ".ifc {0}, r5", ".byte 0x55", ".endif",
        ".ifc {0}, r6", ".byte 0x66", ".endif",
        ".ifc {0}, r7", ".byte 0x77", ".endif",
        ".ifc {0}, r8", ".byte 0x88", ".endif",
        ".ifc {0}, r9", ".byte 0x99", ".endif",
        ".short 84",
        ".long 0",
        inout(reg) p,
        options(nostack, preserves_flags),
    );
    p as usize as u32
}

fn btf_load() -> i32 {
    static raw_btf: BtfBlob = BtfBlob {
        hdr: BtfHeader {
            magic: 0xeb9f, // BTF_MAGIC
            version: 1,    // BTF_VERSION
            flags: 0,
            hdr_len: 32,
            type_off: 0,
            type_len: 32, // sizeof(types)
            str_off: 32,  // offsetof(str) - offsetof(types)
            str_len: 4,   // sizeof(str)
            layout_off: 0,
            layout_len: 0,
        },
        types: [
            // [1] long: BTF_TYPE_INT_ENC(0, BTF_INT_SIGNED, 0, 64, 8)
            0, 0x0100_0000, 8, 0x0100_0040,
            // [2] unsigned long: BTF_TYPE_INT_ENC(0, 0, 0, 64, 8)
            0, 0x0100_0000, 8, 0x0000_0040,
        ],
        str: 0,
    };
    static mut btf_load_attr: BtfLoadAttr = BtfLoadAttr {
        btf: 0,
        btf_log_buf: 0,
        btf_size: 68, // sizeof(raw_btf) == sizeof(BtfBlob)
    };

    unsafe {
        btf_load_attr.btf = core::ptr::addr_of!(raw_btf) as u64;
        bpf_sys_bpf(
            BPF_BTF_LOAD,
            core::ptr::addr_of_mut!(btf_load_attr) as *mut c_void,
            core::mem::size_of::<BtfLoadAttr>() as u32,
        ) as i32
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn load_prog(ctx: *mut Args) -> i32 {
    static license: [u8; 4] = *b"GPL\0";
    static mut insns: [BpfInsn; 8] = [
        BpfInsn { code: 0x7a, regs: regs(10, 0), off: -8, imm: 0 }, // BPF_ST_MEM(DW, R10, -8, 0)
        BpfInsn { code: 0xbf, regs: regs(2, 10), off: 0, imm: 0 },  // BPF_MOV64_REG(R2, R10)
        BpfInsn { code: 0x07, regs: regs(2, 0), off: 0, imm: -8 },  // BPF_ALU64_IMM(ADD, R2, -8)
        BpfInsn { code: 0x18, regs: regs(1, 1), off: 0, imm: 0 },   // BPF_LD_MAP_FD(R1, .) [1/2], patched below
        BpfInsn { code: 0x00, regs: regs(0, 0), off: 0, imm: 0 },   // BPF_LD_MAP_FD(R1, .) [2/2]
        BpfInsn { code: 0x85, regs: regs(0, 0), off: 0, imm: BPF_FUNC_MAP_LOOKUP_ELEM }, // call
        BpfInsn { code: 0xb7, regs: regs(0, 0), off: 0, imm: 0 },   // BPF_MOV64_IMM(R0, 0)
        BpfInsn { code: 0x95, regs: regs(0, 0), off: 0, imm: 0 },   // BPF_EXIT_INSN()
    ];
    static mut map_create_attr: MapCreateAttr = MapCreateAttr {
        map_type: BPF_MAP_TYPE_HASH,
        key_size: 8,
        value_size: 8,
        max_entries: 0,
        map_flags: 0,
        inner_map_fd: 0,
        numa_node: 0,
        map_name: [0; 16],
        map_ifindex: 0,
        btf_fd: 0,
        btf_key_type_id: 1,
        btf_value_type_id: 2,
    };
    static mut map_update_attr: ElemView = ElemView { map_fd: 1, key: 0, value: 0 };
    static key: u64 = 12;
    static value: u64 = 34;
    static mut prog_load_attr: ProgLoadAttr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_XDP,
        insn_cnt: 8,
        insns: 0,
        license: 0,
        log_level: 0,
        log_size: 0,
        log_buf: 0,
    };

    let mut ret = btf_load();
    if ret <= 0 {
        return ret;
    }

    unsafe {
        (*ctx).btf_fd = ret;
        map_create_attr.max_entries = (*ctx).max_entries as u32;
        map_create_attr.btf_fd = ret as u32;

        prog_load_attr.license = core::ptr::addr_of!(license) as u64;
        prog_load_attr.insns = core::ptr::addr_of_mut!(insns) as u64;
        prog_load_attr.log_buf = (*ctx).log_buf;
        prog_load_attr.log_size = (*ctx).log_size;
        prog_load_attr.log_level = 1;

        ret = bpf_sys_bpf(
            BPF_MAP_CREATE,
            core::ptr::addr_of_mut!(map_create_attr) as *mut c_void,
            core::mem::size_of::<MapCreateAttr>() as u32,
        ) as i32;
        if ret <= 0 {
            return ret;
        }
        (*ctx).map_fd = ret;
        insns[3].imm = ret;

        map_update_attr.map_fd = ret as u32;
        map_update_attr.key = core::ptr::addr_of!(key) as u64;
        map_update_attr.value = core::ptr::addr_of!(value) as u64;
        ret = bpf_sys_bpf(
            BPF_MAP_UPDATE_ELEM,
            core::ptr::addr_of_mut!(map_update_attr) as *mut c_void,
            core::mem::size_of::<ElemView>() as u32,
        ) as i32;
        if ret < 0 {
            return ret;
        }

        ret = bpf_sys_bpf(
            BPF_PROG_LOAD,
            core::ptr::addr_of_mut!(prog_load_attr) as *mut c_void,
            core::mem::size_of::<ProgLoadAttr>() as u32,
        ) as i32;
        if ret <= 0 {
            return ret;
        }
        (*ctx).prog_fd = ret;
    }
    1
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn update_outer_map(_ctx: *const c_void) -> i32 {
    let zero: i32 = 0;
    let mut ret: i32 = 0;
    let mut outer_fd: i32 = -1;
    let mut inner_fd: i32 = -1;
    let attr_sz = core::mem::size_of::<BpfAttrBuf>() as u32;

    let attr = bpf_map_lookup_elem(&bpf_attr_array, &zero) as *mut BpfAttrBuf;
    if !attr.is_null() {
        unsafe {
            core::ptr::write_bytes(attr, 0, 1);
            (*(attr as *mut IdView)).map_id =
                map_id(core::ptr::addr_of!(outer_array_map) as *const c_void);
            outer_fd = bpf_sys_bpf(BPF_MAP_GET_FD_BY_ID, attr as *mut c_void, attr_sz) as i32;

            if outer_fd >= 0 {
                core::ptr::write_bytes(attr, 0, 1);
                let create = attr as *mut CreateView;
                (*create).map_type = BPF_MAP_TYPE_ARRAY;
                (*create).key_size = 4;
                (*create).value_size = 4;
                (*create).max_entries = 1;
                inner_fd = bpf_sys_bpf(BPF_MAP_CREATE, attr as *mut c_void, attr_sz) as i32;

                if inner_fd >= 0 {
                    core::ptr::write_bytes(attr, 0, 1);
                    let elem = attr as *mut ElemView;
                    (*elem).map_fd = outer_fd as u32;
                    (*elem).key = core::ptr::addr_of!(zero) as u64;
                    (*elem).value = core::ptr::addr_of!(inner_fd) as u64;
                    let err = bpf_sys_bpf(BPF_MAP_UPDATE_ELEM, attr as *mut c_void, attr_sz);

                    if err == 0 {
                        core::ptr::write_bytes(attr, 0, 1);
                        let elem = attr as *mut ElemView;
                        (*elem).map_fd = outer_fd as u32;
                        (*elem).key = core::ptr::addr_of!(zero) as u64;
                        let err2 =
                            bpf_sys_bpf(BPF_MAP_DELETE_ELEM, attr as *mut c_void, attr_sz);

                        if err2 == 0 {
                            ret = 1;
                        }
                    }
                }
            }
        }
    }

    if inner_fd >= 0 {
        bpf_sys_close(inner_fd as u32);
    }
    if outer_fd >= 0 {
        bpf_sys_close(outer_fd as u32);
    }
    ret
}

bpf_object!("GPL");
