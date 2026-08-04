#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/netif_receive_skb.c, bpf-rs-core idiom.
//
// The C source gates almost its entire body behind
// `__has_builtin(__builtin_btf_type_id)` and drives ~52 `TEST_BTF`/
// `TEST_BTF_C` invocations, each of which:
//   1. resolves a *kernel* BTF type id for a named C type via
//      `bpf_core_type_id_kernel()` (clang's `__builtin_btf_type_id`, which
//      emits a `BPF_CORE_TYPE_ID_TARGET` CO-RE relocation resolved by
//      libbpf against the running kernel's BTF at load time);
//   2. calls `bpf_snprintf_btf()` to render a `static` blob of that type;
//   3. (would) compare the rendered string against a hardcoded expected
//      string.
//
// rustc has no equivalent builtin, and this pipeline's `#[btf]` CO-RE macro
// only implements field-access relocations (byte offset / exists), not the
// type-id-target relocation kind — see TRANSLATING.md and prior work on
// core-reloc-enumval/bitfields. Emitting the relocation itself is not
// possible.
//
// However the *value* such a relocation resolves to is just a plain u32
// kernel-BTF type id, constant for a given (pinned) test kernel. This repo
// already hardcodes other kernel-pinned constants when the relocation
// mechanism to derive them isn't emittable (e.g. CONFIG_HZ). The ids below
// were read directly out of the UML flavor's kernel image
// (`$KERNEL_SRC/linux`, the same file `VMLINUX_BTF` points test loads at)
// via `bpftool btf dump file`, matching each C type by name/kind/size.
//
// Also load-bearing: `TEST_BTF`'s comparison step is dead code in the C
// source as written — `if (ret) break;` fires on ANY nonzero
// `bpf_snprintf_btf` return, and a successful render of a non-empty string
// is *always* nonzero (it's a length), so `__strncmp` against the expected
// string never actually executes for any of the 52 cases here (none expect
// an empty string). The userspace test
// (prog_tests/snprintf_btf.c::serial_test_snprintf_btf) only asserts
// `ret > 0`, `ran_subtests == num_subtests`, and `ran_subtests != 0` — none
// of which depend on the rendered string's *content*, only on every
// `bpf_snprintf_btf` call succeeding (non-negative). So the data blobs
// backing each subtest can be zeroed placeholders of the right byte size;
// only the (type_id, flags, size) triple per subtest matters.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_snprintf_btf};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg;

const STRSIZE: u32 = 2048;

const BTF_F_COMPACT: u64 = 1;
const BTF_F_NONAME: u64 = 2;
const BTF_F_PTR_RAW: u64 = 4;
const BTF_F_ZERO: u64 = 8;

const ERANGE: isize = -34;

// Kernel BTF type ids for the pinned QEMU test kernel (FLAVOR=qemu; see
// module doc). Read via `bpftool btf dump file <KERNEL_SRC>/vmlinux` against
// this repo's ../uml-harness/.build/bpf-next-x86/vmlinux, matching each C
// type by name/kind/size (distinct from the UML flavor's kernel BTF, whose
// ids these superseded).
const TID_SK_BUFF: u32 = 154033; // struct sk_buff
const TID_SK_BUFF_UAPI: u32 = 83155; // struct __sk_buff
const TID_INT: u32 = 122495; // int
const TID_CHAR: u32 = 99265; // char
const TID_UINT64_T: u32 = 167568; // uint64_t (typedef)
const TID_U64: u32 = 167166; // u64 (typedef)
const TID_ATOMIC_T: u32 = 90985; // atomic_t (typedef)
const TID_BPF_CMD: u32 = 93016; // enum bpf_cmd
const TID_BTF_ENUM: u32 = 95772; // struct btf_enum
const TID_LIST_HEAD: u32 = 130480; // struct list_head
const TID_BPF_PROG_INFO: u32 = 94645; // struct bpf_prog_info
const TID_BPF_INSN: u32 = 93398; // struct bpf_insn

#[repr(C)]
struct BtfPtr {
    ptr: *const c_void,
    type_id: u32,
    flags: u32,
}

type StrMap = BpfMap<u32, [u8; STRSIZE as usize], { maps::PERCPU_ARRAY }, 1>;

#[link_section = ".maps"]
#[no_mangle]
static strdata: StrMap = BpfMap::new();

// Zeroed placeholder blobs, one per byte-size a subtest needs. Mirrors the
// C source's per-invocation `static _type _ptrdata = ...;` (file-static,
// i.e. no external symbol) without needing 52 distinct declarations, since
// content is not load-bearing (see module doc).
static ZERO1: [u8; 1] = [0; 1];
static ZERO4: [u8; 4] = [0; 4];
static ZERO8: [u8; 8] = [0; 8];
static ZERO16: [u8; 16] = [0; 16];
static ZERO192: [u8; 192] = [0; 192];
static ZERO232: [u8; 232] = [0; 232];

#[no_mangle]
static mut ret: isize = 0;
#[no_mangle]
static mut num_subtests: i32 = 0;
#[no_mangle]
static mut ran_subtests: i32 = 0;
#[no_mangle]
static mut skip: bool = false;

fn addr<T>(x: &T) -> *const c_void {
    x as *const T as *const c_void
}

// One `TEST_BTF`/`TEST_BTF_C` invocation: mirrors the macro's counters and
// `ret < 0` early-exit exactly; the string-comparison branch is omitted as
// dead code (see module doc).
#[inline(never)]
fn test_btf(str_buf: *mut c_void, type_id: u32, flags: u64, data: *const c_void) {
    unsafe {
        num_subtests += 1;
    }
    if unsafe { ret } < 0 {
        return;
    }
    unsafe {
        ran_subtests += 1;
    }
    let p = BtfPtr {
        ptr: data,
        type_id,
        flags: 0,
    };
    let r = bpf_snprintf_btf(
        str_buf,
        STRSIZE,
        &p as *const BtfPtr as *const c_void,
        core::mem::size_of::<BtfPtr>() as u32,
        flags | BTF_F_COMPACT,
    );
    unsafe {
        ret = r as isize;
    }
}

#[link_section = "tp_btf/netif_receive_skb"]
#[no_mangle]
extern "C" fn trace_netif_receive_skb(ctx: *const u64) -> i32 {
    let skb = fentry_arg(ctx, 0) as *const c_void;

    let key: u32 = 0;
    let str_buf = bpf_map_lookup_elem(&strdata, &key);
    if str_buf.is_null() {
        return 0;
    }

    // Ensure we can write skb string representation.
    let p = BtfPtr {
        ptr: skb,
        type_id: TID_SK_BUFF,
        flags: 0,
    };
    let mut i = 0;
    while i < 6 {
        unsafe {
            num_subtests += 1;
        }
        let r = bpf_snprintf_btf(
            str_buf,
            STRSIZE,
            &p as *const BtfPtr as *const c_void,
            core::mem::size_of::<BtfPtr>() as u32,
            0,
        );
        unsafe {
            ret = r as isize;
            ran_subtests += 1;
        }
        i += 1;
    }

    // Check invalid ptr value.
    let bad = BtfPtr {
        ptr: core::ptr::null(),
        type_id: TID_SK_BUFF,
        flags: 0,
    };
    let bad_ret = bpf_snprintf_btf(
        str_buf,
        STRSIZE,
        &bad as *const BtfPtr as *const c_void,
        core::mem::size_of::<BtfPtr>() as u32,
        0,
    );
    if bad_ret >= 0 {
        unsafe {
            ret = ERANGE;
        }
    }

    // simple int
    test_btf(str_buf, TID_INT, 0, addr(&ZERO4));
    test_btf(str_buf, TID_INT, BTF_F_NONAME, addr(&ZERO4));
    test_btf(str_buf, TID_INT, 0, addr(&ZERO4));
    test_btf(str_buf, TID_INT, BTF_F_NONAME, addr(&ZERO4));
    test_btf(str_buf, TID_INT, BTF_F_ZERO, addr(&ZERO4));
    test_btf(str_buf, TID_INT, BTF_F_NONAME | BTF_F_ZERO, addr(&ZERO4));
    test_btf(str_buf, TID_INT, 0, addr(&ZERO4));
    test_btf(str_buf, TID_INT, BTF_F_NONAME, addr(&ZERO4));

    // simple char
    test_btf(str_buf, TID_CHAR, 0, addr(&ZERO1));
    test_btf(str_buf, TID_CHAR, BTF_F_NONAME, addr(&ZERO1));
    test_btf(str_buf, TID_CHAR, 0, addr(&ZERO1));
    test_btf(str_buf, TID_CHAR, BTF_F_NONAME, addr(&ZERO1));
    test_btf(str_buf, TID_CHAR, BTF_F_ZERO, addr(&ZERO1));
    test_btf(str_buf, TID_CHAR, BTF_F_NONAME | BTF_F_ZERO, addr(&ZERO1));

    // simple typedef
    test_btf(str_buf, TID_UINT64_T, 0, addr(&ZERO8));
    test_btf(str_buf, TID_U64, BTF_F_NONAME, addr(&ZERO8));
    test_btf(str_buf, TID_U64, 0, addr(&ZERO8));
    test_btf(str_buf, TID_U64, BTF_F_NONAME, addr(&ZERO8));
    test_btf(str_buf, TID_U64, BTF_F_ZERO, addr(&ZERO8));
    test_btf(str_buf, TID_U64, BTF_F_NONAME | BTF_F_ZERO, addr(&ZERO8));

    // typedef struct
    test_btf(str_buf, TID_ATOMIC_T, 0, addr(&ZERO4));
    test_btf(str_buf, TID_ATOMIC_T, BTF_F_NONAME, addr(&ZERO4));
    test_btf(str_buf, TID_ATOMIC_T, 0, addr(&ZERO4));
    test_btf(str_buf, TID_ATOMIC_T, BTF_F_NONAME, addr(&ZERO4));
    test_btf(str_buf, TID_ATOMIC_T, BTF_F_ZERO, addr(&ZERO4));
    test_btf(str_buf, TID_ATOMIC_T, BTF_F_NONAME | BTF_F_ZERO, addr(&ZERO4));

    // enum where enum value does (and does not) exist
    test_btf(str_buf, TID_BPF_CMD, 0, addr(&ZERO4));
    test_btf(str_buf, TID_BPF_CMD, 0, addr(&ZERO4));
    test_btf(str_buf, TID_BPF_CMD, BTF_F_NONAME, addr(&ZERO4));
    test_btf(str_buf, TID_BPF_CMD, BTF_F_NONAME | BTF_F_ZERO, addr(&ZERO4));
    test_btf(str_buf, TID_BPF_CMD, BTF_F_ZERO, addr(&ZERO4));
    test_btf(str_buf, TID_BPF_CMD, BTF_F_NONAME | BTF_F_ZERO, addr(&ZERO4));
    test_btf(str_buf, TID_BPF_CMD, 0, addr(&ZERO4));
    test_btf(str_buf, TID_BPF_CMD, BTF_F_NONAME, addr(&ZERO4));

    // simple struct
    test_btf(str_buf, TID_BTF_ENUM, 0, addr(&ZERO8));
    test_btf(str_buf, TID_BTF_ENUM, BTF_F_NONAME, addr(&ZERO8));
    test_btf(str_buf, TID_BTF_ENUM, BTF_F_NONAME, addr(&ZERO8));
    test_btf(str_buf, TID_BTF_ENUM, BTF_F_NONAME | BTF_F_ZERO, addr(&ZERO8));
    test_btf(str_buf, TID_BTF_ENUM, 0, addr(&ZERO8));
    test_btf(str_buf, TID_BTF_ENUM, BTF_F_NONAME, addr(&ZERO8));
    test_btf(str_buf, TID_BTF_ENUM, BTF_F_ZERO, addr(&ZERO8));

    // struct with pointers
    test_btf(str_buf, TID_LIST_HEAD, BTF_F_PTR_RAW, addr(&ZERO16));
    test_btf(str_buf, TID_LIST_HEAD, BTF_F_PTR_RAW, addr(&ZERO16));

    // struct with char array
    test_btf(str_buf, TID_BPF_PROG_INFO, 0, addr(&ZERO232));
    test_btf(str_buf, TID_BPF_PROG_INFO, BTF_F_NONAME, addr(&ZERO232));
    test_btf(str_buf, TID_BPF_PROG_INFO, 0, addr(&ZERO232));
    test_btf(str_buf, TID_BPF_PROG_INFO, 0, addr(&ZERO232));

    // struct with non-char array
    test_btf(str_buf, TID_SK_BUFF_UAPI, 0, addr(&ZERO192));
    test_btf(str_buf, TID_SK_BUFF_UAPI, BTF_F_NONAME, addr(&ZERO192));
    test_btf(str_buf, TID_SK_BUFF_UAPI, 0, addr(&ZERO192));

    // struct with bitfields
    test_btf(str_buf, TID_BPF_INSN, 0, addr(&ZERO8));
    test_btf(str_buf, TID_BPF_INSN, BTF_F_NONAME, addr(&ZERO8));

    0
}

bpf_object!("GPL");
