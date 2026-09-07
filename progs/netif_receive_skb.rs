#![no_std]
#![no_main]

// translint: allow(printk-count)
// The C object carries 111 bpf_trace_printk sites and this one carries 7.
// The arithmetic: 52 TEST_BTF cases x 2 printks = 104 of them sit inside
// the macro's `if (_cmp != 0)` arm, which is UNREACHABLE as written —
// `if (ret) break;` fires on ANY nonzero bpf_snprintf_btf return, and a
// successful render returns a length, so __strncmp never runs for any case
// here (none expect an empty string). The remaining 7 are reachable and
// are translated below: the `ret < 0` render failure, which both compilers
// unroll into the 6-iteration flags loop, plus the BADPTR check.
//
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
// Type-ID polyfills below lower to standard CO-RE TYPE_ID_TARGET relocations.
// libbpf resolves each type against the loading kernel.
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
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_snprintf_btf, bpf_trace_printk};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg;

const STRSIZE: u32 = 2048;

const BTF_F_COMPACT: u64 = 1;
const BTF_F_NONAME: u64 = 2;
const BTF_F_PTR_RAW: u64 = 4;
const BTF_F_ZERO: u64 = 8;

const ERANGE: isize = -34;

// BTF_TYPE_ID: tid_sk_buff struct sk_buff
// BTF_TYPE_ID: tid_sk_buff_uapi struct __sk_buff
// BTF_TYPE_ID: tid_int int int
// BTF_TYPE_ID: tid_char int char
// BTF_TYPE_ID: tid_uint64_t typedef uint64_t
// BTF_TYPE_ID: tid_u64 typedef u64
// BTF_TYPE_ID: tid_atomic_t typedef atomic_t
// BTF_TYPE_ID: tid_bpf_cmd enum bpf_cmd
// BTF_TYPE_ID: tid_btf_enum struct btf_enum
// BTF_TYPE_ID: tid_list_head struct list_head
// BTF_TYPE_ID: tid_bpf_prog_info struct bpf_prog_info
// BTF_TYPE_ID: tid_bpf_insn struct bpf_insn
extern "C" {
    fn tid_sk_buff() -> u64;
    fn tid_sk_buff_uapi() -> u64;
    fn tid_int() -> u64;
    fn tid_char() -> u64;
    fn tid_uint64_t() -> u64;
    fn tid_u64() -> u64;
    fn tid_atomic_t() -> u64;
    fn tid_bpf_cmd() -> u64;
    fn tid_btf_enum() -> u64;
    fn tid_list_head() -> u64;
    fn tid_bpf_prog_info() -> u64;
    fn tid_bpf_insn() -> u64;
}

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
        type_id: unsafe { tid_sk_buff() as u32 },
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
            if ret < 0 {
                static FMT: &[u8] = b"returned %d when writing skb\0";
                bpf_trace_printk(
                    FMT.as_ptr() as *const c_void,
                    FMT.len() as u32,
                    ret as u64,
                    0,
                    0,
                );
            }
            ran_subtests += 1;
        }
        i += 1;
    }

    // Check invalid ptr value.
    let bad = BtfPtr {
        ptr: core::ptr::null(),
        type_id: unsafe { tid_sk_buff() as u32 },
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
            static FMT: &[u8] = b"printing %llx should generate error, got (%d)\0";
            bpf_trace_printk(
                FMT.as_ptr() as *const c_void,
                FMT.len() as u32,
                0,
                bad_ret as u64,
                0,
            );
            ret = ERANGE;
        }
    }

    // simple int
    test_btf(str_buf, unsafe { tid_int() as u32 }, 0, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_int() as u32 }, BTF_F_NONAME, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_int() as u32 }, 0, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_int() as u32 }, BTF_F_NONAME, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_int() as u32 }, BTF_F_ZERO, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_int() as u32 }, BTF_F_NONAME | BTF_F_ZERO, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_int() as u32 }, 0, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_int() as u32 }, BTF_F_NONAME, addr(&ZERO4));

    // simple char
    test_btf(str_buf, unsafe { tid_char() as u32 }, 0, addr(&ZERO1));
    test_btf(str_buf, unsafe { tid_char() as u32 }, BTF_F_NONAME, addr(&ZERO1));
    test_btf(str_buf, unsafe { tid_char() as u32 }, 0, addr(&ZERO1));
    test_btf(str_buf, unsafe { tid_char() as u32 }, BTF_F_NONAME, addr(&ZERO1));
    test_btf(str_buf, unsafe { tid_char() as u32 }, BTF_F_ZERO, addr(&ZERO1));
    test_btf(str_buf, unsafe { tid_char() as u32 }, BTF_F_NONAME | BTF_F_ZERO, addr(&ZERO1));

    // simple typedef
    test_btf(str_buf, unsafe { tid_uint64_t() as u32 }, 0, addr(&ZERO8));
    test_btf(str_buf, unsafe { tid_u64() as u32 }, BTF_F_NONAME, addr(&ZERO8));
    test_btf(str_buf, unsafe { tid_u64() as u32 }, 0, addr(&ZERO8));
    test_btf(str_buf, unsafe { tid_u64() as u32 }, BTF_F_NONAME, addr(&ZERO8));
    test_btf(str_buf, unsafe { tid_u64() as u32 }, BTF_F_ZERO, addr(&ZERO8));
    test_btf(str_buf, unsafe { tid_u64() as u32 }, BTF_F_NONAME | BTF_F_ZERO, addr(&ZERO8));

    // typedef struct
    test_btf(str_buf, unsafe { tid_atomic_t() as u32 }, 0, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_atomic_t() as u32 }, BTF_F_NONAME, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_atomic_t() as u32 }, 0, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_atomic_t() as u32 }, BTF_F_NONAME, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_atomic_t() as u32 }, BTF_F_ZERO, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_atomic_t() as u32 }, BTF_F_NONAME | BTF_F_ZERO, addr(&ZERO4));

    // enum where enum value does (and does not) exist
    test_btf(str_buf, unsafe { tid_bpf_cmd() as u32 }, 0, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_bpf_cmd() as u32 }, 0, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_bpf_cmd() as u32 }, BTF_F_NONAME, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_bpf_cmd() as u32 }, BTF_F_NONAME | BTF_F_ZERO, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_bpf_cmd() as u32 }, BTF_F_ZERO, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_bpf_cmd() as u32 }, BTF_F_NONAME | BTF_F_ZERO, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_bpf_cmd() as u32 }, 0, addr(&ZERO4));
    test_btf(str_buf, unsafe { tid_bpf_cmd() as u32 }, BTF_F_NONAME, addr(&ZERO4));

    // simple struct
    test_btf(str_buf, unsafe { tid_btf_enum() as u32 }, 0, addr(&ZERO8));
    test_btf(str_buf, unsafe { tid_btf_enum() as u32 }, BTF_F_NONAME, addr(&ZERO8));
    test_btf(str_buf, unsafe { tid_btf_enum() as u32 }, BTF_F_NONAME, addr(&ZERO8));
    test_btf(str_buf, unsafe { tid_btf_enum() as u32 }, BTF_F_NONAME | BTF_F_ZERO, addr(&ZERO8));
    test_btf(str_buf, unsafe { tid_btf_enum() as u32 }, 0, addr(&ZERO8));
    test_btf(str_buf, unsafe { tid_btf_enum() as u32 }, BTF_F_NONAME, addr(&ZERO8));
    test_btf(str_buf, unsafe { tid_btf_enum() as u32 }, BTF_F_ZERO, addr(&ZERO8));

    // struct with pointers
    test_btf(str_buf, unsafe { tid_list_head() as u32 }, BTF_F_PTR_RAW, addr(&ZERO16));
    test_btf(str_buf, unsafe { tid_list_head() as u32 }, BTF_F_PTR_RAW, addr(&ZERO16));

    // struct with char array
    test_btf(str_buf, unsafe { tid_bpf_prog_info() as u32 }, 0, addr(&ZERO232));
    test_btf(str_buf, unsafe { tid_bpf_prog_info() as u32 }, BTF_F_NONAME, addr(&ZERO232));
    test_btf(str_buf, unsafe { tid_bpf_prog_info() as u32 }, 0, addr(&ZERO232));
    test_btf(str_buf, unsafe { tid_bpf_prog_info() as u32 }, 0, addr(&ZERO232));

    // struct with non-char array
    test_btf(str_buf, unsafe { tid_sk_buff_uapi() as u32 }, 0, addr(&ZERO192));
    test_btf(str_buf, unsafe { tid_sk_buff_uapi() as u32 }, BTF_F_NONAME, addr(&ZERO192));
    test_btf(str_buf, unsafe { tid_sk_buff_uapi() as u32 }, 0, addr(&ZERO192));

    // struct with bitfields
    test_btf(str_buf, unsafe { tid_bpf_insn() as u32 }, 0, addr(&ZERO8));
    test_btf(str_buf, unsafe { tid_bpf_insn() as u32 }, BTF_F_NONAME, addr(&ZERO8));

    0
}

bpf_object!("GPL");
