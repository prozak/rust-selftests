#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/set_global_vars.c,
// bpf-rs-core idiom.
//
// The only consumer is prog_tests/test_veristat.c, which drives the
// `veristat -G <path>=<value>` global-var-preset machinery directly against
// this object's BTF -- there is no C skeleton consuming these types, so the
// only contract is: top-level var names/sizes match, and every dotted/
// bracketed path used by test_veristat.c resolves to a field of the right
// kind at the right nesting depth.
//
// veristat's field-path walker (adjust_var_secinfo_member in veristat.c)
// auto-flattens through a member ONLY when that member's own BTF name_off is
// empty (a truly anonymous struct/union field) -- exactly the CO-RE
// auto-flatten rule. rustc never emits a nameless composite (see
// anonymous-struct-array-member-unfixable memory), so instead of trying to
// reproduce the C source's anonymous wrapper structs, every C anonymous
// wrapper is dropped here and its members hoisted directly onto the parent
// as plain named fields -- which is exactly how the C source's own field
// paths already read (C source syntax skips anonymous members too), so the
// dotted paths below match test_veristat.c's `-G` strings unchanged.
//
// The one place real overlap matters is `union1`: the test sets
// `union1.struct3.var_u8_l/var_u8_h` and then (via the verifier's -vl2 full
// log constant-folding a load of `union1.var_u16`) expects to see the
// combined 0xaaaa. That needs a genuine Rust `union`. Nothing else here
// needs overlap, so nested "union u" in Struct2 is a plain struct instead.

use bpf_rs_core::bpf_object;
use core::ffi::c_void;
use core::ptr::{addr_of, read_volatile};

#[repr(i32)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
enum Enum {
    EA1 = 0,
    EA2 = 11,
    EA3 = 10,
}

#[repr(u64)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
enum Enumu64 {
    EB1 = 0,
    EB2 = 12,
}

#[repr(i64)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
enum Enums64 {
    EC1 = 0,
    EC2 = 13,
}

// C `union { u8 var_u8[3]; s16 filler3; s32 mat[7][5]; } u;` -- flattened to
// a plain struct (no test needs the members to overlap).
#[repr(C)]
#[derive(Clone, Copy)]
struct UFields {
    var_u8: [u8; 3],
    mat: [[i32; 5]; 7],
}
const ZERO_U: UFields = UFields {
    var_u8: [0; 3],
    mat: [[0; 5]; 7],
};

// C `struct Struct2 { u16 filler; volatile struct { int:1; union {...} u; }; } struct2[2][4];`
// -- the anonymous `volatile struct` wrapper is dropped, `u` hoisted directly.
#[repr(C)]
#[derive(Clone, Copy)]
struct Struct2 {
    u: UFields,
}
const ZERO_STRUCT2: Struct2 = Struct2 { u: ZERO_U };

// C `struct Struct { ...; struct Struct2 struct2[2][4]; };`
#[repr(C)]
#[derive(Clone, Copy)]
struct Struct {
    struct2: [[Struct2; 4]; 2],
}
const ZERO_STRUCT: Struct = Struct {
    struct2: [[ZERO_STRUCT2; 4]; 2],
};

// C `struct Struct3 { struct { u8 var_u8_l; }; struct { struct { u8 var_u8_h; }; }; };`
// -- both wrapper structs are anonymous, members hoisted directly.
#[repr(C)]
#[derive(Clone, Copy)]
struct Struct3 {
    var_u8_l: u8,
    var_u8_h: u8,
}

// C `union Union { u16 var_u16; Struct3_t struct3; };` -- real union: the
// test relies on var_u16 and struct3's two bytes sharing storage.
#[repr(C)]
#[derive(Clone, Copy)]
union Union {
    var_u16: u16,
    struct3: Struct3,
}

#[link_section = ".rodata"]
#[no_mangle]
static var_s64: i64 = -1;

#[link_section = ".rodata"]
#[no_mangle]
static var_u64: u64 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static var_s32: i32 = -1;

#[link_section = ".rodata"]
#[no_mangle]
static var_u32: u32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static var_s16: i16 = -1;

#[link_section = ".rodata"]
#[no_mangle]
static var_u16: u16 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static var_s8: i8 = -1;

#[link_section = ".rodata"]
#[no_mangle]
static var_u8: u8 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static var_ea: Enum = Enum::EA1;

#[link_section = ".rodata"]
#[no_mangle]
static var_eb: Enumu64 = Enumu64::EB1;

#[link_section = ".rodata"]
#[no_mangle]
static var_ec: Enums64 = Enums64::EC1;

#[link_section = ".rodata"]
#[no_mangle]
static var_b: bool = false;

#[link_section = ".rodata"]
#[no_mangle]
static arr: [i32; 32] = [0; 32];

#[link_section = ".rodata"]
#[no_mangle]
static enum_arr: [Enum; 32] = [Enum::EA1; 32];

#[link_section = ".rodata"]
#[no_mangle]
static three_d: [[[i32; 17]; 19]; 47] = [[[0; 17]; 19]; 47];

// A `static` (not `mut`) raw-pointer array would need `Sync`, which raw
// pointers don't implement; `static mut` sidesteps the bound (all access to
// a `static mut` is already unsafe) at the cost of landing in .bss instead
// of .rodata -- harmless here since this var is never read by the program
// and the only assertion on it is that `-G "ptr_arr[0] = 0"` is rejected
// for being a pointer element type, which only needs the BTF kind right.
#[no_mangle]
static mut ptr_arr: [*const i32; 32] = [core::ptr::null(); 32];

// same name prefix as struct1/struct11, unrelated var -- exercises BTF
// name-prefix disambiguation, not itself read by this program.
#[link_section = ".rodata"]
#[no_mangle]
static stru: u32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static struct1: [Struct; 3] = [ZERO_STRUCT; 3];

#[link_section = ".rodata"]
#[no_mangle]
static struct11: [[Struct; 7]; 11] = [[ZERO_STRUCT; 7]; 11];

#[link_section = ".rodata"]
#[no_mangle]
static union1: Union = Union { var_u16: 0xffff };

#[link_section = "socket"]
#[no_mangle]
extern "C" fn test_set_globals(_ctx: *const c_void) -> i32 {
    // C's `a` is `volatile __s8`, which clang keeps as a real stack slot
    // (store on every assignment, never register-promoted). That store is
    // what makes the kernel verifier's full (-vl2) log print each read's
    // resolved value alongside the store's other touched registers (e.g.
    // "R1=<value> R10=fp0 fp-8=..."), which is the literal text
    // test_veristat.c's `-G` assertions grep for. A plain Rust local would
    // get register-promoted (mem2reg) and only ever show a lone "R1=..."
    // with no trailing text -- so every assignment here goes through
    // write_volatile to force the same real stack store.
    let mut a: i8 = 0;
    let p = core::ptr::addr_of_mut!(a);

    macro_rules! set {
        ($val:expr) => {
            core::ptr::write_volatile(p, ($val) as i8)
        };
    }

    unsafe {
        set!(read_volatile(addr_of!(var_s64)));
        set!(read_volatile(addr_of!(var_u64)));
        set!(read_volatile(addr_of!(var_s32)));
        set!(read_volatile(addr_of!(var_u32)));
        set!(read_volatile(addr_of!(var_s16)));
        set!(read_volatile(addr_of!(var_u16)));
        set!(read_volatile(addr_of!(var_s8)));
        set!(read_volatile(addr_of!(var_u8)));
        set!(read_volatile(addr_of!(var_ea) as *const i32));
        set!(read_volatile(addr_of!(var_eb) as *const u64));
        set!(read_volatile(addr_of!(var_ec) as *const i64));
        set!(read_volatile(addr_of!(var_b) as *const u8));
        set!(read_volatile(addr_of!(
            struct1[2].struct2[1][2].u.var_u8[2]
        )));
        set!(read_volatile(addr_of!(union1.var_u16)));
        set!(read_volatile(addr_of!(arr[3])));
        set!(read_volatile(addr_of!(arr[Enum::EA2 as usize])));
        set!(read_volatile(
            addr_of!(enum_arr[Enums64::EC2 as usize]) as *const i32
        ));
        set!(read_volatile(addr_of!(
            three_d[31][7][Enum::EA2 as usize]
        )));
        set!(read_volatile(addr_of!(
            struct1[2].struct2[1][2].u.mat[5][3]
        )));
        set!(read_volatile(addr_of!(
            struct11[7][5].struct2[0][1].u.mat[3][0]
        )));

        read_volatile(p) as i32
    }
}

bpf_object!("GPL");
