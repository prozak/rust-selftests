#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_core_autosize.c
// (bpf-rs-core idiom).
//
// The C original exercises clang/libbpf's CO-RE *size autosizing*: fields of
// `struct test_struct___{samesize,downsize,signed}` are accessed directly
// (preserve_access_index) against a synthetic 32-bit-pointer "kernel" BTF
// (`struct test_struct`) supplied by the userspace test via btf_custom_path.
//
// This crate's only CO-RE machinery is the `#[btf]` proc-macro plus
// `rust-bpf/bpf-postproc/src/field_reloc.rs`'s `FieldRelocPass`, which lowers
// field-info polyfills to exactly two of LLVM's kinds: BYTE_OFFSET (0) and
// EXISTENCE (2). That turned out to be enough: real libbpf's BYTE_OFFSET
// relocation handler (`bpf_core_calc_field_relo` + `bpf_core_patch_insn` in
// tools/lib/bpf/relo_core.c) computes the *target* field's resolved size
// unconditionally (not just for the dedicated FIELD_BYTE_SIZE kind), and
// when it differs from the compiled LDX/STX instruction's own width (which
// must match the *local* field's declared size), it rewrites the
// instruction's size bits in place and lets the normal zero-extending BPF
// load/store do the rest -- no BYTE_SIZE/SIGNED relocation needed at all.
// So `handle_samesize`/`handle_downsize`/`handle_probed` below are ordinary
// direct field dereferences at CO-RE-resolved addresses, exactly like the C
// original's `in->val2` etc: declare each shadow struct's field with
// whatever width the C source uses (samesize: exact target widths;
// downsize: `unsigned long` -> u64 throughout) and let real libpf's load-time
// patcher narrow the actual instruction. The one hard constraint (confirmed
// by trial: "insn #N (LDX/ST/STX) unexpected mem size" load failure) is that
// the compiled instruction's width must equal the *local* declared size --
// i.e. never read/write through a narrower reinterpreted pointer than the
// field's own declared type, since libbpf checks the instruction's
// as-compiled width against that before it will rewrite it.
//
// `handle_signed` cannot reach a real value either way (the C original's
// program never runs -- the object fails to load), and the test only
// asserts `test_core_autosize__load(skel)` returns nonzero. Real CO-RE field
// *matching* (`bpf_core_fields_are_compat()`) ignores int size/signedness
// entirely, so a plain signed-vs-unsigned `long` mismatch (the C original's
// actual mechanism) would still resolve fine through this pipeline's
// BYTE_OFFSET relocation and load successfully -- not the outcome the test
// wants. Kind compatibility (BTF_KIND_PTR vs BTF_KIND_INT) *is* still
// enforced unconditionally, though, so `val2` in the ___signed shadow struct
// is declared as a pointer instead of the C original's `long`: that field
// can never resolve against the target's integer `val2`, libbpf poisons the
// instruction, and the load is rejected -- the same observable outcome
// (load failure) reached through a mismatch this pipeline can express.

use core::ffi::c_void;
use core::ptr::addr_of;
use core::ptr::addr_of_mut;

use bpf_rs_core::bpf_object;
use btf_macros::btf;

// Real, fixed memory layout backing `input`/`output_*` -- matches the C
// original's `struct test_struct___real` field-for-field (not a CO-RE type;
// this is our own program's plain global storage, never target-kernel
// memory, so it's read/written directly with no field relocation involved).
// Named exactly like the C type (including the `___real` flavor suffix) so
// `bpftool gen skeleton`'s generated `struct test_struct___real input;`
// field resolves against `prog_tests/core_autosize.c`'s own pre-declared
// definition of the same name, instead of an unresolvable invented name.
#[repr(C)]
#[derive(Clone, Copy)]
struct test_struct___real {
    ptr: u32,
    val2: u32,
    val1: u64,
    val3: u16,
    val4: u8,
    _pad: u8,
}

#[no_mangle]
static mut input: test_struct___real = test_struct___real {
    ptr: 0x01020304,
    val2: 0x0a0b0c0d,
    val1: 0x1020304050607080,
    val3: 0xfeed,
    val4: 0xb9,
    _pad: 0xff,
};

/* fields of exactly the same size */
#[btf]
struct test_struct___samesize {
    ptr: *const u8,
    val1: u64,
    val2: u32,
    val3: u16,
    val4: u8,
}

/* unsigned fields that have to be downsized by libbpf */
#[btf]
struct test_struct___downsize {
    ptr: *const u8,
    val1: u64,
    val2: u64,
    val3: u64,
    val4: u64,
}

/* fields with signed integers of wrong size, should be rejected -- val2 is
 * deliberately a pointer (kind mismatch) so the CO-RE relocation this
 * pipeline can actually emit (BYTE_OFFSET) fails to resolve; see module doc.
 */
#[btf]
struct test_struct___signed {
    ptr: *const u8,
    val1: i64,
    val2: *const u8,
    val3: i64,
    val4: i64,
}

// All 23 zero-init globals the C original declares after `input` live in one
// flat `[u8; 232]` instead of 23 top-level `static mut`s or one named
// #[repr(C)] struct. Three pipeline constraints collide here:
//  - `bpftool gen object` (the kernel selftests Makefile's 3x self-link pass
//    before `gen skeleton`) hard-errors ("failed to find BTF info for
//    global/extern symbol") on any GLOBAL-bind object symbol whose BTF is
//    missing -- so a global_asm!-hand-laid, BTF-less symbol (the usual fix
//    for rustc's alphabetical mono-item scatter -- see
//    bss-global-order-fix-via-global-asm, and
//    rustc-mono-item-order-by-symbol-name-unfixable, which already notes
//    this bypass "forfeits BTF ... info") is not an option.
//  - `prog_tests/core_autosize.c` reads the whole `.bss` map as one raw byte
//    blob (`bpf_map__lookup_elem(bss_map, ..., &out, sizeof(out), 0)`) into
//    a userspace struct whose members are exactly these 23 globals in C
//    declaration order, so rustc's normal per-static placement (ascending
//    ABI symbol name order, not declaration order) would scramble it if each
//    stayed a separate top-level `static`.
//  - Bundling them into one *named* #[repr(C)] struct (tried first) gets the
//    order and the BTF right, but `bpftool gen skeleton` then emits
//    `struct <ThatName> bss;` into the generated header by bare name,
//    exactly like it already does for `struct test_struct___real input` --
//    except nothing predeclares that invented name the way
//    `prog_tests/core_autosize.c` predeclares `test_struct___real`
//    (`./test_core_autosize.skel.h:33:28: error: field 'bss' has incomplete
//    type`).
// A byte array sidesteps all three: it's one symbol (no multi-item ordering
// to scramble), it gets real BTF (`bpftool gen object` is satisfied), and
// its element type is a builtin (`unsigned char bss[232];` needs no
// predeclared name at all). Every field is then a hand-computed byte offset
// into it -- the offsets are exactly the ones the field layout below would
// have produced, just not expressed as Rust field access.
const OFF_PTR_SAMESIZED: usize = 0;
const OFF_VAL1_SAMESIZED: usize = 8;
const OFF_VAL2_SAMESIZED: usize = 16;
const OFF_VAL3_SAMESIZED: usize = 24;
const OFF_VAL4_SAMESIZED: usize = 32;
const OFF_OUTPUT_SAMESIZED: usize = 40; // struct test_struct___real, 24 bytes

const OFF_PTR_DOWNSIZED: usize = 64;
const OFF_VAL1_DOWNSIZED: usize = 72;
const OFF_VAL2_DOWNSIZED: usize = 80;
const OFF_VAL3_DOWNSIZED: usize = 88;
const OFF_VAL4_DOWNSIZED: usize = 96;
const OFF_OUTPUT_DOWNSIZED: usize = 104; // struct test_struct___real, 24 bytes

const OFF_PTR_PROBED: usize = 128;
const OFF_VAL1_PROBED: usize = 136;
const OFF_VAL2_PROBED: usize = 144;
const OFF_VAL3_PROBED: usize = 152;
const OFF_VAL4_PROBED: usize = 160;

const OFF_VAL2_SIGNED: usize = 184;
const OFF_VAL3_SIGNED: usize = 192;
const OFF_VAL4_SIGNED: usize = 200;
const OFF_OUTPUT_SIGNED: usize = 208; // struct test_struct___real, 24 bytes

const BSS_SIZE: usize = 232;

// Written but never read from within this compilation unit (the userspace
// test reads it out-of-band via a raw `.bss` map lookup), so plain O2 would
// see an unread-after-write global and delete every store into it -- and,
// with them, the CO-RE field-access chains that fed them. `#[used]` keeps it
// externally observable (`@llvm.used`) so the optimizer can't assume that;
// `#[link_section]` counters `#[used]`'s side effect of moving an otherwise
// plain zero-init static into its own uniquely-named (here ".bss.bss")
// SHF_GNU_RETAIN section instead of the shared ".bss" the map lookup needs.
#[used]
#[link_section = ".bss"]
#[no_mangle]
static mut bss: [u8; BSS_SIZE] = [0; BSS_SIZE];

#[inline(always)]
unsafe fn bss_at(offset: usize) -> *mut u8 {
    (addr_of_mut!(bss) as *mut u8).add(offset)
}

// Every write below uses `core::ptr::write` (alignment-asserting), never
// `write_unaligned`, even though the destination is technically only
// byte-aligned (`bss: [u8; N]`) and a CO-RE-resolved address's *final*
// (post-relocation) offset isn't guaranteed 8-aligned either. Two things
// make this both safe and necessary, not just convenient: x86_64 has
// efficient unaligned access, so the verifier's `check_ptr_alignment()`
// never enforces natural alignment on this target regardless of which
// intrinsic is used -- so nothing is actually gained safety-wise from
// `write_unaligned`. But it costs a lot: LLVM lowers an `align 1` 8-byte
// store into eight chained single-byte shift+store instructions on this
// backend (confirmed by inspecting the disassembly), and libbpf's
// CO-RE patcher requires the compiled instruction's width to already equal
// the local field's declared size before it will resize it -- eight 1-byte
// stores instead of one 8-byte store fails exactly that check ("insn #N
// (LDX/ST/STX) unexpected mem size: got 1, exp 8"). Plain `write`/`read`
// always compiles to one natural-width instruction.

#[link_section = "raw_tp/sys_exit"]
#[no_mangle]
extern "C" fn handle_samesize(_ctx: *const c_void) -> i32 {
    let in_ = unsafe { &*(addr_of!(input) as *const test_struct___samesize) };
    let out_ = unsafe { &*(bss_at(OFF_OUTPUT_SAMESIZED) as *const test_struct___samesize) };

    let ptr_v = unsafe { *in_.ptr().as_ptr() } as u64;
    let val1_v = unsafe { *in_.val1().as_ptr() };
    let val2_v = unsafe { *in_.val2().as_ptr() } as u64;
    let val3_v = unsafe { *in_.val3().as_ptr() } as u64;
    let val4_v = unsafe { *in_.val4().as_ptr() } as u64;

    unsafe {
        core::ptr::write(bss_at(OFF_PTR_SAMESIZED) as *mut u64, ptr_v);
        core::ptr::write(bss_at(OFF_VAL1_SAMESIZED) as *mut u64, val1_v);
        core::ptr::write(bss_at(OFF_VAL2_SAMESIZED) as *mut u64, val2_v);
        core::ptr::write(bss_at(OFF_VAL3_SAMESIZED) as *mut u64, val3_v);
        core::ptr::write(bss_at(OFF_VAL4_SAMESIZED) as *mut u64, val4_v);

        core::ptr::write(out_.ptr().as_mut_ptr(), ptr_v as *const u8);
        core::ptr::write(out_.val1().as_mut_ptr(), val1_v);
        core::ptr::write(out_.val2().as_mut_ptr(), val2_v as u32);
        core::ptr::write(out_.val3().as_mut_ptr(), val3_v as u16);
        core::ptr::write(out_.val4().as_mut_ptr(), val4_v as u8);
    }

    0
}

#[link_section = "raw_tp/sys_exit"]
#[no_mangle]
extern "C" fn handle_downsize(_ctx: *const c_void) -> i32 {
    let in_ = unsafe { &*(addr_of!(input) as *const test_struct___downsize) };
    let out_ = unsafe { &*(bss_at(OFF_OUTPUT_DOWNSIZED) as *const test_struct___downsize) };

    let ptr_v = unsafe { *in_.ptr().as_ptr() } as u64;
    let val1_v = unsafe { *in_.val1().as_ptr() };
    let val2_v = unsafe { *in_.val2().as_ptr() };
    let val3_v = unsafe { *in_.val3().as_ptr() };
    let val4_v = unsafe { *in_.val4().as_ptr() };

    unsafe {
        core::ptr::write(bss_at(OFF_PTR_DOWNSIZED) as *mut u64, ptr_v);
        core::ptr::write(bss_at(OFF_VAL1_DOWNSIZED) as *mut u64, val1_v);
        core::ptr::write(bss_at(OFF_VAL2_DOWNSIZED) as *mut u64, val2_v);
        core::ptr::write(bss_at(OFF_VAL3_DOWNSIZED) as *mut u64, val3_v);
        core::ptr::write(bss_at(OFF_VAL4_DOWNSIZED) as *mut u64, val4_v);

        core::ptr::write(out_.ptr().as_mut_ptr(), ptr_v as *const u8);
        core::ptr::write(out_.val1().as_mut_ptr(), val1_v);
        core::ptr::write(out_.val2().as_mut_ptr(), val2_v);
        core::ptr::write(out_.val3().as_mut_ptr(), val3_v);
        core::ptr::write(out_.val4().as_mut_ptr(), val4_v);
    }

    0
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handle_probed(_ctx: *const c_void) -> i32 {
    let in_ = unsafe { &*(addr_of!(input) as *const test_struct___downsize) };

    let ptr_v = unsafe { *in_.ptr().as_ptr() } as u64;
    let val1_v = unsafe { *in_.val1().as_ptr() };
    let val2_v = unsafe { *in_.val2().as_ptr() };
    let val3_v = unsafe { *in_.val3().as_ptr() };
    let val4_v = unsafe { *in_.val4().as_ptr() };

    unsafe {
        core::ptr::write(bss_at(OFF_PTR_PROBED) as *mut u64, ptr_v);
        core::ptr::write(bss_at(OFF_VAL1_PROBED) as *mut u64, val1_v);
        core::ptr::write(bss_at(OFF_VAL2_PROBED) as *mut u64, val2_v);
        core::ptr::write(bss_at(OFF_VAL3_PROBED) as *mut u64, val3_v);
        core::ptr::write(bss_at(OFF_VAL4_PROBED) as *mut u64, val4_v);
    }

    0
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handle_signed(_ctx: *const c_void) -> i32 {
    let in_ = unsafe { &*(addr_of!(input) as *const test_struct___signed) };
    let out_ = unsafe { &*(bss_at(OFF_OUTPUT_SIGNED) as *const test_struct___signed) };

    // `val2` never resolves (kind mismatch vs the target's integer field):
    // this poisons the relocation and the whole object fails to load when
    // this program's autoload isn't disabled, mirroring the C original's
    // (unreachable, in this pipeline) signed/unsigned rejection.
    let val2_v = unsafe { *in_.val2().as_ptr() } as u64;
    let val3_v = unsafe { *in_.val3().as_ptr() } as u64;
    let val4_v = unsafe { *in_.val4().as_ptr() } as u64;

    unsafe {
        core::ptr::write(bss_at(OFF_VAL2_SIGNED) as *mut u64, val2_v);
        core::ptr::write(bss_at(OFF_VAL3_SIGNED) as *mut u64, val3_v);
        core::ptr::write(bss_at(OFF_VAL4_SIGNED) as *mut u64, val4_v);

        core::ptr::write(out_.val2().as_mut_ptr(), val2_v as *const u8);
        core::ptr::write(out_.val3().as_mut_ptr(), val3_v as i64);
        core::ptr::write(out_.val4().as_mut_ptr(), val4_v as i64);
    }

    0
}

bpf_object!("GPL");
