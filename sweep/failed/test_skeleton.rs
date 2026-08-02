#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_skeleton.c
// (bpf-rs-core idiom).
//
// `bpf_syscall`/`kern_ver` mirror C's `bool bpf_syscall`/`int kern_ver`, but
// the C source populates them from `extern ... __kconfig` externs
// (CONFIG_BPF_SYSCALL, LINUX_KERNEL_VERSION). rustc's `extern "C" { static
// X: T; }` produces a plain external LLVM global with no attached debug
// info (unlike clang's `DIGlobalVariable(isDefinition: false)` for
// `__kconfig` externs), so no BTF extern-linkage VAR is ever emitted for
// them (see test_global_map_resize.rs's version_sink for the same gap).
// Without a BTF extern VAR, libbpf's bpf_object__init_kconfig_map() never
// creates the ".kconfig" datasec/map (it only fires when
// obj->externs contains an EXT_KCFG entry — see libbpf.c). That, in turn,
// means bpftool gen skeleton emits no `struct test_skeleton__kconfig` and
// no `kconfig` member on `struct test_skeleton` at all (codegen_datasec_def
// walks BTF datasecs; there is none to find). prog_tests/skeleton.c is
// fixed kernel-tree source that directly dereferences `skel->kconfig` and
// `kcfg->CONFIG_BPF_SYSCALL` / `kcfg->LINUX_KERNEL_VERSION` — with those
// symbols absent from the regenerated header this is a hard compile
// failure of the unmodified test harness, not a translatable behavioral
// gap. bpf_syscall/kern_ver are kept as always-zero globals (still
// required: both are real global OBJECT symbols in the C object's
// keep-list) purely for completeness; the kconfig blocker is unfixable
// regardless of their value.
//
// `.data.non_mmapable`'s `zero_key`/`zero_value` (C: `__hidden int
// zero_key`, `static struct my_value zero_value`) exist purely so the
// datasec's map ends up *not* BPF_F_MMAPABLE: libbpf's map_is_mmapable()
// walks the datasec's BTF VARs and flags the map mmapable iff any member
// has non-static linkage; the C source achieves "no non-static member" by
// making `zero_key` a global symbol with restricted (STV_HIDDEN) ELF
// visibility, which libbpf explicitly downgrades to BTF_VAR_STATIC (see
// libbpf.c's bpf_object__collect_externs/fixup, the STV_HIDDEN override
// comment). Rust has no attribute for per-item ELF visibility, so instead
// of replicating `zero_key` as an exported-but-hidden symbol, the key is
// just a stack local (its identity is never observed by any test) and only
// `zero_value` — a private (non-#[no_mangle], hence naturally
// internal-linkage / BTF_VAR_STATIC) static — lives in the section. That
// keeps every member of `.data.non_mmapable` static-linkage, which is the
// actual property `bpf_map__map_flags(...) == 0` depends on.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_map_update_elem;
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

const BPF_ANY: u64 = 0;

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct S {
    a: i32,
    b: i64,
}

#[repr(C)]
struct MyValue {
    x: i32,
    y: i32,
    z: i32,
}

unsafe impl Sync for MyValue {}

#[repr(C)]
struct InCfg {
    in6: i32,
}

// .data section (nonzero init).
#[no_mangle]
static mut in1: i32 = -1;
#[no_mangle]
static mut in2: i64 = -1;
#[no_mangle]
static mut out1: i32 = -1;
#[no_mangle]
static mut out2: i64 = -1;

// .bss section (zero init).
#[no_mangle]
static mut in3: i8 = 0;
#[no_mangle]
static mut in4: i64 = 0;
#[no_mangle]
static mut in5: S = S { a: 0, b: 0 };
#[no_mangle]
static mut out3: i8 = 0;
#[no_mangle]
static mut out4: i64 = 0;
#[no_mangle]
static mut out5: S = S { a: 0, b: 0 };
#[no_mangle]
static mut out6: i32 = 0;
#[no_mangle]
static mut bpf_syscall: bool = false;
#[no_mangle]
static mut kern_ver: i32 = 0;
#[no_mangle]
static mut out_mostly_var: i32 = 0;

const HUGE_ARR_LEN: usize = 16 * 1024 * 1024;
#[no_mangle]
static mut huge_arr: [u8; HUGE_ARR_LEN] = [0; HUGE_ARR_LEN];

// .rodata section (const volatile).
#[link_section = ".rodata"]
#[no_mangle]
static r#in: InCfg = InCfg { in6: 0 };

// .rodata.dyn section (const volatile).
#[link_section = ".rodata.dyn"]
#[no_mangle]
static in_dynarr_sz: i32 = 0;
#[link_section = ".rodata.dyn"]
#[no_mangle]
static in_dynarr: [i32; 4] = [-1, -2, -3, -4];

// .data.dyn section.
#[link_section = ".data.dyn"]
#[no_mangle]
static mut out_dynarr: [i32; 4] = [1, 2, 3, 4];

// .data.read_mostly section (`__read_mostly` == SEC(".data.read_mostly")).
#[link_section = ".data.read_mostly"]
#[no_mangle]
static mut read_mostly_var: i32 = 0;

// .data.non_mmapable section: only static-linkage members (see file header).
#[link_section = ".data.non_mmapable"]
static zero_value: MyValue = MyValue { x: 0, y: 0, z: 0 };

#[link_section = ".maps"]
#[no_mangle]
static my_map: BpfMap<i32, MyValue, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler(_ctx: *const c_void) -> i32 {
    unsafe {
        out1 = in1;
        out2 = in2;
        out3 = in3;
        out4 = in4;
        out5 = in5;
    }

    let in6 = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(r#in.in6)) };
    unsafe { out6 = in6 };

    let n = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(in_dynarr_sz)) };
    let mut i: i32 = 0;
    while i < n {
        let v = unsafe {
            core::ptr::read_volatile((core::ptr::addr_of!(in_dynarr) as *const i32).add(i as usize))
        };
        unsafe {
            (core::ptr::addr_of_mut!(out_dynarr) as *mut i32)
                .add(i as usize)
                .write(v);
        }
        i += 1;
    }

    let rmv = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(read_mostly_var)) };
    unsafe { out_mostly_var = rmv };

    unsafe {
        (core::ptr::addr_of_mut!(huge_arr) as *mut u8)
            .add(HUGE_ARR_LEN - 1)
            .write(123);
    }

    let key: i32 = 0;
    bpf_map_update_elem(&my_map, &key, &zero_value, BPF_ANY);

    0
}

bpf_object!("GPL");
