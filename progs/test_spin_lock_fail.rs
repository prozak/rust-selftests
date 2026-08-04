#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_spin_lock_fail.c
// (bpf-rs-core idiom).
//
// Every program here is driven by prog_tests/spin_lock.c's
// test_spin_lock_fail_prog(): it force-autoloads exactly one program by
// name, asserts the load *fails*, then regex-matches the kernel verifier
// log against an expected message. This is not the usual bpf_misc.h
// __failure/__msg decl-tag mechanism (untranslatable per TRANSLATING.md) --
// it's a hand-written userspace test that itself expects rejection, so the
// translation's job is to keep the same call/lock structure that the
// kernel verifier rejects for the same reason, not to make anything load.
//
// map_of_maps (BPF_MAP_TYPE_ARRAY_OF_MAPS) uses the zero-length `values`
// array-of-maps idiom (see progs/timer_mim.rs): the load-time slot
// population is unfixable in this pipeline, but every consumer here is
// load-only (test_spin_lock_fail_prog never calls bpf_prog_test_run on
// these programs), so the inner-map BTF typing the verifier needs for
// `bpf_map_lookup_elem(bpf_map_lookup_elem(&map_of_maps, ...), ...)` is
// unaffected -- only the runtime fd population (irrelevant here) is lost.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    self, bpf_copy_from_user, bpf_map_lookup_elem, bpf_spin_lock, bpf_spin_unlock,
    bpf_this_cpu_ptr,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vload;
use core::ffi::c_void;

// struct bpf_spin_lock { __u32 val; }; -- matched by BTF struct name.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[repr(C)]
struct foo {
    lock: bpf_spin_lock,
    data: i32,
}

type ArrayMap = BpfMap<i32, foo, { maps::ARRAY }, 1>;

#[link_section = ".maps"]
#[no_mangle]
static array_map: ArrayMap = BpfMap::new();

// enum bpf_map_type: BPF_MAP_TYPE_ARRAY_OF_MAPS (not exported by
// bpf_rs_core::maps, which only covers the constants its existing
// translations needed).
const ARRAY_OF_MAPS: usize = 12;

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_of_maps_def {
    r#type: *const [i32; ARRAY_OF_MAPS],
    max_entries: *const [i32; 1],
    key: *const i32,
    value: *const i32,
    // Zero-length: see the file-level comment / timer_mim.rs. Carries the
    // inner map's BTF pointer type (`*const ArrayMap`) for the verifier's
    // static typing even with no populated slots.
    values: [*const ArrayMap; 0],
}
unsafe impl Sync for map_of_maps_def {}

#[link_section = ".maps"]
#[no_mangle]
static map_of_maps: map_of_maps_def = map_of_maps_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [],
};

// C: `static struct bpf_spin_lock lockA/lockB SEC(".data.A"/".data.B");` --
// file-scope `static`, never exported. Per
// [[rust-no-elf-visibility-use-private-static]] a plain private (no
// #[no_mangle]) `static mut` gets the same effective BTF_VAR_STATIC linkage.
#[allow(non_upper_case_globals)]
#[link_section = ".data.A"]
static mut lockA: bpf_spin_lock = bpf_spin_lock { val: 0 };
#[allow(non_upper_case_globals)]
#[link_section = ".data.B"]
static mut lockB: bpf_spin_lock = bpf_spin_lock { val: 0 };

// Forces rustc to emit a full BTF_KIND_STRUCT (not a bare FWD) for `foo`:
// as a bare pointee-of-a-pointer (bpf_obj_new's return cast, map value
// field) the type only ever needs a forward declaration; embedding it as an
// actual by-value global forces full field/layout emission. Internal
// linkage only (no #[no_mangle]) -- never reaches the object's kept ABI
// symbol set. See [[bpf-obj-new-local-type-id-post-dedup-technique]].
static FOO_LAYOUT_PROBE: foo = foo {
    lock: bpf_spin_lock { val: 0 },
    data: 0,
};

// This object's own (raw, pre-dedup) BTF type id for `struct foo`, read
// back from `bpftool btf dump file bld/test_spin_lock_fail.bpf.o` after a
// build with FOO_LAYOUT_PROBE in place. C's `bpf_obj_new(typeof(*f))` macro
// resolves this via a BPF_CORE_TYPE_ID_LOCAL relocation Clang emits and
// libbpf patches at load time; this pipeline has no such relocation
// support, so the id is hardcoded here instead. Per the CORRECTED note in
// [[bpf-obj-new-local-type-id-post-dedup-technique]], `bpf_object__load()`
// never runs `btf__dedup()` on a translated object's own .BTF, so the raw
// id (not a hand-counted post-dedup guess) is what the kernel actually
// sees.
const FOO_TYPE_ID: u64 = 9;

extern "C" {
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(ptr: *mut c_void) -> c_void;
}

#[inline(always)]
fn new_foo() -> *mut foo {
    let f = unsafe { bpf_obj_new(FOO_TYPE_ID) } as *mut foo;
    let mut p = core::ptr::addr_of!(FOO_LAYOUT_PROBE) as *mut foo;
    helpers::sink(&mut p);
    f
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn lock_id_kptr_preserve(_ctx: *mut c_void) -> i32 {
    let f = new_foo();
    if f.is_null() {
        return 0;
    }
    bpf_this_cpu_ptr(f as *const c_void);
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn lock_id_global_zero(_ctx: *mut c_void) -> i32 {
    bpf_this_cpu_ptr(core::ptr::addr_of!(lockA) as *const c_void);
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn lock_id_mapval_preserve(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    let f = bpf_map_lookup_elem(&array_map, &key) as *mut foo;
    if f.is_null() {
        return 0;
    }
    bpf_this_cpu_ptr(f as *const c_void);
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn lock_id_innermapval_preserve(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    let map = bpf_map_lookup_elem(&map_of_maps, &key);
    if map.is_null() {
        return 0;
    }
    let f = bpf_map_lookup_elem(map, &key) as *mut foo;
    if f.is_null() {
        return 0;
    }
    bpf_this_cpu_ptr(f as *const c_void);
    0
}

// Generates one `lock_id_mismatch_<name>` "?tc" program matching the C
// CHECK() macro's body: acquire iv (inner-map value), v (array-map value),
// f1/f2 (fresh kptrs), then bpf_spin_lock(A) / bpf_spin_unlock(B) on two
// (possibly-)different locks, which the verifier must reject with
// "bpf_spin_unlock of different lock" whenever A and B don't share a lock
// id. $a/$b select which acquired pointer's `.lock` (or which global lock)
// to use, resolved via lock_ptr!.
macro_rules! lock_ptr {
    (F1, $f1:expr, $f2:expr, $v:expr, $iv:expr) => {
        core::ptr::addr_of_mut!((*$f1).lock)
    };
    (F2, $f1:expr, $f2:expr, $v:expr, $iv:expr) => {
        core::ptr::addr_of_mut!((*$f2).lock)
    };
    (V, $f1:expr, $f2:expr, $v:expr, $iv:expr) => {
        core::ptr::addr_of_mut!((*$v).lock)
    };
    (IV, $f1:expr, $f2:expr, $v:expr, $iv:expr) => {
        core::ptr::addr_of_mut!((*$iv).lock)
    };
    (LOCKA, $f1:expr, $f2:expr, $v:expr, $iv:expr) => {
        core::ptr::addr_of_mut!(lockA)
    };
    (LOCKB, $f1:expr, $f2:expr, $v:expr, $iv:expr) => {
        core::ptr::addr_of_mut!(lockB)
    };
}

macro_rules! lock_id_mismatch {
    ($fn_name:ident, $a:tt, $b:tt) => {
        #[link_section = "?tc"]
        #[no_mangle]
        extern "C" fn $fn_name(_ctx: *mut c_void) -> i32 {
            let key: i32 = 0;

            let map = bpf_map_lookup_elem(&map_of_maps, &key);
            if map.is_null() {
                return 0;
            }
            let iv = bpf_map_lookup_elem(map, &key) as *mut foo;
            if iv.is_null() {
                return 0;
            }
            let v = bpf_map_lookup_elem(&array_map, &key) as *mut foo;
            if v.is_null() {
                return 0;
            }
            let f1 = new_foo();
            if f1.is_null() {
                return 0;
            }
            let f2 = new_foo();
            if f2.is_null() {
                unsafe {
                    bpf_obj_drop(f1 as *mut c_void);
                }
                return 0;
            }
            // LOCKA/LOCKB-only instantiations (e.g. global_global) need no
            // raw-pointer deref, making this block a no-op unsafely for
            // them specifically.
            #[allow(unused_unsafe)]
            unsafe {
                bpf_spin_lock(lock_ptr!($a, f1, f2, v, iv));
                bpf_spin_unlock(lock_ptr!($b, f1, f2, v, iv));
            }
            0
        }
    };
}

lock_id_mismatch!(lock_id_mismatch_kptr_kptr, F1, F2);
lock_id_mismatch!(lock_id_mismatch_kptr_global, F1, LOCKA);
lock_id_mismatch!(lock_id_mismatch_kptr_mapval, F1, V);
lock_id_mismatch!(lock_id_mismatch_kptr_innermapval, F1, IV);

lock_id_mismatch!(lock_id_mismatch_global_global, LOCKA, LOCKB);
lock_id_mismatch!(lock_id_mismatch_global_kptr, LOCKA, F1);
lock_id_mismatch!(lock_id_mismatch_global_mapval, LOCKA, V);
lock_id_mismatch!(lock_id_mismatch_global_innermapval, LOCKA, IV);

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn lock_id_mismatch_mapval_mapval(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;

    let f1 = bpf_map_lookup_elem(&array_map, &key) as *mut foo;
    if f1.is_null() {
        return 0;
    }
    let f2 = bpf_map_lookup_elem(&array_map, &key) as *mut foo;
    if f2.is_null() {
        return 0;
    }

    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!((*f1).lock));
        (*f1).data = 42;
        bpf_spin_unlock(core::ptr::addr_of_mut!((*f2).lock));
    }
    0
}

lock_id_mismatch!(lock_id_mismatch_mapval_kptr, V, F1);
lock_id_mismatch!(lock_id_mismatch_mapval_global, V, LOCKB);
lock_id_mismatch!(lock_id_mismatch_mapval_innermapval, V, IV);

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn lock_id_mismatch_innermapval_innermapval1(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;

    let map = bpf_map_lookup_elem(&map_of_maps, &key);
    if map.is_null() {
        return 0;
    }
    let f1 = bpf_map_lookup_elem(map, &key) as *mut foo;
    if f1.is_null() {
        return 0;
    }
    let f2 = bpf_map_lookup_elem(map, &key) as *mut foo;
    if f2.is_null() {
        return 0;
    }

    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!((*f1).lock));
        (*f1).data = 42;
        bpf_spin_unlock(core::ptr::addr_of_mut!((*f2).lock));
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn lock_id_mismatch_innermapval_innermapval2(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;

    let map = bpf_map_lookup_elem(&map_of_maps, &key);
    if map.is_null() {
        return 0;
    }
    let f1 = bpf_map_lookup_elem(map, &key) as *mut foo;
    if f1.is_null() {
        return 0;
    }
    let map2 = bpf_map_lookup_elem(&map_of_maps, &key);
    if map2.is_null() {
        return 0;
    }
    let f2 = bpf_map_lookup_elem(map2, &key) as *mut foo;
    if f2.is_null() {
        return 0;
    }

    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!((*f1).lock));
        (*f1).data = 42;
        bpf_spin_unlock(core::ptr::addr_of_mut!((*f2).lock));
    }
    0
}

lock_id_mismatch!(lock_id_mismatch_innermapval_kptr, IV, F1);
lock_id_mismatch!(lock_id_mismatch_innermapval_global, IV, LOCKA);
lock_id_mismatch!(lock_id_mismatch_innermapval_mapval, IV, V);

// C: `__noinline int global_subprog(struct __sk_buff *ctx)` -- non-static,
// so it's a real *global* BPF subprog: the kernel verifier categorically
// disallows calling a global function while holding a spin lock
// ("global function calls are not allowed while holding a lock"),
// independent of what the callee's body does. `pub` (matching
// progs/test_global_func1.rs's f1/f2/f3/global_func1 convention) plus
// #[no_mangle] keeps it a real, separately-callable, exported subprog; the
// build's internalize pass demotes the `static`-in-C ones back to local
// linkage from the C object's own keep-list, so plain #[no_mangle] without
// `pub` is used for those instead.
#[no_mangle]
#[inline(never)]
pub extern "C" fn global_subprog(ctx: *const __sk_buff) -> i32 {
    let mut ret: i32 = 0;
    if vload!((*ctx).protocol) != 0 {
        ret += vload!((*ctx).protocol) as i32;
    }
    ret + vload!((*ctx).mark) as i32
}

#[no_mangle]
#[inline(never)]
extern "C" fn static_subprog_call_global(ctx: *const __sk_buff) -> i32 {
    let ret: i32 = 0;
    if vload!((*ctx).protocol) != 0 {
        return ret;
    }
    ret + vload!((*ctx).len) as i32 + global_subprog(ctx)
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn lock_global_subprog_call1(ctx: *const __sk_buff) -> i32 {
    let mut ret: i32 = 0;
    bpf_spin_lock(core::ptr::addr_of_mut!(lockA));
    if vload!((*ctx).mark) == 42 {
        ret = global_subprog(ctx);
    }
    bpf_spin_unlock(core::ptr::addr_of_mut!(lockA));
    ret
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn lock_global_subprog_call2(ctx: *const __sk_buff) -> i32 {
    let mut ret: i32 = 0;
    bpf_spin_lock(core::ptr::addr_of_mut!(lockA));
    if vload!((*ctx).mark) == 42 {
        ret = static_subprog_call_global(ctx);
    }
    bpf_spin_unlock(core::ptr::addr_of_mut!(lockA));
    ret
}

// The remaining four `int __noinline` C functions are likewise non-static
// (real global subprogs); the C bodies call bpf_printk / the
// bpf_copy_from_user_str KFUNC (KF_SLEEPABLE) to make them "sleepable", but
// the verifier's "global function calls are not allowed while holding a
// lock" check fires for *any* global-function call while locked -- see
// lock_global_subprog_call1/2 above, whose callee is not sleepable at all
// and still hits the exact same error message in the expected-message
// table. So the sleepable-kfunc detail is not load-bearing for this test;
// bpf_copy_from_user_str is a genuine kfunc with a bare `void *dst` param
// that add_ksyms.py cannot mirror without crashing llvm-as (same class of
// bug documented in progs/test_attach_probe.rs), so it's swapped here for
// the already-safe `bpf_copy_from_user` HELPER, keeping the call graph
// shape (global subprog calling global subprog calling a copy-from-user
// primitive) without that landmine. barrier_var keeps each function a real
// non-trivial, non-eliminated subprog (see
// [[weak-trivial-subprog-ipsccp-eliminated]]).
#[no_mangle]
#[inline(never)]
pub extern "C" fn global_subprog_int(i: i32) -> i32 {
    let mut v = i as usize;
    helpers::barrier_var(&mut v);
    v as i32
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn global_sleepable_helper_subprog(i: i32) -> i32 {
    if i != 0 {
        let mut buf: i32 = i;
        bpf_copy_from_user(
            &mut buf as *mut i32 as *mut c_void,
            core::mem::size_of::<i32>() as u32,
            core::ptr::null(),
        );
    }
    let mut v = i as usize;
    helpers::barrier_var(&mut v);
    v as i32
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn global_sleepable_kfunc_subprog(i: i32) -> i32 {
    if i != 0 {
        let mut buf: [u8; 4] = [0; 4];
        bpf_copy_from_user(
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            core::ptr::null(),
        );
    }
    global_subprog_int(i);
    let mut v = i as usize;
    helpers::barrier_var(&mut v);
    v as i32
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn global_subprog_calling_sleepable_global(i: i32) -> i32 {
    if i == 0 {
        global_sleepable_kfunc_subprog(i);
    }
    let mut v = i as usize;
    helpers::barrier_var(&mut v);
    v as i32
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn lock_global_sleepable_helper_subprog(ctx: *const __sk_buff) -> i32 {
    let mut ret: i32 = 0;
    bpf_spin_lock(core::ptr::addr_of_mut!(lockA));
    if vload!((*ctx).mark) == 42 {
        ret = global_sleepable_helper_subprog(vload!((*ctx).mark) as i32);
    }
    bpf_spin_unlock(core::ptr::addr_of_mut!(lockA));
    ret
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn lock_global_sleepable_kfunc_subprog(ctx: *const __sk_buff) -> i32 {
    let mut ret: i32 = 0;
    bpf_spin_lock(core::ptr::addr_of_mut!(lockA));
    if vload!((*ctx).mark) == 42 {
        ret = global_sleepable_kfunc_subprog(vload!((*ctx).mark) as i32);
    }
    bpf_spin_unlock(core::ptr::addr_of_mut!(lockA));
    ret
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn lock_global_sleepable_subprog_indirect(ctx: *const __sk_buff) -> i32 {
    let mut ret: i32 = 0;
    bpf_spin_lock(core::ptr::addr_of_mut!(lockA));
    if vload!((*ctx).mark) == 42 {
        ret = global_subprog_calling_sleepable_global(vload!((*ctx).mark) as i32);
    }
    bpf_spin_unlock(core::ptr::addr_of_mut!(lockA));
    ret
}

bpf_object!("GPL");
