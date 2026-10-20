// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![feature(used_with_arg)]

// Direct translation of tools/testing/selftests/bpf/progs/res_spin_lock_fail.c
// (bpf-rs-core idiom): the verifier's checks on bpf_res_spin_lock -- the
// lock argument's type and offset, AA deadlocks, mismatched and
// out-of-order unlocks, irqsave/irqrestore pairing, and maps or local
// kptrs that hold no bpf_res_spin_lock at all. The hidden per-section
// locks (`__hidden SEC(".data.X")`) are private statics in those sections
// as in res_spin_lock.rs; bpf_core_cast is bpf_rdonly_cast with the
// BTF_TYPE_ID of struct __sk_buff, and bpf_assert_range is the C macro's
// two `if ... goto +2; r1 = 0; call bpf_throw` asm blocks. The test_loader
// decl tags are declared with test_tags! (scripts/btf_test_tags.py).

// BTF_TYPE_ID: tid_sk_buff struct __sk_buff
// BTF_TYPE_ID: anon_i_id local struct anon_i (anonymous)

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_map_lookup_elem;
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::test_tags;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_res_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct arr_elem {
    lock: bpf_res_spin_lock,
}

// C: struct { int i; } *p = bpf_obj_new(typeof(*p)); -- the anonymous
// local type, named here for the BTF_TYPE_ID above.
#[allow(non_camel_case_types)]
#[repr(C)]
struct anon_i {
    i: i32,
}

#[link_section = ".maps"]
#[no_mangle]
static arrmap: BpfMap<i32, arr_elem, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut value: i64 = 0;

// C: struct bpf_spin_lock lock __hidden SEC(".data.A");
//    struct bpf_res_spin_lock res_lock __hidden SEC(".data.B");
// `lock` is referenced by nothing, as in the C. #[used(compiler)] puts it in
// llvm.compiler.used, which globaldce honours but the internalize pass does
// not, so the symbol stays LOCAL (BTF linkage static, like the C's hidden
// global); plain #[used] (llvm.used) would keep it GLOBAL, libbpf would
// then make .data.A mmapable and the kernel refuses an mmapable map that
// holds a spin lock (-ENOTSUPP).
#[allow(non_upper_case_globals)]
#[used(compiler)]
#[link_section = ".data.A"]
static mut lock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[link_section = ".data.B"]
static mut res_lock: bpf_res_spin_lock = bpf_res_spin_lock { val: 0 };

extern "C" {
    fn tid_sk_buff() -> u64;
    fn anon_i_id() -> u64;
    fn bpf_res_spin_lock(lock: *mut bpf_res_spin_lock) -> i32;
    fn bpf_res_spin_unlock(lock: *mut bpf_res_spin_lock);
    fn bpf_res_spin_lock_irqsave(lock: *mut bpf_res_spin_lock, flags: *mut u64) -> i32;
    fn bpf_res_spin_unlock_irqrestore(lock: *mut bpf_res_spin_lock, flags: *mut u64);
    fn bpf_local_irq_save(flags: *mut u64);
    fn bpf_rdonly_cast(obj: *const c_void, btf_id: u32) -> *mut c_void;
    fn bpf_throw(cookie: u64);
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
}

test_tags! {
    res_spin_lock_arg: __failure, __msg("R1 type=untrusted_ptr_ expected=map_value, ptr_");
    res_spin_lock_AA: __failure, __msg("AA deadlock detected");
    res_spin_lock_cond_AA: __failure, __msg("AA deadlock detected");
    res_spin_lock_mismatch_1: __failure, __msg("unlock of different lock");
    res_spin_lock_mismatch_2: __failure, __msg("unlock of different lock");
    res_spin_lock_irq_mismatch_1: __failure, __msg("unlock of different lock");
    res_spin_lock_irq_mismatch_2: __failure, __msg("unlock of different lock");
    res_spin_lock_ooo: __success;
    res_spin_lock_ooo_irq: __success;
    res_spin_lock_ooo_unlock: __failure, __msg("bpf_res_spin_unlock cannot be out of order");
    res_spin_lock_bad_off: __failure, __msg("off 1 doesn't point to 'struct bpf_res_spin_lock' that is at 0");
    res_spin_lock_var_off: __failure, __msg("R1 doesn't have constant offset. bpf_res_spin_lock has to be at the constant offset");
    res_spin_lock_no_lock_map: __failure, __msg("map 'res_spin.bss' has no valid bpf_res_spin_lock");
    res_spin_lock_no_lock_kptr: __failure, __msg("local 'kptr' has no valid bpf_res_spin_lock");
}

// C: elem = bpf_map_lookup_elem(&arrmap, &(int){0}); -- a macro, not an
// #[inline(always)] fn: LLVM hoists an inlined callee's allocas to the top
// of the caller's entry block, which would put the key slot above the
// irqsave flags slots and move those (the prover pins a kfunc's pointer
// argument by its frame offset) away from the C's fp-8 / fp-16. The key is
// a function-scope local like the C's compound literal (a block-scoped one
// dies before the irqsave calls and stack coloring folds its slot into a
// flags slot). For the same reason the irq programs declare their locals
// in the reverse of the C's order: rustc gives the later-declared local
// the higher frame slot, clang the earlier one.
macro_rules! lookup_elem {
    ($elem:ident) => {
        let key: i32 = 0;
        let $elem = bpf_map_lookup_elem(&arrmap, &key) as *mut arr_elem;
    };
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn res_spin_lock_arg(_ctx: *mut __sk_buff) -> i32 {
    lookup_elem!(elem);
    if elem.is_null() {
        return 0;
    }
    unsafe {
        // C: bpf_res_spin_lock((struct bpf_res_spin_lock *)bpf_core_cast(&elem->lock, struct __sk_buff));
        bpf_res_spin_lock(
            bpf_rdonly_cast(addr_of_mut!((*elem).lock) as *const c_void, tid_sk_buff() as u32)
                as *mut bpf_res_spin_lock,
        );
        bpf_res_spin_lock(addr_of_mut!((*elem).lock));
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn res_spin_lock_AA(_ctx: *mut __sk_buff) -> i32 {
    lookup_elem!(elem);
    if elem.is_null() {
        return 0;
    }
    unsafe {
        bpf_res_spin_lock(addr_of_mut!((*elem).lock));
        bpf_res_spin_lock(addr_of_mut!((*elem).lock));
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn res_spin_lock_cond_AA(_ctx: *mut __sk_buff) -> i32 {
    lookup_elem!(elem);
    if elem.is_null() {
        return 0;
    }
    unsafe {
        if bpf_res_spin_lock(addr_of_mut!((*elem).lock)) != 0 {
            return 0;
        }
        bpf_res_spin_lock(addr_of_mut!((*elem).lock));
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn res_spin_lock_mismatch_1(_ctx: *mut __sk_buff) -> i32 {
    lookup_elem!(elem);
    if elem.is_null() {
        return 0;
    }
    unsafe {
        if bpf_res_spin_lock(addr_of_mut!((*elem).lock)) != 0 {
            return 0;
        }
        bpf_res_spin_unlock(addr_of_mut!(res_lock));
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn res_spin_lock_mismatch_2(_ctx: *mut __sk_buff) -> i32 {
    lookup_elem!(elem);
    if elem.is_null() {
        return 0;
    }
    unsafe {
        if bpf_res_spin_lock(addr_of_mut!(res_lock)) != 0 {
            return 0;
        }
        bpf_res_spin_unlock(addr_of_mut!((*elem).lock));
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn res_spin_lock_irq_mismatch_1(_ctx: *mut __sk_buff) -> i32 {
    lookup_elem!(elem);
    let mut f1 = MaybeUninit::<u64>::uninit();
    if elem.is_null() {
        return 0;
    }
    unsafe {
        bpf_local_irq_save(f1.as_mut_ptr());
        if bpf_res_spin_lock(addr_of_mut!(res_lock)) != 0 {
            return 0;
        }
        bpf_res_spin_unlock_irqrestore(addr_of_mut!(res_lock), f1.as_mut_ptr());
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn res_spin_lock_irq_mismatch_2(_ctx: *mut __sk_buff) -> i32 {
    lookup_elem!(elem);
    let mut f1 = MaybeUninit::<u64>::uninit();
    if elem.is_null() {
        return 0;
    }
    unsafe {
        if bpf_res_spin_lock_irqsave(addr_of_mut!(res_lock), f1.as_mut_ptr()) != 0 {
            return 0;
        }
        bpf_res_spin_unlock(addr_of_mut!(res_lock));
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn res_spin_lock_ooo(_ctx: *mut __sk_buff) -> i32 {
    lookup_elem!(elem);
    if elem.is_null() {
        return 0;
    }
    unsafe {
        if bpf_res_spin_lock(addr_of_mut!(res_lock)) != 0 {
            return 0;
        }
        if bpf_res_spin_lock(addr_of_mut!((*elem).lock)) != 0 {
            bpf_res_spin_unlock(addr_of_mut!(res_lock));
            return 0;
        }
        bpf_res_spin_unlock(addr_of_mut!((*elem).lock));
        bpf_res_spin_unlock(addr_of_mut!(res_lock));
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn res_spin_lock_ooo_irq(_ctx: *mut __sk_buff) -> i32 {
    lookup_elem!(elem);
    let mut f2 = MaybeUninit::<u64>::uninit();
    let mut f1 = MaybeUninit::<u64>::uninit();
    if elem.is_null() {
        return 0;
    }
    unsafe {
        if bpf_res_spin_lock_irqsave(addr_of_mut!(res_lock), f1.as_mut_ptr()) != 0 {
            return 0;
        }
        if bpf_res_spin_lock_irqsave(addr_of_mut!((*elem).lock), f2.as_mut_ptr()) != 0 {
            bpf_res_spin_unlock_irqrestore(addr_of_mut!(res_lock), f1.as_mut_ptr());
            /* We won't have a unreleased IRQ flag error here. */
            return 0;
        }
        bpf_res_spin_unlock_irqrestore(addr_of_mut!((*elem).lock), f2.as_mut_ptr());
        bpf_res_spin_unlock_irqrestore(addr_of_mut!(res_lock), f1.as_mut_ptr());
    }
    0
}

// C: struct bpf_res_spin_lock lock1 __hidden SEC(".data.OO1");
//    struct bpf_res_spin_lock lock2 __hidden SEC(".data.OO2");
#[allow(non_upper_case_globals)]
#[link_section = ".data.OO1"]
static mut lock1: bpf_res_spin_lock = bpf_res_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[link_section = ".data.OO2"]
static mut lock2: bpf_res_spin_lock = bpf_res_spin_lock { val: 0 };

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn res_spin_lock_ooo_unlock(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        if bpf_res_spin_lock(addr_of_mut!(lock1)) != 0 {
            return 0;
        }
        if bpf_res_spin_lock(addr_of_mut!(lock2)) != 0 {
            bpf_res_spin_unlock(addr_of_mut!(lock1));
            return 0;
        }
        bpf_res_spin_unlock(addr_of_mut!(lock1));
        bpf_res_spin_unlock(addr_of_mut!(lock2));
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn res_spin_lock_bad_off(_ctx: *mut __sk_buff) -> i32 {
    lookup_elem!(elem);
    if elem.is_null() {
        return 0;
    }
    // C: bpf_res_spin_lock((void *)&elem->lock + 1);
    unsafe {
        bpf_res_spin_lock((addr_of_mut!((*elem).lock) as *mut u8).add(1) as *mut bpf_res_spin_lock);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn res_spin_lock_var_off(_ctx: *mut __sk_buff) -> i32 {
    let mut val: u64 = unsafe { value } as u64;
    lookup_elem!(elem);
    if elem.is_null() {
        // FIXME: Only inline assembly use in assert macro doesn't emit
        //	  BTF definition.
        unsafe { bpf_throw(0) };
        return 0;
    }
    // C: bpf_assert_range(val, 0, 40); -- barrier_var(val), then the two
    // unsigned __bpf_assert asm blocks (`r1 = 0` is the cookie).
    unsafe {
        core::arch::asm!(
            "if {val} >= 0 goto +2;",
            "r1 = 0;",
            "call {bpf_throw};",
            "if {val} <= 40 goto +2;",
            "r1 = 0;",
            "call {bpf_throw};",
            val = inout(reg) val,
            bpf_throw = sym bpf_throw,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
        );
        // C: bpf_res_spin_lock((void *)&value + val);
        bpf_res_spin_lock((addr_of_mut!(value) as *mut u8).add(val as usize) as *mut bpf_res_spin_lock);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn res_spin_lock_no_lock_map(_ctx: *mut __sk_buff) -> i32 {
    // C: bpf_res_spin_lock((void *)&value + 1);
    unsafe {
        bpf_res_spin_lock((addr_of_mut!(value) as *mut u8).add(1) as *mut bpf_res_spin_lock);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn res_spin_lock_no_lock_kptr(_ctx: *mut __sk_buff) -> i32 {
    let p = unsafe { bpf_obj_new(anon_i_id()) } as *mut anon_i;
    if p.is_null() {
        return 0;
    }
    unsafe { bpf_res_spin_lock(p as *mut c_void as *mut bpf_res_spin_lock) };
    0
}

bpf_object!("GPL");
