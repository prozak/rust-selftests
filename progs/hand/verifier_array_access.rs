// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_array_access.c, translated
// by hand; include!d by the generated progs/verifier_array_access.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::{bpf_get_prandom_u32, bpf_map_lookup_elem, bpf_probe_read_user};

/// `__u32 __attribute__((aligned(8))) key`: the key at an 8-aligned stack
/// slot, written as the one u32 store the verifier's constant-key elision
/// looks for (a struct literal would store the padding too, as a u64).
#[repr(C, align(8))]
struct Key8 {
    k: u32,
}

/// `let key = key8!(v)`: the slot, written in place with one volatile u32
/// store, so the stores keep their source order (a __msg names them).
macro_rules! key8 {
    ($name:ident, $v:expr) => {
        let mut $name = core::mem::MaybeUninit::<Key8>::uninit();
        unsafe { core::ptr::addr_of_mut!((*$name.as_mut_ptr()).k).write_volatile($v) };
    };
}

#[inline(always)]
fn key8_ref(key: &core::mem::MaybeUninit<Key8>) -> &u32 {
    unsafe { &(*key.as_ptr()).k }
}

// HAND: an_array_with_a_constant_no_nullness -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("valid map access into an array using constant without nullness")
//   __success __retval(4) __log_level(2)
//   __msg("mark_precise: frame0: regs= stack=-8 before {{[0-9]}}: ({{[a-f0-9]+}}) *(u32 *)(r10 -8) = {{(1|r[0-9])}}")
//   unsigned int an_array_with_a_constant_no_nullness(void)
//   {
//       /* Need 8-byte alignment for spill tracking */
//       __u32 __attribute__((aligned(8))) key = 1;
//       struct test_val *val;
//
//       val = bpf_map_lookup_elem(&map_array, &key);
//       val->index = offsetof(struct test_val, foo);
//
//       return val->index;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn an_array_with_a_constant_no_nullness() -> u32 {
    key8!(key, 1);
    let val = bpf_map_lookup_elem(&map_array, key8_ref(&key)) as *mut test_val;
    unsafe {
        (*val).index = 4; // offsetof(struct test_val, foo)
        (*val).index
    }
}

// HAND: multiple_array_with_a_constant_no_nullness -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("valid multiple map access into an array using constant without nullness")
//   __success __retval(8) __log_level(2)
//   __msg("mark_precise: frame0: regs= stack=-8 before {{[0-9]}}: ({{[a-f0-9]+}}) *(u32 *)(r10 -16) = {{(0|r[0-9])}}")
//   __msg("mark_precise: frame0: regs= stack=-8 before {{[0-9]}}: ({{[a-f0-9]+}}) *(u32 *)(r10 -8) = {{(1|r[0-9])}}")
//   unsigned int multiple_array_with_a_constant_no_nullness(void)
//   {
//       __u32 __attribute__((aligned(8))) key = 1;
//       __u32 __attribute__((aligned(8))) key2 = 0;
//       struct test_val *val, *val2;
//
//       val = bpf_map_lookup_elem(&map_array, &key);
//       val->index = offsetof(struct test_val, foo);
//
//       val2 = bpf_map_lookup_elem(&map_array, key8_ref(&key2));
//       val2->index = offsetof(struct test_val, foo);
//
//       return val->index + val2->index;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn multiple_array_with_a_constant_no_nullness() -> u32 {
    // The __msg names the slots and the store order: key at fp-8 stored
    // first, key2 at fp-16 second. rustc's frame puts the last local at
    // fp-8 (clang the first), so key2 is declared first but written second.
    let mut key2 = core::mem::MaybeUninit::<Key8>::uninit();
    key8!(key, 1);
    unsafe { core::ptr::addr_of_mut!((*key2.as_mut_ptr()).k).write_volatile(0) };
    let val = bpf_map_lookup_elem(&map_array, key8_ref(&key)) as *mut test_val;
    unsafe { (*val).index = 4 }; // offsetof(struct test_val, foo)
    let val2 = bpf_map_lookup_elem(&map_array, key8_ref(&key2)) as *mut test_val;
    unsafe {
        (*val2).index = 4;
        (*val).index.wrapping_add((*val2).index)
    }
}

// HAND: an_array_with_a_32bit_constant_0_no_nullness -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("valid map access into an array using natural aligned 32-bit constant 0 without nullness")
//   __success __retval(4)
//   unsigned int an_array_with_a_32bit_constant_0_no_nullness(void)
//   {
//       /* Unlike the above tests, 32-bit zeroing is precisely tracked even
//        * if writes are not aligned to BPF_REG_SIZE. This tests that our
//        * STACK_ZERO handling functions.
//        */
//       struct test_val *val;
//       __u32 key = 0;
//
//       val = bpf_map_lookup_elem(&map_array, &key);
//       val->index = offsetof(struct test_val, foo);
//
//       return val->index;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn an_array_with_a_32bit_constant_0_no_nullness() -> u32 {
    let key: u32 = 0;
    let val = bpf_map_lookup_elem(&map_array, &key) as *mut test_val;
    unsafe {
        (*val).index = 4; // offsetof(struct test_val, foo)
        (*val).index
    }
}

// HAND: a_pcpu_array_with_a_constant_no_nullness -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("valid map access into a pcpu array using constant without nullness")
//   __success __retval(4) __log_level(2)
//   __msg("mark_precise: frame0: regs= stack=-8 before {{[0-9]}}: ({{[a-f0-9]+}}) *(u32 *)(r10 -8) = {{(1|r[0-9])}}")
//   unsigned int a_pcpu_array_with_a_constant_no_nullness(void)
//   {
//       __u32 __attribute__((aligned(8))) key = 1;
//       struct test_val *val;
//
//       val = bpf_map_lookup_elem(&map_array_pcpu, &key);
//       val->index = offsetof(struct test_val, foo);
//
//       return val->index;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn a_pcpu_array_with_a_constant_no_nullness() -> u32 {
    key8!(key, 1);
    let val = bpf_map_lookup_elem(&map_array_pcpu, key8_ref(&key)) as *mut test_val;
    unsafe {
        (*val).index = 4; // offsetof(struct test_val, foo)
        (*val).index
    }
}

// HAND: an_array_with_a_constant_no_nullness_out_of_bounds -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("invalid map access into an array using constant without nullness")
//   __failure __msg("R0 invalid mem access 'map_value_or_null'")
//   unsigned int an_array_with_a_constant_no_nullness_out_of_bounds(void)
//   {
//       /* Out of bounds */
//       __u32 __attribute__((aligned(8))) key = 3;
//       struct test_val *val;
//
//       val = bpf_map_lookup_elem(&map_array, &key);
//       val->index = offsetof(struct test_val, foo);
//
//       return val->index;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn an_array_with_a_constant_no_nullness_out_of_bounds() -> u32 {
    key8!(key, 3);
    let val = bpf_map_lookup_elem(&map_array, key8_ref(&key)) as *mut test_val;
    unsafe {
        (*val).index = 4; // offsetof(struct test_val, foo)
        (*val).index
    }
}

// HAND: an_array_with_a_constant_too_small -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("invalid map access into an array using constant smaller than key_size")
//   __failure __msg("R0 invalid mem access 'map_value_or_null'")
//   unsigned int an_array_with_a_constant_too_small(void)
//   {
//       __u32 __attribute__((aligned(8))) key;
//       struct test_val *val;
//
//       /* Mark entire key as STACK_MISC */
//       bpf_probe_read_user(&key, sizeof(key), NULL);
//
//       /* Spilling only the bottom byte results in a tnum const of 1.
//        * We want to check that the verifier rejects it, as the spill is < 4B.
//        */
//       *(__u8 *)&key = 1;
//       val = bpf_map_lookup_elem(&map_array, &key);
//
//       /* Should fail, as verifier cannot prove in-bound lookup */
//       val->index = offsetof(struct test_val, foo);
//
//       return val->index;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn an_array_with_a_constant_too_small() -> u32 {
    let mut key = core::mem::MaybeUninit::<Key8>::uninit();
    // mark the entire key as STACK_MISC, then spill only its bottom byte
    bpf_probe_read_user(key.as_mut_ptr() as *mut c_void, 4, core::ptr::null());
    unsafe { (key.as_mut_ptr() as *mut u8).write(1) };
    let val = bpf_map_lookup_elem(&map_array, key8_ref(&key)) as *mut test_val;
    unsafe {
        (*val).index = 4; // offsetof(struct test_val, foo)
        (*val).index
    }
}

// HAND: an_array_with_a_constant_too_big -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("invalid map access into an array using constant larger than key_size")
//   __failure __msg("R0 invalid mem access 'map_value_or_null'")
//   unsigned int an_array_with_a_constant_too_big(void)
//   {
//       struct test_val *val;
//       __u64 key = 1;
//
//       /* Even if the constant value is < max_entries, if the spill size is
//        * larger than the key size, the set bits may not be where we expect them
//        * to be on different endian architectures.
//        */
//       val = bpf_map_lookup_elem(&map_array, &key);
//       val->index = offsetof(struct test_val, foo);
//
//       return val->index;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn an_array_with_a_constant_too_big() -> u32 {
    let key: u64 = 1;
    let val = bpf_map_lookup_elem(&map_array, &key) as *mut test_val;
    unsafe {
        (*val).index = 4; // offsetof(struct test_val, foo)
        (*val).index
    }
}

// HAND: mixed_const_and_non_const_key_lookup -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("invalid elided lookup using const and non-const key")
//   __failure __msg("R0 invalid mem access 'map_value_or_null'")
//   unsigned int mixed_const_and_non_const_key_lookup(void)
//   {
//       __u32 __attribute__((aligned(8))) key;
//       struct test_val *val;
//       __u32 rand;
//
//       rand = bpf_get_prandom_u32();
//       key = rand > 42 ? 1 : rand;
//       val = bpf_map_lookup_elem(&map_array, &key);
//
//       return val->index;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn mixed_const_and_non_const_key_lookup() -> u32 {
    let rand = bpf_get_prandom_u32();
    key8!(key, if rand > 42 { 1 } else { rand });
    let val = bpf_map_lookup_elem(&map_array, key8_ref(&key)) as *mut test_val;
    unsafe { (*val).index }
}

// HAND: non_stack_key_lookup -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("invalid elided lookup using non-stack key")
//   __failure __msg("R0 invalid mem access 'map_value_or_null'")
//   unsigned int non_stack_key_lookup(void)
//   {
//       struct test_val *val;
//
//       global_key = 1;
//       val = bpf_map_lookup_elem(&map_array, (void *)&global_key);
//       val->index = offsetof(struct test_val, foo);
//
//       return val->index;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn non_stack_key_lookup() -> u32 {
    unsafe {
        global_key = 1;
        let val = bpf_map_lookup_elem(&map_array, &*core::ptr::addr_of!(global_key)) as *mut test_val;
        (*val).index = 4; // offsetof(struct test_val, foo)
        (*val).index
    }
}

// HAND: doesnt_reject_irrelevant_maps -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("doesn't reject UINT64_MAX as s64 for irrelevant maps")
//   __success __retval(42)
//   unsigned int doesnt_reject_irrelevant_maps(void)
//   {
//       __u64 key = 0xFFFFFFFFFFFFFFFF;
//       struct test_val *val;
//
//       val = bpf_map_lookup_elem(&map_hash_48b, &key);
//       if (val)
//           return val->index;
//
//       return 42;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn doesnt_reject_irrelevant_maps() -> u32 {
    let key: u64 = 0xFFFFFFFFFFFFFFFF;
    let val = bpf_map_lookup_elem(&map_hash_48b, &key) as *mut test_val;
    if !val.is_null() {
        return unsafe { (*val).index };
    }
    42
}
