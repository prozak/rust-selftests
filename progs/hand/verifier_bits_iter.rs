// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_bits_iter.c, translated
// by hand; include!d by the generated progs/verifier_bits_iter.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: no_destroy -- translate the C below (see the file comment)
//   SEC("iter.s/cgroup")
//   __description("bits iter without destroy")
//   __failure __msg("Unreleased reference")
//   int BPF_PROG(no_destroy, struct bpf_iter_meta *meta, struct cgroup *cgrp)
//   {
//       struct bpf_iter_bits it;
//       u64 data = 1;
//
//       bpf_iter_bits_new(&it, &data, 1);
//       bpf_iter_bits_next(&it);
//       return 0;
//   }
#[link_section = "iter.s/cgroup"]
#[no_mangle]
extern "C" fn no_destroy(_ctx: *mut u64) -> i32 {
    // the C's frame: `it` above `data` (rustc places the last local highest)
    let mut data: u64 = 1;
    let mut it = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    unsafe {
        bpf_iter_bits_new(it.as_mut_ptr() as *mut c_void, &mut data as *mut u64 as *mut c_void, 1);
        bpf_iter_bits_next(it.as_mut_ptr() as *mut c_void);
    }
    0
}

// HAND: next_uninit -- translate the C below (see the file comment)
//   SEC("iter/cgroup")
//   __description("uninitialized iter in ->next()")
//   __failure __msg("expected an initialized iter_bits as R1")
//   int BPF_PROG(next_uninit, struct bpf_iter_meta *meta, struct cgroup *cgrp)
//   {
//       struct bpf_iter_bits it = {};
//
//       bpf_iter_bits_next(&it);
//       return 0;
//   }
#[link_section = "iter/cgroup"]
#[no_mangle]
extern "C" fn next_uninit(_ctx: *mut u64) -> i32 {
    let mut it: [u64; 2] = [0; 2];
    unsafe { bpf_iter_bits_next(it.as_mut_ptr() as *mut c_void) };
    0
}

// HAND: destroy_uninit -- translate the C below (see the file comment)
//   SEC("iter/cgroup")
//   __description("uninitialized iter in ->destroy()")
//   __failure __msg("expected an initialized iter_bits as R1")
//   int BPF_PROG(destroy_uninit, struct bpf_iter_meta *meta, struct cgroup *cgrp)
//   {
//       struct bpf_iter_bits it = {};
//
//       bpf_iter_bits_destroy(&it);
//       return 0;
//   }
#[link_section = "iter/cgroup"]
#[no_mangle]
extern "C" fn destroy_uninit(_ctx: *mut u64) -> i32 {
    let mut it: [u64; 2] = [0; 2];
    unsafe { bpf_iter_bits_destroy(it.as_mut_ptr() as *mut c_void) };
    0
}

// HAND: null_pointer -- translate the C below (see the file comment)
//   SEC("syscall")
//   __description("null pointer")
//   __success __retval(0)
//   int null_pointer(void)
//   {
//       struct bpf_iter_bits iter;
//       int err, nr = 0;
//       int *bit;
//
//       err = bpf_iter_bits_new(&iter, NULL, 1);
//       bpf_iter_bits_destroy(&iter);
//       if (err != -EINVAL)
//           return 1;
//
//       bpf_for_each(bits, bit, NULL, 1)
//           nr++;
//       return nr;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn null_pointer() -> i32 {
    let mut iter = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    let mut nr: i32 = 0;

    let err = unsafe { bpf_iter_bits_new(iter.as_mut_ptr() as *mut c_void, core::ptr::null_mut(), 1) };
    unsafe { bpf_iter_bits_destroy(iter.as_mut_ptr() as *mut c_void) };
    if err != -22 {
        // -EINVAL
        return 1;
    }

    // bpf_for_each(bits, bit, NULL, 1)
    let mut it = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    unsafe {
        bpf_iter_bits_new(it.as_mut_ptr() as *mut c_void, core::ptr::null_mut(), 1);
        loop {
            let bit = bpf_iter_bits_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if bit.is_null() {
                break;
            }
            nr += 1;
        }
        bpf_iter_bits_destroy(it.as_mut_ptr() as *mut c_void);
    }
    nr
}

// HAND: bits_copy -- translate the C below (see the file comment)
//   SEC("syscall")
//   __description("bits copy")
//   __success __retval(10)
//   int bits_copy(void)
//   {
//       u64 data = 0xf7310UL; /* 4 + 3 + 2 + 1 + 0*/
//       int nr = 0;
//       int *bit;
//
//       bpf_for_each(bits, bit, &data, 1)
//           nr++;
//       return nr;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn bits_copy() -> i32 {
    let mut data: u64 = 0xf7310; // 4 + 3 + 2 + 1 + 0
    let mut nr: i32 = 0;
    // bpf_for_each(bits, bit, &data, 1)
    let mut it = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    unsafe {
        bpf_iter_bits_new(it.as_mut_ptr() as *mut c_void, &mut data as *mut u64 as *mut c_void, 1);
        loop {
            let bit = bpf_iter_bits_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if bit.is_null() {
                break;
            }
            nr += 1;
        }
        bpf_iter_bits_destroy(it.as_mut_ptr() as *mut c_void);
    }
    nr
}

// HAND: bits_memalloc -- translate the C below (see the file comment)
//   SEC("syscall")
//   __description("bits memalloc")
//   __success __retval(64)
//   int bits_memalloc(void)
//   {
//       u64 data[2];
//       int nr = 0;
//       int *bit;
//
//       __builtin_memset(&data, 0xf0, sizeof(data)); /* 4 * 16 */
//       bpf_for_each(bits, bit, &data[0], ARRAY_SIZE(data))
//           nr++;
//       return nr;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn bits_memalloc() -> i32 {
    let mut data: [u64; 2] = [0xf0f0f0f0f0f0f0f0; 2]; // memset 0xf0: 4 * 16
    let mut nr: i32 = 0;
    // bpf_for_each(bits, bit, &data[0], ARRAY_SIZE(data))
    let mut it = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    unsafe {
        bpf_iter_bits_new(it.as_mut_ptr() as *mut c_void, data.as_mut_ptr() as *mut c_void, 2);
        loop {
            let bit = bpf_iter_bits_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if bit.is_null() {
                break;
            }
            nr += 1;
        }
        bpf_iter_bits_destroy(it.as_mut_ptr() as *mut c_void);
    }
    nr
}

// HAND: bit_index -- translate the C below (see the file comment)
//   SEC("syscall")
//   __description("bit index")
//   __success __retval(8)
//   int bit_index(void)
//   {
//       u64 data = 0x100;
//       int bit_idx = 0;
//       int *bit;
//
//       bpf_for_each(bits, bit, &data, 1) {
//           if (*bit == 0)
//               continue;
//           bit_idx = *bit;
//       }
//       return bit_idx;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn bit_index() -> i32 {
    let mut data: u64 = 0x100;
    let mut bit_idx: i32 = 0;
    // bpf_for_each(bits, bit, &data, 1)
    let mut it = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    unsafe {
        bpf_iter_bits_new(it.as_mut_ptr() as *mut c_void, &mut data as *mut u64 as *mut c_void, 1);
        loop {
            let bit = bpf_iter_bits_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if bit.is_null() {
                break;
            }
            if *bit == 0 {
                continue;
            }
            bit_idx = *bit;
        }
        bpf_iter_bits_destroy(it.as_mut_ptr() as *mut c_void);
    }
    bit_idx
}

// HAND: bits_too_big -- translate the C below (see the file comment)
//   SEC("syscall")
//   __description("bits too big")
//   __success __retval(0)
//   int bits_too_big(void)
//   {
//       u64 data[4];
//       int nr = 0;
//       int *bit;
//
//       __builtin_memset(&data, 0xff, sizeof(data));
//       bpf_for_each(bits, bit, &data[0], 512) /* Be greater than 511 */
//           nr++;
//       return nr;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn bits_too_big() -> i32 {
    let mut data: [u64; 4] = [0xffffffffffffffff; 4]; // memset 0xff
    let mut nr: i32 = 0;
    // bpf_for_each(bits, bit, &data[0], 512)
    let mut it = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    unsafe {
        bpf_iter_bits_new(it.as_mut_ptr() as *mut c_void, data.as_mut_ptr() as *mut c_void, 512);
        loop {
            let bit = bpf_iter_bits_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if bit.is_null() {
                break;
            }
            nr += 1;
        }
        bpf_iter_bits_destroy(it.as_mut_ptr() as *mut c_void);
    }
    nr
}

// HAND: fewer_words -- translate the C below (see the file comment)
//   SEC("syscall")
//   __description("fewer words")
//   __success __retval(1)
//   int fewer_words(void)
//   {
//       u64 data[2] = {0x1, 0xff};
//       int nr = 0;
//       int *bit;
//
//       bpf_for_each(bits, bit, &data[0], 1)
//           nr++;
//       return nr;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn fewer_words() -> i32 {
    let mut data: [u64; 2] = [0x1, 0xff];
    let mut nr: i32 = 0;
    // bpf_for_each(bits, bit, &data[0], 1)
    let mut it = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    unsafe {
        bpf_iter_bits_new(it.as_mut_ptr() as *mut c_void, data.as_mut_ptr() as *mut c_void, 1);
        loop {
            let bit = bpf_iter_bits_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if bit.is_null() {
                break;
            }
            nr += 1;
        }
        bpf_iter_bits_destroy(it.as_mut_ptr() as *mut c_void);
    }
    nr
}

// HAND: zero_words -- translate the C below (see the file comment)
//   SEC("syscall")
//   __description("zero words")
//   __success __retval(0)
//   int zero_words(void)
//   {
//       u64 data[2] = {0x1, 0xff};
//       int nr = 0;
//       int *bit;
//
//       bpf_for_each(bits, bit, &data[0], 0)
//           nr++;
//       return nr;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn zero_words() -> i32 {
    let mut data: [u64; 2] = [0x1, 0xff];
    let mut nr: i32 = 0;
    // bpf_for_each(bits, bit, &data[0], 0)
    let mut it = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    unsafe {
        bpf_iter_bits_new(it.as_mut_ptr() as *mut c_void, data.as_mut_ptr() as *mut c_void, 0);
        loop {
            let bit = bpf_iter_bits_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if bit.is_null() {
                break;
            }
            nr += 1;
        }
        bpf_iter_bits_destroy(it.as_mut_ptr() as *mut c_void);
    }
    nr
}

// HAND: huge_words -- translate the C below (see the file comment)
//   SEC("syscall")
//   __description("huge words")
//   __success __retval(0)
//   int huge_words(void)
//   {
//       u64 data[8] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1};
//       int nr = 0;
//       int *bit;
//
//       bpf_for_each(bits, bit, &data[0], 67108865)
//           nr++;
//       return nr;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn huge_words() -> i32 {
    let mut data: [u64; 8] = [0x1; 8];
    let mut nr: i32 = 0;
    // bpf_for_each(bits, bit, &data[0], 67108865)
    let mut it = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    unsafe {
        bpf_iter_bits_new(it.as_mut_ptr() as *mut c_void, data.as_mut_ptr() as *mut c_void, 67108865);
        loop {
            let bit = bpf_iter_bits_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if bit.is_null() {
                break;
            }
            nr += 1;
        }
        bpf_iter_bits_destroy(it.as_mut_ptr() as *mut c_void);
    }
    nr
}

// HAND: max_words -- translate the C below (see the file comment)
//   SEC("syscall")
//   __description("max words")
//   __success __retval(4)
//   int max_words(void)
//   {
//       volatile int nr = 0;
//       int *bit;
//
//       bits_array[0] = (1ULL << 63) | 1U;
//       bits_array[510] = (1ULL << 33) | (1ULL << 32);
//
//       bpf_for_each(bits, bit, bits_array, 511) {
//           if (nr == 0 && *bit != 0)
//               break;
//           if (nr == 2 && *bit != 32672)
//               break;
//           nr++;
//       }
//       return nr;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn max_words() -> i32 {
    // volatile int nr
    let mut nr: i32 = 0;
    unsafe {
        core::ptr::write_volatile(&mut nr, 0);
        *core::ptr::addr_of_mut!(bits_array).cast::<u64>().add(0) = (1u64 << 63) | 1;
        *core::ptr::addr_of_mut!(bits_array).cast::<u64>().add(510) = (1u64 << 33) | (1u64 << 32);
    }

    // bpf_for_each(bits, bit, bits_array, 511)
    let mut it = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    unsafe {
        bpf_iter_bits_new(it.as_mut_ptr() as *mut c_void, core::ptr::addr_of_mut!(bits_array) as *mut c_void, 511);
        loop {
            let bit = bpf_iter_bits_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if bit.is_null() {
                break;
            }
            if core::ptr::read_volatile(&nr) == 0 && *bit != 0 {
                break;
            }
            if core::ptr::read_volatile(&nr) == 2 && *bit != 32672 {
                break;
            }
            core::ptr::write_volatile(&mut nr, core::ptr::read_volatile(&nr) + 1);
        }
        bpf_iter_bits_destroy(it.as_mut_ptr() as *mut c_void);
    }
    unsafe { core::ptr::read_volatile(&nr) }
}

// HAND: bad_words -- translate the C below (see the file comment)
//   SEC("syscall")
//   __description("bad words")
//   __success __retval(0)
//   int bad_words(void)
//   {
//       void *bad_addr = (void *)-4095;
//       struct bpf_iter_bits iter;
//       volatile int nr;
//       int *bit;
//       int err;
//
//       err = bpf_iter_bits_new(&iter, bad_addr, 1);
//       bpf_iter_bits_destroy(&iter);
//       if (err != -EFAULT)
//           return 1;
//
//       nr = 0;
//       bpf_for_each(bits, bit, bad_addr, 1)
//           nr++;
//       if (nr != 0)
//           return 2;
//
//       err = bpf_iter_bits_new(&iter, bad_addr, 4);
//       bpf_iter_bits_destroy(&iter);
//       if (err != -EFAULT)
//           return 3;
//
//       nr = 0;
//       bpf_for_each(bits, bit, bad_addr, 4)
//           nr++;
//       if (nr != 0)
//           return 4;
//
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn bad_words() -> i32 {
    let bad_addr = (-4095isize) as *mut c_void;
    let mut iter = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    // volatile int nr
    let mut nr: i32 = 0;

    let err = unsafe { bpf_iter_bits_new(iter.as_mut_ptr() as *mut c_void, bad_addr, 1) };
    unsafe { bpf_iter_bits_destroy(iter.as_mut_ptr() as *mut c_void) };
    if err != -14 {
        // -EFAULT
        return 1;
    }

    unsafe { core::ptr::write_volatile(&mut nr, 0) };
    let mut it = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    unsafe {
        bpf_iter_bits_new(it.as_mut_ptr() as *mut c_void, bad_addr, 1);
        loop {
            let bit = bpf_iter_bits_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if bit.is_null() {
                break;
            }
            core::ptr::write_volatile(&mut nr, core::ptr::read_volatile(&nr) + 1);
        }
        bpf_iter_bits_destroy(it.as_mut_ptr() as *mut c_void);
    }
    if unsafe { core::ptr::read_volatile(&nr) } != 0 {
        return 2;
    }

    let err = unsafe { bpf_iter_bits_new(iter.as_mut_ptr() as *mut c_void, bad_addr, 4) };
    unsafe { bpf_iter_bits_destroy(iter.as_mut_ptr() as *mut c_void) };
    if err != -14 {
        return 3;
    }

    unsafe { core::ptr::write_volatile(&mut nr, 0) };
    let mut it = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    unsafe {
        bpf_iter_bits_new(it.as_mut_ptr() as *mut c_void, bad_addr, 4);
        loop {
            let bit = bpf_iter_bits_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if bit.is_null() {
                break;
            }
            core::ptr::write_volatile(&mut nr, core::ptr::read_volatile(&nr) + 1);
        }
        bpf_iter_bits_destroy(it.as_mut_ptr() as *mut c_void);
    }
    if unsafe { core::ptr::read_volatile(&nr) } != 0 {
        return 4;
    }

    0
}
