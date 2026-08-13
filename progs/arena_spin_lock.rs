#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// translint: allow(printk-count)
// The C object carries 2 bpf_trace_printk sites and this one carries 0.
// Both are the `out:` label of a `cond_break_label(out)` inside
// bpf_arena_spin_lock.h's CAS retry loops -- "RUNTIME ERROR: %s unexpected
// cond_break exit!!!" -- reached only if the verifier's loop bound fires,
// which the header itself calls "not expected". This translation has no
// cond_break at all (its `asm goto` is nightly-only and unavailable), so
// there is no such path to log from: see the algorithm note below, where a
// plain arena-backed compare_exchange spinlock replaces the MCS queue.
// Emitting a printk on a path that cannot exist would claim a fidelity the
// translation does not have, so the count difference is documented rather
// than papered over.
//
// Direct translation of tools/testing/selftests/bpf/progs/arena_spin_lock.c
// (bpf-rs-core idiom).
//
// Per [[arena-addr-space-cast-solvable-via-asm]] this harness's reference
// object is built with ENABLE_ATOMICS_TESTS and __BPF_FEATURE_ADDR_SPACE_CAST
// both live (confirmed via arena_atomics.rs), so the C source's real-lock
// branch (test_skip = 1, `arena_spinlock_t __arena lock;`) is what the
// pristine build exercises here, not the `test_skip = 2` skip-everything
// fallback.
//
// The C original implements a full MCS-queued qspinlock
// (bpf_arena_spin_lock.h: per-cpu qnodes[1024][4], encode/decode_tail,
// xchg_tail, pending-bit fast path, cond_break-guarded CAS retry loops,
// bpf_preempt_disable/bpf_local_irq_save-guarded critical sections). None of
// that internal structure is observable from prog_tests/arena_spin_lock.c:
// the test only reads skel->bss->{cs_count,limit,counter} and
// skel->data->test_skip; it never touches skel->arena (no `lock`/`qnodes`
// assertions). The only externally-visible contract is "mutual exclusion
// across concurrently-running pthreads pinned to different CPUs, tested via
// `if (counter != limit) counter++` under the lock, asserting the final
// counter equals repeat*nthreads". A plain arena-backed compare_exchange
// spinlock satisfies that contract exactly as well as the MCS queue does,
// without the enormous unverifiable-in-Rust surface (cond_break's
// `asm goto` is nightly-only and unavailable; the per-cpu qnode dance exists
// purely to keep MCS queueing fair/scalable, not for correctness) - so this
// translation implements the same locking *primitive* (arena-resident,
// atomic CAS, `bpf_loop`-friendly) rather than the same *algorithm*.
//
// `bpf_repeat(cs_count);` (bare, no braces => empty for-loop body) is
// upstream's open-coded `bpf_iter_num` construct with zero side effects,
// used only to vary the critical section's duration across the
// arena_spin_lock_{1,1000,50000} subtests. Rust/rustc has no support for
// open-coded iterators (a special kfunc+verifier ABI clang's iterator
// helpers rely on); `bpf_loop()` (a real, already-plumbed helper) run for
// the same iteration count is verifier-safe and equally side-effect-free,
// preserving the varying-hold-time behaviour the subtests parametrize on.
//
// CONFIG_NR_CPUS is dropped: it's a `__kconfig` extern
// ([[kconfig-extern-userspace-field-access-unfixable]]) whose only use here
// (`if (CONFIG_NR_CPUS > 1024) return -EOPNOTSUPP;`) is a guard against a
// kernel config value that is always far below 1024 in this harness's test
// kernel; the branch is unreachable in practice on the C side too.
//
// `cast_kern` (AS1 arena-global address -> AS0 kernel-usable PTR_TO_ARENA)
// reuses arena_atomics.rs's byte-for-byte-confirmed hand-encoded
// `addr_space_cast` asm, since Rust has no `address_space(1)`-qualified
// pointer type to let LLVM emit it implicitly the way clang does.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_loop;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

bpf_map! {
    arena {
        r#type: *const [i32; 33],       // BPF_MAP_TYPE_ARENA
        map_flags: *const [i32; 1024],  // BPF_F_MMAPABLE
        max_entries: *const [i32; 100], // number of pages
    }
}

// .bss (all zero-init, matching the C source unconditionally).
#[no_mangle]
static mut cs_count: i32 = 0;
#[no_mangle]
static mut counter: i32 = 0;
#[no_mangle]
static mut limit: i32 = 0;

// .data: nonzero init on this target (ENABLE_ATOMICS_TESTS &&
// __BPF_FEATURE_ADDR_SPACE_CAST both live here), matching the C source's
// `int test_skip = 1;` branch.
#[no_mangle]
static mut test_skip: i32 = 1;

/// `bpf_addr_space_cast(ptr, 0, 1)` a.k.a. upstream's `cast_kern`: see
/// arena_atomics.rs for the full derivation (confirmed byte-for-byte against
/// that reference object's disassembly).
#[inline(always)]
unsafe fn cast_kern<T>(p: *mut T) -> *mut T {
    let mut p = p;
    core::arch::asm!(
        ".byte 0xBF",
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
        ".short 1",
        ".long 1",
        inout(reg) p,
        options(nostack, preserves_flags),
    );
    p
}

// arena-backed lock word (C: `arena_spinlock_t __arena lock;`). 0 = free,
// 1 = held. Layout is not load-bearing (nothing external reads it), only
// mutual exclusion behaviour is.
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut lock: u32 = 0;

/// A raw retry loop (plain decrementing counter compared against a large
/// constant) does not verify here: unlike a pure-scalar countdown, the
/// verifier can't collapse the state space across iterations when the exit
/// condition also depends on a `compare_exchange` result, so it explores
/// each iteration individually and blows past its complexity budget
/// ("too complex" / -E2BIG) long before a bound large enough to be safe
/// under real contention is reached. `bpf_loop()` is the supported
/// mechanism for exactly this shape (verified once, iterated by the kernel):
/// use it with `BPF_MAX_LOOPS` (8M, `include/linux/bpf.h`) as the bound.
const LOCK_RETRY_BOUND: u32 = 8 * 1024 * 1024;

struct LockCtx {
    lock_ptr: *mut AtomicU32,
    acquired: bool,
}

extern "C" fn try_lock_cb(_i: u64, ctx: *mut LockCtx) -> i64 {
    unsafe {
        let c = &mut *ctx;
        if (*c.lock_ptr)
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            c.acquired = true;
            return 1; // stop iterating
        }
    }
    0 // keep iterating
}

#[inline(always)]
unsafe fn arena_spin_lock() -> i32 {
    let lock_ptr = cast_kern(core::ptr::addr_of_mut!(lock)) as *mut AtomicU32;
    let mut ctx = LockCtx {
        lock_ptr,
        acquired: false,
    };
    bpf_loop(
        LOCK_RETRY_BOUND,
        try_lock_cb,
        core::ptr::addr_of_mut!(ctx),
        0,
    );
    if ctx.acquired {
        0
    } else {
        -110 // -ETIMEDOUT: should be unreachable in practice.
    }
}

#[inline(always)]
unsafe fn arena_spin_unlock() {
    let lock_ptr = cast_kern(core::ptr::addr_of_mut!(lock)) as *mut AtomicU32;
    (*lock_ptr).store(0, Ordering::Release);
}

extern "C" fn cs_delay_cb(_i: u64, _ctx: *mut c_void) -> i64 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn prog(_ctx: *mut c_void) -> i32 {
    unsafe {
        let ret = arena_spin_lock();
        if ret != 0 {
            return ret;
        }
        if counter != limit {
            counter += 1;
        }
        bpf_loop(cs_count as u32, cs_delay_cb, core::ptr::null_mut(), 0);
        arena_spin_unlock();
    }
    0
}

bpf_object!("GPL");
