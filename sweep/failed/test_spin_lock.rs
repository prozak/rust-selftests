#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_spin_lock.c
// (bpf-rs-core idiom).
//
// The __failure spin_lock_fail_tests table in prog_tests/spin_lock.c is
// driven by a *different* object (test_spin_lock_fail.c) and is out of
// scope here; this file only has to satisfy test_spin_lock_success(),
// which loads every autoloaded program below and exercises
// bpf_spin_lock_test concurrently from four threads.

use bpf_rs_core::bpf_map;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_get_local_storage, bpf_ktime_get_ns, bpf_map_lookup_elem, bpf_map_update_elem,
    bpf_spin_lock, bpf_spin_unlock,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, vload, vstore};

// struct bpf_spin_lock { __u32 val; };  -- matched by BTF struct name.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct hmap_elem {
    cnt: i32, // volatile int cnt
    lock: bpf_spin_lock,
    test_padding: i32,
}

// struct bpf_cgroup_storage_key (UAPI linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_cgroup_storage_key {
    cgroup_inode_id: u64,
    attach_type: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct cls_elem {
    lock: bpf_spin_lock,
    cnt: i32, // volatile int cnt
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_vqueue {
    lock: bpf_spin_lock,
    // 4 byte hole (Rust's repr(C) inserts it automatically to align lasttime)
    lasttime: u64,
    credit: i32,
    rate: u32,
}

#[link_section = ".maps"]
#[no_mangle]
static hmap: BpfMap<i32, hmap_elem, { maps::HASH }, 1> = BpfMap::new();

// No __uint(max_entries, ...) in the C source: BPF_MAP_TYPE_CGROUP_STORAGE
// is sized implicitly, so this needs the bpf_map! escape hatch rather than
// the BpfMap<K, V, TYPE, MAX> generic.
bpf_map! {
    cls_map {
        r#type: *const [i32; 19], // BPF_MAP_TYPE_CGROUP_STORAGE
        key: *const bpf_cgroup_storage_key,
        value: *const cls_elem,
    }
}

#[link_section = ".maps"]
#[no_mangle]
static vqueue: BpfMap<i32, bpf_vqueue, { maps::ARRAY }, 1> = BpfMap::new();

const CREDIT_PER_NS_SHIFT: u32 = 20;
const MAX_CREDIT: i32 = 100;
const PKT_LEN: i32 = 64;

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
extern "C" fn bpf_spin_lock_test(_skb: *const __sk_buff) -> i32 {
    let key: i32 = 0;
    let mut err: i32 = 0;
    let zero = hmap_elem {
        cnt: 0,
        lock: bpf_spin_lock { val: 0 },
        test_padding: 0,
    };

    let mut val = bpf_map_lookup_elem(&hmap, &key) as *mut hmap_elem;
    if val.is_null() {
        bpf_map_update_elem(&hmap, &key, &zero, 0);
        val = bpf_map_lookup_elem(&hmap, &key) as *mut hmap_elem;
        if val.is_null() {
            return 1;
        }
    }

    // spin_lock in hash map run time test
    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!((*val).lock));
    }
    if vload!((*val).cnt) != 0 {
        vstore!((*val).cnt, vload!((*val).cnt) - 1);
    } else {
        vstore!((*val).cnt, vload!((*val).cnt) + 1);
    }
    if vload!((*val).cnt) != 0 && vload!((*val).cnt) != 1 {
        err = 1;
    }
    unsafe {
        bpf_spin_unlock(core::ptr::addr_of_mut!((*val).lock));
    }

    // spin_lock in array. virtual queue demo
    let q = bpf_map_lookup_elem(&vqueue, &key) as *mut bpf_vqueue;
    if q.is_null() {
        return err;
    }
    let curtime = bpf_ktime_get_ns();
    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!((*q).lock));
    }
    unsafe {
        let delta = curtime.wrapping_sub((*q).lasttime);
        let credit_per_ns = ((delta.wrapping_mul((*q).rate as u64)) >> CREDIT_PER_NS_SHIFT) as i32;
        (*q).credit = (*q).credit.wrapping_add(credit_per_ns);
        (*q).lasttime = curtime;
        if (*q).credit > MAX_CREDIT {
            (*q).credit = MAX_CREDIT;
        }
        (*q).credit -= PKT_LEN;
    }
    unsafe {
        bpf_spin_unlock(core::ptr::addr_of_mut!((*q).lock));
    }

    // C sinks `credit` (a copy of q->credit taken under the lock) here via
    // __sink() purely to stop the compiler treating the preceding
    // arithmetic as dead code. Every one of those stores lands in `*q`, a
    // BPF map value reached through an opaque helper-returned pointer —
    // LLVM cannot prove such a store dead, so the local copy and its sink
    // are redundant here and are dropped rather than reproducing the
    // zero-instruction-asm/.BTF.ext line_info clash `sink_val` triggers
    // when it lands immediately before another statement's first insn.

    // spin_lock in cgroup local storage
    let cls = bpf_get_local_storage(&cls_map, 0) as *mut cls_elem;
    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!((*cls).lock));
        vstore!((*cls).cnt, vload!((*cls).cnt) + 1);
        bpf_spin_unlock(core::ptr::addr_of_mut!((*cls).lock));
    }

    err
}

// C: `struct bpf_spin_lock lockA __hidden SEC(".data.A");` — `__hidden`
// gives lockA STV_HIDDEN ELF visibility, which libbpf's
// bpf_object__collect_externs/fixup explicitly downgrades to BTF_VAR_STATIC
// (see libbpf.c's STV_HIDDEN override); map_is_mmapable() then sees no
// non-static member in the datasec and leaves ".data.A" un-mmapable.
// Rust has no per-item ELF-visibility attribute, so instead a plain
// private (non-#[no_mangle]) `static mut` is used: it never becomes an
// external symbol at all, so it gets the same effective BTF_VAR_STATIC
// linkage without needing the hidden-visibility trick. lockA is never
// referenced outside this file, so nothing depends on it being a real
// global symbol.
#[allow(non_upper_case_globals)]
#[link_section = ".data.A"]
static mut lockA: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[no_mangle]
#[inline(never)]
extern "C" fn static_subprog(ctx: *const __sk_buff) -> i32 {
    let ret: i32 = 0;

    if vload!((*ctx).protocol) != 0 {
        return ret;
    }
    ret + vload!((*ctx).len) as i32
}

#[no_mangle]
#[inline(never)]
extern "C" fn static_subprog_lock(ctx: *const __sk_buff) -> i32 {
    let ret = static_subprog(ctx);

    bpf_spin_lock(core::ptr::addr_of_mut!(lockA));
    ret + vload!((*ctx).len) as i32
}

#[no_mangle]
#[inline(never)]
extern "C" fn static_subprog_unlock(ctx: *const __sk_buff) -> i32 {
    let ret = static_subprog(ctx);

    bpf_spin_unlock(core::ptr::addr_of_mut!(lockA));
    ret + vload!((*ctx).len) as i32
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn lock_static_subprog_call(ctx: *const __sk_buff) -> i32 {
    let mut ret: i32 = 0;

    bpf_spin_lock(core::ptr::addr_of_mut!(lockA));
    if vload!((*ctx).mark) == 42 {
        ret = static_subprog(ctx);
    }
    bpf_spin_unlock(core::ptr::addr_of_mut!(lockA));
    ret
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn lock_static_subprog_lock(ctx: *const __sk_buff) -> i32 {
    let ret = static_subprog_lock(ctx);

    bpf_spin_unlock(core::ptr::addr_of_mut!(lockA));
    ret
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn lock_static_subprog_unlock(ctx: *const __sk_buff) -> i32 {
    bpf_spin_lock(core::ptr::addr_of_mut!(lockA));
    static_subprog_unlock(ctx)
}

bpf_object!("GPL");
