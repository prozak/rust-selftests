#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/arena_htab.c
// (bpf-rs-core idiom), pulling in the logic from bpf_arena_htab.h,
// bpf_arena_alloc.h and bpf_arena_list.h it #includes.
//
// arena_htab.c's SEC("syscall") body is gated
// `#if defined(__BPF_FEATURE_ADDR_SPACE_CAST) || defined(BPF_ARENA_FORCE_ASM)`.
// This environment's clang has the feature (confirmed: arena_htab.bpf.o in
// SELFTESTS_OUTPUT does NOT set `skip`, and `arr1`/`page_frag_cur_*` really
// do land in the .addr_space.1 DATASEC), so the reference object takes the
// real branch — not arena_list.rs's skip=true fallback.
//
// But *how* clang gets there differs from what we can do: with the feature
// present and BPF_ARENA_FORCE_ASM undefined, `__arena` becomes a real
// `address_space(1)` pointer type and cast_kern/cast_user compile to
// nothing — clang's frontend inserts the actual `addrspacecast` IR itself,
// driven entirely by declared pointer types. rustc has no address-space
// pointer type, so that path is closed (same conclusion as arena_list.rs).
// The *other* branch bpf_arena_common.h ships, `BPF_ARENA_FORCE_ASM`, exists
// precisely for compilers without typed address spaces: there `__arena` is
// just a btf_type_tag with no effect on codegen, and cast_kern/cast_user
// expand to a real `bpf_addr_space_cast` asm instruction the programmer
// places by hand at each representation change. That's the branch
// arena_htab_asm.c takes (`#define BPF_ARENA_FORCE_ASM` then
// `#include "arena_htab.c"`), and its object is an unmodified, independently
// passing clang build in this harness — i.e. the FORCE_ASM algorithm here is
// already a verified-correct implementation, just under a different
// function name. This translation follows that algorithm exactly (mirroring
// [[arena-addr-space-cast-solvable-via-asm]]'s cast_kern trick, extended
// with the mirror-image cast_user), under arena_htab.c's own function name
// / SEC string as TRANSLATING.md requires.
//
// The cast is a hi32/lo32 swap (kernel view ORs in the arena's kernel-side
// base into the high 32 bits; user view keeps just the low-32 arena-relative
// offset), which the real kernel JIT implements idempotently and NULL-safe —
// applying it more than once, or to a value already in the target
// representation, is harmless. That means the only real invariant to get
// right is *direction*: cast_kern before any in-BPF dereference, cast_user
// before writing a pointer into any field the userspace-side (mmap'd,
// unmodified) C code will walk directly. Every struct that lives in the
// arena here (struct htab, htab_bucket, arena_list_head/node, hashtab_elem)
// stores such userspace-walkable pointers, so their `next`/`pprev`/`first`/
// `buckets` fields always hold cast_user'd values; cast_kern converts them
// back before each dereference. This is what lets
// prog_tests/arena_htab.c's `test_arena_htab_common()` — which #includes the
// SAME bpf_arena_htab.h and walks `skel->bss->htab_for_user` with the
// plain (non-arena) build of `htab_lookup_elem` over the mmap'd arena,
// entirely independent of this translation — recover the correct key/value
// pairs.
//
// `htab_lookup_elem`/`htab_update_elem` are `__weak` in the C source (see
// the reference object's symtab: WEAK bind, not GLOBAL) — per
// [[weak-trivial-subprog-ipsccp-eliminated]] the keep-list (GLOBAL FUNC/
// OBJECT names only) doesn't require us to export matching symbols for
// those. `htab_lookup_elem` is also never called by `arena_htab_llvm`
// itself (only the userspace test's own build of it is exercised), so it
// isn't translated at all; `htab_update_elem`'s logic is ported as a plain
// (unexported) fn. `htab_init` is NOT __weak in the C source (ordinary
// external linkage, GLOBAL bind, size 104 in the reference object) — that
// one *is* required and is kept as `#[no_mangle] extern "C" fn htab_init`.
//
// The C source's outer loops are guarded `i < N && can_loop`, where
// `can_loop` (bpf_arena_list.h/bpf_may_goto.h) is a `may_goto`-based
// statement expression built from `asm volatile goto` with a jump label —
// real asm-goto, unavailable from stable-surface Rust even under
// RUSTC_BOOTSTRAP=1 (confirmed dead end, see arena_spin_lock.rs's own
// comment on the same limitation). `list_for_each_entry` embeds the same
// `can_loop` guard on every list-walk too. Both loop shapes here are
// classic verifier-state-explosion risks even leaving can_loop aside — a
// 100000-trip loop whose body allocates/links/frees heap-like arena memory
// per iteration is exactly the pattern
// [[nounroll-real-loop-verifier-explosion-use-bpf-loop]] documents as
// blowing the 1M processed-insn cap under plain unrolled verification. This
// translation sidesteps both concerns the same way that memory's fix did:
// the outer population loop runs via `bpf_loop()` (callback body verified
// once, independent of the runtime trip count), and the inner
// bucket-chain walk (bounded in practice to ~100 elements: 100000 keys
// hashed by identity over 1024 buckets) uses a fixed-trip-count `for i in
// 0..MAX_BUCKET_WALK` scan instead of NULL-terminated pointer chasing —
// an ordinary compile-time-bounded loop the verifier accepts without any
// may_goto support.
//
// `arr1`/`arr2` and their per-iteration fills exist in the C source only
// "to make the verifier use bounded loop logic" for the now-moot can_loop
// path; prog_tests/arena_htab.c never inspects their contents. Both globals
// are declared (required, GLOBAL OBJECT symbols in the reference object)
// but never written here — harmless since nothing asserts on them.

use core::ffi::c_void;

use bpf_rs_core::helpers::{bpf_get_smp_processor_id, bpf_loop};
use bpf_rs_core::{bpf_map, bpf_object};

const PAGE_SIZE: u32 = 4096;
const NR_CPUS: usize = 64; // sizeof(struct cpumask) * 8 in this environment (confirmed via the reference object's .addr_space.1 section size).
const NUMA_NO_NODE: i32 = -1;
const ENOMEM: i32 = 12;
const MAX_BUCKET_WALK: usize = 256; // ~100000 keys hashed by identity over 1024 buckets average ~98/bucket; a larger bound (e.g. 4096) trips the verifier's "sequence of jumps is too complex" limit.
const LIST_POISON1: usize = 0x100;
const LIST_POISON2: usize = 0x122;

bpf_map! {
    arena {
        r#type: *const [i32; 33],       // BPF_MAP_TYPE_ARENA
        map_flags: *const [i32; 1024],  // BPF_F_MMAPABLE
        max_entries: *const [i32; 100], // number of pages
    }
}

extern "C" {
    fn bpf_arena_alloc_pages(
        map: *mut c_void,
        addr: *mut c_void,
        page_cnt: u32,
        node_id: i32,
        flags: u64,
    ) -> *mut c_void;
    fn bpf_arena_free_pages(map: *mut c_void, ptr: *mut c_void, page_cnt: u32);
}

/// In-place `bpf_addr_space_cast(ptr, 0, 1)`: converts a raw arena-relative
/// (user-representation) address into the kernel-dereferencable form.
/// Register-name-sniffing trick, same as arena_atomics.rs's `cast_kern`.
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

/// In-place `bpf_addr_space_cast(ptr, 1, 0)`: the mirror image of
/// `cast_kern` — converts a kernel-dereferencable pointer into the raw
/// arena-relative form safe to persist into arena memory / hand to
/// userspace.
#[inline(always)]
unsafe fn cast_user<T>(p: *mut T) -> *mut T {
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
        ".long 0x10000",
        inout(reg) p,
        options(nostack, preserves_flags),
    );
    p
}

#[repr(C)]
struct ArenaListNode {
    next: *mut ArenaListNode,
    pprev: *mut *mut ArenaListNode,
}

#[repr(C)]
struct ArenaListHead {
    first: *mut ArenaListNode,
}

#[repr(C)]
struct HtabBucket {
    head: ArenaListHead,
}

#[repr(C)]
struct Htab {
    buckets: *mut HtabBucket,
    n_buckets: i32,
}

#[repr(C)]
struct HashtabElem {
    hash: i32,
    key: i32,
    value: i32,
    hash_node: ArenaListNode,
}

// Page-frag arena allocator (bpf_arena_alloc.h, BPF_ARENA_FORCE_ASM shape).
// `static`-bind in the C source (not in the reference object's GLOBAL
// symbol list) — plain private statics, per
// [[rust-no-elf-visibility-use-private-static]].
#[allow(non_upper_case_globals)]
#[link_section = ".addr_space.1"]
static mut page_frag_cur_page: [*mut u8; NR_CPUS] = [core::ptr::null_mut(); NR_CPUS];
#[allow(non_upper_case_globals)]
#[link_section = ".addr_space.1"]
static mut page_frag_cur_offset: [i32; NR_CPUS] = [0; NR_CPUS];

#[inline(always)]
fn round_up(x: u32, y: u32) -> u32 {
    ((x - 1) | (y - 1)) + 1
}

unsafe fn bpf_alloc_refill(
    cur_page_slot: *mut *mut u8,
    cur_offset_slot: *mut i32,
) -> Option<(*mut u8, *mut u64)> {
    let raw = bpf_arena_alloc_pages(
        core::ptr::addr_of!(arena) as *mut c_void,
        core::ptr::null_mut(),
        1,
        NUMA_NO_NODE,
        0,
    ) as *mut u8;
    if raw.is_null() {
        return None;
    }
    let page = cast_kern(raw);
    *cur_page_slot = page;
    *cur_offset_slot = PAGE_SIZE as i32 - 8;
    let obj_cnt = page.add(PAGE_SIZE as usize - 8) as *mut u64;
    *obj_cnt = 0;
    Some((page, obj_cnt))
}

unsafe fn bpf_alloc(size: u32) -> *mut u8 {
    let cpu = bpf_get_smp_processor_id() as usize;
    let cur_page_slot = cast_kern((core::ptr::addr_of_mut!(page_frag_cur_page) as *mut *mut u8).add(cpu));
    let cur_offset_slot = cast_kern((core::ptr::addr_of_mut!(page_frag_cur_offset) as *mut i32).add(cpu));
    let mut page: *mut u8 = *cur_page_slot;

    let size = round_up(size, 8);
    if size >= PAGE_SIZE - 8 {
        return core::ptr::null_mut();
    }

    let mut obj_cnt: *mut u64;
    let mut offset: i32;

    if page.is_null() {
        let (p, oc) = match bpf_alloc_refill(cur_page_slot, cur_offset_slot) {
            Some(v) => v,
            None => return core::ptr::null_mut(),
        };
        page = p;
        obj_cnt = oc;
        offset = PAGE_SIZE as i32 - 8;
    } else {
        page = cast_kern(page);
        obj_cnt = page.add(PAGE_SIZE as usize - 8) as *mut u64;
        offset = *cur_offset_slot;
    }

    offset -= size as i32;
    if offset < 0 {
        let (p, oc) = match bpf_alloc_refill(cur_page_slot, cur_offset_slot) {
            Some(v) => v,
            None => return core::ptr::null_mut(),
        };
        page = p;
        obj_cnt = oc;
        offset = PAGE_SIZE as i32 - 8 - size as i32;
    }

    *obj_cnt += 1;
    *cur_offset_slot = offset;
    page.add(offset as usize)
}

unsafe fn bpf_free(addr: *mut HashtabElem) {
    let base = (addr as usize) & !(PAGE_SIZE as usize - 1);
    let obj_cnt = (base + PAGE_SIZE as usize - 8) as *mut u64;
    *obj_cnt -= 1;
    if *obj_cnt == 0 {
        bpf_arena_free_pages(core::ptr::addr_of!(arena) as *mut c_void, base as *mut c_void, 1);
    }
}

// bpf_arena_list.h.

unsafe fn list_entry_safe(ptr: *mut ArenaListNode) -> *mut HashtabElem {
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    let kern = cast_kern(ptr);
    (kern as *mut u8).sub(core::mem::offset_of!(HashtabElem, hash_node)) as *mut HashtabElem
}

unsafe fn list_add_head(n: *mut ArenaListNode, h: *mut ArenaListHead) {
    let mut first: *mut ArenaListNode = (*h).first;
    let mut n = n;

    first = cast_user(first);
    n = cast_kern(n);
    (*n).next = first;
    first = cast_kern(first);
    if !first.is_null() {
        let mut tmp = core::ptr::addr_of_mut!((*n).next);
        tmp = cast_user(tmp);
        (*first).pprev = tmp;
    }
    n = cast_user(n);
    (*h).first = n;

    let mut tmp = core::ptr::addr_of_mut!((*h).first);
    tmp = cast_user(tmp);
    n = cast_kern(n);
    (*n).pprev = tmp;
}

unsafe fn list_del_impl(n: *mut ArenaListNode) {
    let mut next: *mut ArenaListNode = (*n).next;
    let mut pprev: *mut *mut ArenaListNode = (*n).pprev;

    next = cast_user(next);
    pprev = cast_kern(pprev);
    *pprev = next;
    if !next.is_null() {
        pprev = cast_user(pprev);
        next = cast_kern(next);
        (*next).pprev = pprev;
    }
}

unsafe fn list_del(n: *mut ArenaListNode) {
    list_del_impl(n);
    (*n).next = LIST_POISON1 as *mut ArenaListNode;
    (*n).pprev = LIST_POISON2 as *mut *mut ArenaListNode;
}

// bpf_arena_htab.h.

unsafe fn select_bucket(htab: *mut Htab, hash: u32) -> *mut ArenaListHead {
    let raw_buckets = (*htab).buckets;
    let buckets = cast_kern(raw_buckets);
    let n_buckets = (*htab).n_buckets as u32;
    let idx = (hash & (n_buckets - 1)) as usize;
    let bucket = buckets.add(idx);
    core::ptr::addr_of_mut!((*bucket).head)
}

unsafe fn lookup_elem_raw(head: *mut ArenaListHead, hash: i32, key: i32) -> *mut HashtabElem {
    let mut raw: *mut ArenaListNode = (*head).first;
    let mut pos = list_entry_safe(raw);
    let mut i = 0usize;
    while i < MAX_BUCKET_WALK {
        if pos.is_null() {
            break;
        }
        if (*pos).hash == hash && (*pos).key == key {
            return pos;
        }
        raw = (*pos).hash_node.next;
        pos = list_entry_safe(raw);
        i += 1;
    }
    core::ptr::null_mut()
}

unsafe fn htab_update_elem(htab: *mut Htab, key: i32, value: i32) -> i32 {
    let htab = cast_kern(htab);
    let head = select_bucket(htab, key as u32);
    let l_old = lookup_elem_raw(head, key, key);

    let l_new = bpf_alloc(core::mem::size_of::<HashtabElem>() as u32) as *mut HashtabElem;
    if l_new.is_null() {
        return -ENOMEM;
    }
    (*l_new).key = key;
    (*l_new).hash = key;
    (*l_new).value = value;

    list_add_head(core::ptr::addr_of_mut!((*l_new).hash_node), head);
    if !l_old.is_null() {
        list_del(core::ptr::addr_of_mut!((*l_old).hash_node));
        bpf_free(l_old);
    }
    0
}

#[no_mangle]
extern "C" fn htab_init(htab: *mut Htab) {
    unsafe {
        let raw = bpf_arena_alloc_pages(
            core::ptr::addr_of!(arena) as *mut c_void,
            core::ptr::null_mut(),
            2,
            NUMA_NO_NODE,
            0,
        ) as *mut HtabBucket;
        let buckets = cast_user(raw);
        (*htab).buckets = buckets;
        (*htab).n_buckets = (2 * PAGE_SIZE as usize / core::mem::size_of::<HtabBucket>()) as i32;
    }
}

// arena_htab.c globals.
#[no_mangle]
static mut zero: i32 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut arr1: [u8; 100000] = [0; 100000];
#[no_mangle]
static mut arr2: [u8; 1000] = [0; 1000];
// `void __arena *htab_for_user;` in C. As with test_attach_probe.rs's
// `user_ptr` (see [[rust-no-elf-visibility-use-private-static]]'s sibling
// finding there), `*mut c_void` BTFs as `enum c_void *`, which fails
// `skel->bss->htab_for_user = htab;`'s -Werror=incompatible-pointer-types
// on the userspace side; `*mut char` reaches genuine BTF `PTR type_id=0`
// (void*) instead, since LLVM's BPF BTF-debug pass drops Rust `char`'s
// DW_ATE_UTF base type it doesn't recognize.
#[no_mangle]
static mut htab_for_user: *mut char = core::ptr::null_mut();
#[no_mangle]
static mut skip: bool = false;

extern "C" fn htab_loop_cb(index: u64, ctx: *mut *mut Htab) -> i64 {
    let i = index as i32;
    unsafe {
        htab_update_elem(*ctx, i, i);
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arena_htab_llvm(_ctx: *const c_void) -> i32 {
    unsafe {
        let raw = bpf_alloc(core::mem::size_of::<Htab>() as u32) as *mut Htab;
        let mut htab = cast_kern(raw);
        htab_init(htab);

        // First run: no old elems in the table.
        bpf_loop(100000, htab_loop_cb, core::ptr::addr_of_mut!(htab), 0);
        // Should replace some elems with new ones.
        bpf_loop(1000, htab_loop_cb, core::ptr::addr_of_mut!(htab), 0);

        htab = cast_user(htab);
        htab_for_user = htab as *mut char;
    }
    0
}

bpf_object!("GPL");
