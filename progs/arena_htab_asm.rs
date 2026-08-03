#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/arena_htab_asm.c,
// which is `#define BPF_ARENA_FORCE_ASM` + `#define arena_htab_llvm
// arena_htab_asm` + `#include "arena_htab.c"`. Unlike arena_list.c (see
// progs/arena_list.rs), prog_tests/arena_htab.c's test_arena_htab_asm()
// does NOT check a `skip` flag: it unconditionally reads
// `skel->bss->htab_for_user` and walks the hash table on the host using
// its own copy of bpf_arena_htab.h (compiled without __BPF__, so cast_kern/
// cast_user are nops there and htab_lookup_elem() walks the exact bytes our
// program wrote). So this translation must implement the real
// FORCE_ASM allocator/htab/list logic, not take a fallback branch.
//
// BPF_ARENA_FORCE_ASM means `__arena` carries no LLVM address_space
// qualifier at all (just a BTF type tag) -- cast_kern/cast_user are real,
// hand-emitted `BPF_ADDR_SPACE_CAST` instructions (off=1,
// imm=(dst_as<<16)|src_as), the same encoding this repo's arena_atomics.rs
// already validated (see [[arena-addr-space-cast-solvable-via-asm]]):
// opcode 0xBF, in-place single-register operand sniffed via `.ifc {0}, rN`.
// cast_kern = dst_as=0,src_as=1 -> imm=1; cast_user = dst_as=1,src_as=0 ->
// imm=65536. Call-site fidelity matters here (unlike a stateless helper):
// bpf_arena_htab.h/bpf_arena_list.h call cast_kern/cast_user repeatedly on
// the same local variable at different points (e.g. bpf_alloc's
// `cast_kern(cur_page)` then later `cast_kern(page)` on a value already
// once cast), so every C call site is mirrored 1:1 rather than
// deduplicated -- trusting upstream's macro-expansion semantics rather
// than re-deriving them.
//
// The kfunc `bpf_arena_alloc_pages`/`bpf_arena_free_pages` take `void *`/
// `void __arena *` args and return `void __arena *`; the old
// [[void-star-kfunc-arg-breaks-llvm-as]] finding predates
// add_ksyms.py mirroring the kernel's real BTF proto for kfunc args
// (pointer kind -> DIDerivedType with baseType: null for void*, not an
// ill-formed node), see [[add_ksyms-kfunc-func-protos-are-void]] --
// re-verified working here.
//
// `struct htab`, `hashtab_elem`, `arena_list_node`, `arena_list_head` are
// NOT part of this object's BTF at all (confirmed via `bpftool btf dump`
// on the pristine reference object: only `struct htab` appears, pulled in
// by htab_init/htab_lookup_elem/htab_update_elem's signatures; htab_bucket
// stays a bare FWD, and hashtab_elem/arena_list_node/arena_list_head never
// appear since no BTF-visible declaration mentions them by name). So exact
// BTF shape/naming for these doesn't matter -- only their C-ABI byte
// layout does, since the host test's own separately-compiled copy of
// bpf_arena_htab.h dereferences the exact same arena-mmapped bytes our
// program wrote. `#[repr(C)]` with the same field order/types as the C
// structs reproduces that layout bit-for-bit.
//
// `can_loop` (bpf_may_goto.h's `__BPF_FEATURE_MAY_GOTO`-less fallback,
// used unconditionally by the pristine upstream build too) is a hand
// encoded `may_goto`-shaped insn (opcode 0xe5, off=0, imm=branch-offset)
// via Rust's (now-stable) `asm!` `label {}` operand -- confirmed compiling
// for the bpfel-unknown-none-v4 target with a standalone smoke test before
// use here. It's not a "just in case" safety net: upstream's C source
// ANDs it into both `for` loops' conditions and into
// bpf_arena_list.h's list_for_each_entry macro unconditionally, i.e. this
// exact allocator+htab program is known (by the people who wrote it) to
// need it for the verifier to accept the large/complex loops below.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_smp_processor_id;
use bpf_rs_core::vstore;
use core::ffi::c_void;

const PAGE_SIZE: i32 = 4096;
const NUMA_NO_NODE: i32 = -1;
const NR_CPUS: usize = 64;
const ENOMEM: i32 = 12;
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

// Named to match the C source's `struct htab` tag exactly (not just its
// layout): prog_tests/arena_htab.c assigns `skel->bss->htab_for_user`
// (host-generated skeleton type) directly to a `struct htab *` local with
// no cast, under -Werror=incompatible-pointer-types. A same-shaped but
// differently-BTF-named/anonymous struct (or `*mut c_void`, which surfaces
// in BTF as `enum c_void *` via core::ffi::c_void's DWARF representation,
// not a real `void *`) fails that strict assignment; matching the tag name
// makes the regenerated skeleton emit `struct htab *` and the assignment
// compiles clean.
#[allow(non_camel_case_types)]
#[repr(C)]
struct htab {
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

// .bss
#[no_mangle]
static mut skip: bool = false;
#[no_mangle]
static mut zero: i32 = 0;
#[no_mangle]
static mut arr2: [u8; 1000] = [0; 1000];
#[no_mangle]
static mut htab_for_user: *mut htab = core::ptr::null_mut();

// .addr_space.1 (arena-backed globals)
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut arr1: [u8; 100000] = [0; 100000];
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut page_frag_cur_page: [*mut u8; NR_CPUS] = [core::ptr::null_mut(); NR_CPUS];
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut page_frag_cur_offset: [i32; NR_CPUS] = [0; NR_CPUS];

/// `bpf_addr_space_cast(ptr, 0, 1)`: AS1 (arena) raw address -> AS0
/// kernel-usable pointer. See [[arena-addr-space-cast-solvable-via-asm]].
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

/// `bpf_addr_space_cast(ptr, 1, 0)`: AS0 kernel pointer -> AS1 arena
/// representation (the numbering host userspace sees via mmap).
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
        ".long 65536",
        inout(reg) p,
        options(nostack, preserves_flags),
    );
    p
}

/// bpf_may_goto.h's `can_loop` (non-`__BPF_FEATURE_MAY_GOTO` fallback):
/// hand-encoded may_goto-shaped insn (opcode 0xe5) via a stable `asm!`
/// `label {}` operand carrying the branch-offset computation.
#[inline(always)]
unsafe fn can_loop() -> bool {
    let mut ret = true;
    core::arch::asm!(
        "1:",
        ".byte 0xe5",
        ".byte 0",
        ".long (({0} - 1b - 8) / 8) & 0xffff",
        ".short 0",
        label {
            ret = false;
        },
    );
    ret
}

#[inline(always)]
fn round_up(x: u32, y: u32) -> u32 {
    ((x - 1) | (y - 1)) + 1
}

#[inline(always)]
unsafe fn bpf_alloc(size: u32) -> *mut u8 {
    let cpu = bpf_get_smp_processor_id() as usize;
    let cur_page: *mut *mut u8 =
        cast_kern((core::ptr::addr_of_mut!(page_frag_cur_page) as *mut *mut u8).add(cpu));
    let cur_offset: *mut i32 =
        cast_kern((core::ptr::addr_of_mut!(page_frag_cur_offset) as *mut i32).add(cpu));
    let mut page: *mut u8 = *cur_page;

    let size = round_up(size, 8);
    if size >= (PAGE_SIZE - 8) as u32 {
        return core::ptr::null_mut();
    }

    let mut obj_cnt: *mut u64;
    let mut offset: i32;

    loop {
        if page.is_null() {
            let p = bpf_arena_alloc_pages(
                core::ptr::addr_of!(arena) as *mut c_void,
                core::ptr::null_mut(),
                1,
                NUMA_NO_NODE,
                0,
            ) as *mut u8;
            if p.is_null() {
                return core::ptr::null_mut();
            }
            page = cast_kern(p);
            *cur_page = page;
            *cur_offset = PAGE_SIZE - 8;
            obj_cnt = page.add((PAGE_SIZE - 8) as usize) as *mut u64;
            *obj_cnt = 0;
            offset = PAGE_SIZE - 8;
        } else {
            page = cast_kern(page);
            obj_cnt = page.add((PAGE_SIZE - 8) as usize) as *mut u64;
            offset = *cur_offset;
        }

        offset -= size as i32;
        if offset < 0 {
            page = core::ptr::null_mut();
            continue;
        }
        break;
    }

    *obj_cnt += 1;
    *cur_offset = offset;
    page.add(offset as usize)
}

#[inline(always)]
unsafe fn bpf_free(addr: *mut u8) {
    let addr = ((addr as usize) & !((PAGE_SIZE as usize) - 1)) as *mut u8;
    let obj_cnt = addr.add((PAGE_SIZE - 8) as usize) as *mut u64;
    *obj_cnt -= 1;
    if *obj_cnt == 0 {
        bpf_arena_free_pages(core::ptr::addr_of!(arena) as *mut c_void, addr as *mut c_void, 1);
    }
}

#[inline(always)]
unsafe fn list_add_head(mut n: *mut ArenaListNode, h: *mut ArenaListHead) {
    let mut first: *mut ArenaListNode = (*h).first;

    first = cast_user(first);
    n = cast_kern(n);
    vstore!((*n).next, first);
    first = cast_kern(first);
    if !first.is_null() {
        let mut tmp: *mut *mut ArenaListNode = core::ptr::addr_of_mut!((*n).next);
        tmp = cast_user(tmp);
        vstore!((*first).pprev, tmp);
    }
    n = cast_user(n);
    vstore!((*h).first, n);

    let mut tmp: *mut *mut ArenaListNode = core::ptr::addr_of_mut!((*h).first);
    tmp = cast_user(tmp);
    n = cast_kern(n);
    vstore!((*n).pprev, tmp);
}

#[inline(always)]
unsafe fn arena_list_del_raw(n: *mut ArenaListNode) {
    let mut next: *mut ArenaListNode = (*n).next;
    let mut pprev: *mut *mut ArenaListNode = (*n).pprev;

    next = cast_user(next);
    pprev = cast_kern(pprev);
    vstore!(*pprev, next);
    if !next.is_null() {
        pprev = cast_user(pprev);
        next = cast_kern(next);
        vstore!((*next).pprev, pprev);
    }
}

#[inline(always)]
unsafe fn list_del(n: *mut ArenaListNode) {
    arena_list_del_raw(n);
    (*n).next = LIST_POISON1 as *mut ArenaListNode;
    (*n).pprev = LIST_POISON2 as *mut *mut ArenaListNode;
}

#[inline(always)]
unsafe fn list_entry_safe(ptr: *mut ArenaListNode) -> *mut HashtabElem {
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    let p = cast_kern(ptr);
    (p as *mut u8).sub(core::mem::offset_of!(HashtabElem, hash_node)) as *mut HashtabElem
}

#[inline(always)]
unsafe fn lookup_elem_raw(head: *mut ArenaListHead, hash: i32, key: i32) -> *mut HashtabElem {
    let mut pos = list_entry_safe((*head).first);
    loop {
        if pos.is_null() {
            break;
        }
        let next = (*pos).hash_node.next;
        if !can_loop() {
            break;
        }
        if (*pos).hash == hash && (*pos).key == key {
            return pos;
        }
        pos = list_entry_safe(next);
    }
    core::ptr::null_mut()
}

#[inline(always)]
fn htab_hash(key: i32) -> i32 {
    key
}

#[inline(always)]
unsafe fn select_bucket(htab: *mut htab, hash: u32) -> *mut ArenaListHead {
    let b: *mut HtabBucket = cast_kern((*htab).buckets);
    let idx = (hash & ((*htab).n_buckets as u32 - 1)) as usize;
    core::ptr::addr_of_mut!((*b.add(idx)).head)
}

#[no_mangle]
extern "C" fn htab_lookup_elem(htab: *mut htab, key: i32) -> i32 {
    unsafe {
        let htab = cast_kern(htab);
        let head = select_bucket(htab, key as u32);
        let l_old = lookup_elem_raw(head, htab_hash(key), key);
        if !l_old.is_null() {
            (*l_old).value
        } else {
            0
        }
    }
}

#[no_mangle]
extern "C" fn htab_update_elem(htab: *mut htab, key: i32, value: i32) -> i32 {
    unsafe {
        let htab = cast_kern(htab);
        let head = select_bucket(htab, key as u32);
        let l_old = lookup_elem_raw(head, htab_hash(key), key);

        let l_new = bpf_alloc(core::mem::size_of::<HashtabElem>() as u32) as *mut HashtabElem;
        if l_new.is_null() {
            return -ENOMEM;
        }
        (*l_new).key = key;
        (*l_new).hash = htab_hash(key);
        (*l_new).value = value;

        list_add_head(core::ptr::addr_of_mut!((*l_new).hash_node), head);
        if !l_old.is_null() {
            list_del(core::ptr::addr_of_mut!((*l_old).hash_node));
            bpf_free(l_old as *mut u8);
        }
        0
    }
}

#[no_mangle]
extern "C" fn htab_init(htab: *mut htab) {
    unsafe {
        let buckets = bpf_arena_alloc_pages(
            core::ptr::addr_of!(arena) as *mut c_void,
            core::ptr::null_mut(),
            2,
            NUMA_NO_NODE,
            0,
        ) as *mut u8;
        let buckets = cast_user(buckets) as *mut HtabBucket;
        (*htab).buckets = buckets;
        (*htab).n_buckets = (2 * PAGE_SIZE) / core::mem::size_of::<HtabBucket>() as i32;
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arena_htab_asm(_ctx: *const c_void) -> i32 {
    unsafe {
        let htab = bpf_alloc(core::mem::size_of::<htab>() as u32) as *mut htab;
        let htab = cast_kern(htab);
        htab_init(htab);

        let arr = cast_kern(core::ptr::addr_of_mut!(arr1) as *mut u8);

        let mut i: u64 = zero as u64;
        while i < 100000 && can_loop() {
            htab_update_elem(htab, i as i32, i as i32);
            *arr.add(i as usize) = i as u8;
            i += 1;
        }

        let mut i: u64 = zero as u64;
        while i < 1000 && can_loop() {
            htab_update_elem(htab, i as i32, i as i32);
            *(core::ptr::addr_of_mut!(arr2) as *mut u8).add(i as usize) = i as u8;
            i += 1;
        }

        let htab = cast_user(htab);
        htab_for_user = htab;
    }
    0
}

bpf_object!("GPL");
