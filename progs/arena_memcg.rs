// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/arena_memcg.c
// (bpf-rs-core idiom). The object is a single BPF_F_MMAPABLE arena map and
// no program: prog_tests/arena_memcg.c loads it inside a memory cgroup and
// faults the arena's pages in from user space to check that the pages are
// charged to that cgroup. max_entries is the C's page count (covers
// ARENA_FAULT on 4K pages, stays under 4G on 64K pages); map_extra is the
// mmap() region's start, encoded as an ENUM64 value as clang's __ulong()
// does (arena_mem_usage.rs).

#[repr(u64)]
enum ArenaAddress {
    Start = 1u64 << 44,
}

#[repr(C)]
struct ArenaMap {
    r#type: *const [i32; 33],       // BPF_MAP_TYPE_ARENA
    map_flags: *const [i32; 1024],  // BPF_F_MMAPABLE
    max_entries: *const [i32; 50000],
    map_extra: ArenaAddress,
}
unsafe impl Sync for ArenaMap {}

#[no_mangle]
#[link_section = ".maps"]
static arena: ArenaMap = ArenaMap {
    r#type: core::ptr::null(),
    map_flags: core::ptr::null(),
    max_entries: core::ptr::null(),
    map_extra: ArenaAddress::Start,
};

bpf_rs_core::bpf_object!("GPL");
