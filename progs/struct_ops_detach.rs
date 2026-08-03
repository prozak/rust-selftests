#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_detach.c,
// bpf-rs-core idiom.
//
// dangling_subprog: a plain global .text function with no SEC() at all —
// this is not a BPF program, it exercises libbpf's handling of a
// subprogram-only object with no entry programs (see the C comment).
//
// testmod_do_detach: SEC(".struct_ops.link") struct bpf_testmod_ops with
// every callback left unset (implicit zero, same as the C global) — no
// userspace test ever reads/writes a member through the generated
// skeleton's shadow struct (prog_tests/test_struct_ops_module.c's
// test_detach_link() only attaches/detaches the map itself). A fully
// empty local struct (0 members) makes libbpf treat the whole
// ".struct_ops.link" ELF section as zero-sized and skip it entirely
// ("elf: skipping section... (size 0)"), so no map gets created at all;
// the local struct must have at least one real, non-pointer member to
// give the section nonzero size. `onebyte` is the one `char` field in
// the real bpf_testmod_ops (bpf_testmod.h) — same BTF kind (INT) on both
// sides, so libbpf's bpf_map__init_kern_struct_ops() just memcpy's the
// zero value across, which is a no-op vs. the kernel's own zeroed
// struct_ops storage. No function-pointer member is declared, so there
// is no const-evaluated null function pointer to construct (which Rust's
// fn type forbids; see struct_ops_forgotten_cb's blocker).

use bpf_rs_core::bpf_object;

#[no_mangle]
extern "C" fn dangling_subprog() -> i32 {
    0
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    onebyte: u8,
}

unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_do_detach: bpf_testmod_ops = bpf_testmod_ops { onebyte: 0 };

bpf_object!("GPL");
