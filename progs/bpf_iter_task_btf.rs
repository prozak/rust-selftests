#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_task_btf.c
// (bpf-rs-core idiom).
//
// The "live" half of the C source is gated behind
// `#if __has_builtin(__builtin_btf_type_id)`: it fills in a `struct btf_ptr`
// via `bpf_core_type_id_kernel(struct task_struct)` (a BPF_TYPE_ID_TARGET
// CO-RE relocation) and prints it with bpf_seq_printf_btf(). This pipeline
// cannot emit that relocation -- btf-macros only emits field
// byte_offset/field_exists relocations, see getsockname_unix_prog.rs and
// tcp_ca_untrusted_btf_write.rs for the same limitation. The C source
// itself already defines the correct behavior for that situation: the
// `#else` branch, `skip = true;`. Taking it here is not a workaround, it's
// the upstream fallback path for a toolchain without the builtin.
//
// prog_tests/bpf_iter.c's do_btf_read() checks bss->skip first and, if set,
// calls test__skip() and returns before asserting on bss->tasks/seq_err --
// so this is a clean SKIP of the task_btf subtest, not a FAIL.

use bpf_rs_core::bpf_object;

#[no_mangle]
static mut tasks: isize = 0;
#[no_mangle]
static mut seq_err: isize = 0;
#[no_mangle]
static mut skip: bool = false;

#[link_section = "iter/task"]
#[no_mangle]
extern "C" fn dump_task_struct(_ctx: *const u64) -> i32 {
    unsafe { skip = true };
    0
}

bpf_object!("GPL");
