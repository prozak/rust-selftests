#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bad_struct_ops2.c,
// bpf-rs-core idiom.
//
// This is an unused struct_ops program: it has no corresponding
// struct_ops map, so nothing provides attachment information. libbpf
// still autoloads it (struct_ops programs not referenced from any map
// default to autoload=true), and the kernel rejects the load because
// there is no member named "foo" in any registered struct_ops type to
// establish its context. prog_tests/bad_struct_ops.c's unused_program()
// expects bad_struct_ops2__load() to fail with a "prog 'foo': failed to
// load" libbpf log message.

use bpf_rs_core::bpf_object;

#[link_section = "struct_ops/foo"]
#[no_mangle]
extern "C" fn foo() {}

bpf_object!("GPL");
