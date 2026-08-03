#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/nested_acquire.c,
// bpf-rs-core idiom.
//
// prog_tests/nested_trust.c's test_nested_trust() does
// RUN_TESTS(nested_acquire): both programs here are __success, so
// test_loader's default (no BTF_KIND_DECL_TAG in this pipeline => expect
// success) already matches the C source's contract.
//
// Both tp_btf/tcp_probe programs take a trusted PTR_TO_BTF_ID `sk` (BPF_PROG
// arg 0) and pass the address of one of its nested aggregate fields
// (&sk->sk_write_queue, &sk->__sk_common) to a KF_ACQUIRE kfunc expecting a
// pointer to that nested field's own struct type. The C compiler resolves
// `&sk->field` through vmlinux.h as a CO-RE field-offset access (same
// mechanism BPF_CORE_READ uses); btf_macros' `#[btf]` field accessors emit
// the equivalent byte_offset relocation (see find_vma_fail1.rs for the
// established `(&*ptr).field().as_ptr()` idiom).
//
// libbpf's CO-RE field matcher (bpf_core_fields_are_compat in relo_core.c)
// only accepts a candidate when local and target field KINDS are compatible;
// two STRUCT/UNION kinds are always compatible regardless of name/size, but
// a scalar local field against a real STRUCT target field is rejected
// outright ("failed to resolve CO-RE relocation"). So the local field type
// must itself be BTF_KIND_STRUCT. The `#[btf]` macro's own aggregate view
// wrapper only exposes `exists()`/nested accessors (no `as_ptr()`), so
// instead of `#[btf]`-wrapping sk_buff_head/sock_common we hand-implement
// `btf::BtfType` for them the same way btf-macros does for pointer/scalar
// leaves (`View = Field` directly) — that keeps `.as_ptr()` reachable while
// still landing a STRUCT-kind local type for the compat check.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use btf::{BtfType, Field};
use btf_macros::btf;

macro_rules! opaque_struct_btf_type {
    ($name:ident) => {
        #[repr(C)]
        struct $name {
            _priv: [u8; 0],
        }

        impl BtfType for $name {
            type Carrier = Self;
            type View<'a, Root, Path, Mode>
                = Field<'a, Root, Self, Path, Mode>
            where
                Self: 'a,
                Root: BtfType + 'a;

            #[inline(always)]
            fn __btf_view<'a, Root, Path, Mode>(
                field: Field<'a, Root, Self, Path, Mode>,
            ) -> Self::View<'a, Root, Path, Mode>
            where
                Self: 'a,
                Root: BtfType + 'a,
            {
                field
            }
        }
    };
}

opaque_struct_btf_type!(sk_buff_head);
opaque_struct_btf_type!(sock_common);

#[repr(C)]
struct sk_buff {
    _priv: [u8; 0],
}

#[btf]
struct sock {
    sk_write_queue: sk_buff_head,
    __sk_common: sock_common,
}

extern "C" {
    fn bpf_kfunc_nested_acquire_nonzero_offset_test(ptr: *mut sk_buff_head) -> *mut sk_buff;
    fn bpf_kfunc_nested_acquire_zero_offset_test(ptr: *mut sock_common) -> *mut sk_buff;
    fn bpf_kfunc_nested_release_test(ptr: *mut sk_buff);
}

#[link_section = "tp_btf/tcp_probe"]
#[no_mangle]
extern "C" fn test_nested_acquire_nonzero(ctx: *const u64) -> i32 {
    let sk = arg(ctx, 0) as *const sock;
    let field = unsafe { (&*sk).sk_write_queue().as_ptr() } as *mut sk_buff_head;

    let ptr = unsafe { bpf_kfunc_nested_acquire_nonzero_offset_test(field) };
    unsafe { bpf_kfunc_nested_release_test(ptr) };
    0
}

#[link_section = "tp_btf/tcp_probe"]
#[no_mangle]
extern "C" fn test_nested_acquire_zero(ctx: *const u64) -> i32 {
    let sk = arg(ctx, 0) as *const sock;
    let field = unsafe { (&*sk).__sk_common().as_ptr() } as *mut sock_common;

    let ptr = unsafe { bpf_kfunc_nested_acquire_zero_offset_test(field) };
    unsafe { bpf_kfunc_nested_release_test(ptr) };
    0
}

bpf_object!("GPL");
