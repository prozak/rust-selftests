#![no_std]
#![feature(asm_experimental_arch)]
// bpf-rs-core: the canonical idiom layer for the rust2bpf pipeline.
//
// Everything here is a macro, a generic, or #[inline(always)] — the crate is
// header-only by construction: bodies monomorphize into each program's
// bitcode, so the llvm-link / postproc / internalize pipeline stays
// untouched. NO runtime, NO allocator, NO aya.
//
// Invariant this crate must never break: the BTF/ABI of an object built
// against it is indistinguishable (to libbpf, bpftool skeletons, and the
// kernel) from the clang-built C object. The kernel selftests harness is
// the acceptance oracle for every change here.

pub mod maps;
pub mod helpers;
pub mod ctx;
pub mod progs;

/// License static + panic handler, the fixed per-object preamble.
///
/// `bpf_object!("GPL")` expands to the `_license` static (strlen+NUL bytes,
/// same as C) and the unreachable `loop {}` panic handler that DCE removes.
#[macro_export]
macro_rules! bpf_object {
    ($lic:literal) => {
        #[link_section = "license"]
        #[no_mangle]
        static _license: [u8; $lic.len() + 1] = $crate::__lic_bytes::<{ $lic.len() + 1 }>($lic);

        #[panic_handler]
        fn panic(_: &core::panic::PanicInfo) -> ! {
            loop {}
        }
    };
}

#[doc(hidden)]
pub const fn __lic_bytes<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0;
    while i < b.len() {
        out[i] = b[i];
        i += 1;
    }
    out
}

/// Test-loader expectations, mirroring the `bpf_misc.h` attributes.
///
/// `test_loader.c` decides whether a program must load, must be *rejected*,
/// and what the verifier log must contain by reading BTF_KIND_DECL_TAGs off
/// the program's FUNC ("comment:<n>:test_expect_failure",
/// "comment:<n>:test_expect_msg=..."). clang derives those from
/// `__attribute__((btf_decl_tag))`; rustc has no way to emit them.
///
/// So this macro expands to NOTHING: the declaration is read from the source
/// by scripts/btf_test_tags.py, which appends the tags to the built object's
/// .BTF. It is a macro rather than a comment so that rustc checks the shape
/// and so there is exactly one grep-able anchor per translation:
///
/// ```ignore
/// test_tags! {
///     global_func1: __failure, __msg("combined stack size of 3 calls is");
/// }
/// ```
///
/// A message may wildcard the parts of a verifier log line that depend on
/// register allocation, using the matcher's own `{{regex}}` brackets:
/// `__msg("{{R[0-9]}} type=scalar expected=fp")`. scripts/translint.py bounds
/// which tokens may be relaxed that way.
#[macro_export]
macro_rules! test_tags {
    ($($func:ident : $($tag:expr),+ $(,)? );+ $(;)?) => {};
}
