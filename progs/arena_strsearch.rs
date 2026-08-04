#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/arena_strsearch.c
// (bpf-rs-core idiom), pulling in bpf_arena_strsearch.h's bpf_arena_strlen()
// and glob_match() it #includes.
//
// This environment's clang has __BPF_FEATURE_ADDR_SPACE_CAST (confirmed by
// arena_atomics.rs/arena_htab.rs), so pat/str/glob_tests are real
// `address_space(1)` pointers in the reference object, with the frontend
// inserting `addrspacecast` implicitly. rustc has no addrspace-qualified
// pointer type, so — same as arena_atomics.rs's `cast_kern` / arena_htab.rs's
// cast_kern+cast_user pair — a hand-encoded `bpf_addr_space_cast` asm
// sequence stands in. Only one cast is needed here (read-only traversal,
// nothing written back into the arena or handed to userspace): `glob_tests`'s
// base address is cast once from AS1 (scalar ld_imm64 relocated against the
// arena map) to a kernel-usable PTR_TO_ARENA register; every pointer derived
// from it afterwards via ordinary `.add()` arithmetic keeps that verifier
// type, matching how PTR_TO_MAP_VALUE survives ALU offsetting.
//
// `bpf_arena_strlen`/`glob_match` are real GLOBAL FUNC symbols (external
// linkage, no `static` in the C source) in the reference object's symtab.
// A first attempt kept them as matching `#[no_mangle] extern "C" fn`s, but
// that hits a hard verifier wall: a GLOBAL (BTF_FUNC_GLOBAL) subprogram's
// call sites are checked against its *abstract* BTF signature
// (`btf_check_func_arg_match` in kernel/bpf/btf.c), not simulated with the
// caller's real register state. A plain pointer parameter with no BTF type
// tag classifies as `ARG_PTR_TO_MEM`, whose accepted register kinds
// (`check_helper_mem_access`'s switch) do not include `PTR_TO_ARENA` — only
// a pointee tagged `btf_type_tag("arena")` (what C's `__arena` qualifier
// emits) gets the permissive `ARG_PTR_TO_ARENA` classification that accepts
// `PTR_TO_ARENA`/`SCALAR_VALUE` registers. rustc cannot emit
// `BTF_KIND_TYPE_TAG` (same wall as [[btf-type-tag-uptr-kptr-unfixable]]),
// so any GLOBAL Rust function taking an arena-derived pointer argument is
// rejected at every call site with "Caller passes invalid args into
// func#N", regardless of how the pointer was produced.
//
// Fix: translate them as plain **static** (non-`#[no_mangle]`, internal
// linkage) functions instead of matching the C symbols' external linkage.
// `check_func_call`'s BTF-based arg check is bypassed entirely for
// non-global subprograms (`btf_check_subprog_call`'s result is only fatal
// inside the `bpf_subprog_is_global()` branch); a static callee instead
// gets ordinary flow-sensitive pushdown verification with the caller's
// *real* `PTR_TO_ARENA` register state, which works with no tag needed —
// exactly like any other private helper in this codebase that takes an
// arena pointer (e.g. arena_htab.rs's `list_add_head`). Neither function is
// referenced anywhere outside this file (not in `arena_strsearch.skel.h`,
// not in `prog_tests/arena_strsearch.c`), so losing their GLOBAL bind /
// exact keep-list match costs nothing observable — `#[inline(never)]`
// keeps each as a real subprogram call (preserving the low verifier
// complexity the C source's `__noinline` was there for), just under
// internal linkage. `test()` is a small `static` C helper the compiler
// fully inlines into `arena_strsearch` (absent from the reference symtab);
// it's translated as a plain unexported fn here too.
//
// The C source's `for (;;) { ...; cond_break; }` / `do { ...; cond_break; }
// while (...)` loops are structurally unbounded, relying on `cond_break`
// (bpf_may_goto.h: an `asm goto` "may_goto" safepoint — a real BPF_JMP|
// BPF_JCOND instruction the verifier specially recognizes as self-limiting,
// letting it accept the loop via aggressive state pruning instead of
// requiring a provable scalar trip-count bound) for verifier acceptance.
//
// A first attempt replaced every `cond_break` with a plain `while i < BOUND`
// compile-time-bounded counter loop (the arena_htab.rs `MAX_BUCKET_WALK`
// pattern). That works for a simple linear walk, but not here: it made the
// verifier fall back to ordinary scalar-range widening to prove termination,
// which does not converge quickly for `glob_match`'s character-class loop
// (each iteration's freshly-loaded `a`/`class` byte gets a new scalar id, so
// the range only narrows by ~1 per modeled iteration) — nested three deep
// (dispatch loop x match loop x class loop) this blew straight through the
// verifier's 1,000,000-insn cap (`BPF program is too large`).
//
// Fix: reproduce the real `may_goto` mechanism instead of approximating it.
// `#![feature(asm_experimental_arch)]` (already needed for `cast_kern`'s
// hand-encoded arena cast) also unlocks inline-asm local numeric labels on
// the bpf target; `.byte 0xe5; .byte 0; .long ((<label> - <here> - 8) / 8) &
// 0xffff; .short 0` is bpf_may_goto.h's own non-`__BPF_FEATURE_MAY_GOTO`
// hand-encoding of the `may_goto` opcode (the fallback clang itself uses on
// compilers without native asm-goto support) — self-contained in one `asm!`
// string via GAS local labels (`1:`/`2f`/`3f`), so it needs no Rust-level
// `asm_goto` label-operand feature, just an ordinary `asm!` block. Each
// `cond_break`/`__cond_break(expr)` site becomes `if should_break() { <expr
// or break> }` at the exact same position in the loop body; every loop is
// otherwise written with its own real termination condition (nul byte, `]`,
// end of pattern) exactly as the C source has it, so `should_break()` firing
// is — like the real `cond_break` — pure verifier insurance that never
// actually triggers for this harness's tiny, well-formed test data.
//
// `glob_tests` itself is `static const char __arena glob_tests[]` — a LOCAL
// (not GLOBAL) OBJECT symbol in the reference object (confirmed via
// `readelf -s`: file-scope `static`, internal linkage), so per
// [[rust-no-elf-visibility-use-private-static]] it's a plain private
// (non-`#[no_mangle]`) `static` here, keeping natural internal linkage.
// `skip` is a GLOBAL `bool` in `.bss`, declared but never written anywhere
// in this file (same as the C source — nothing here ever sets it), so it
// stays at its zero-init default, matching prog_tests/arena_strsearch.c's
// expectation that the `skip` branch is never taken in this environment.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use core::ffi::c_void;

bpf_map! {
    arena {
        r#type: *const [i32; 33],       // BPF_MAP_TYPE_ARENA
        map_flags: *const [i32; 1024],  // BPF_F_MMAPABLE
        max_entries: *const [i32; 100], // number of pages
    }
}

/// In-place `bpf_addr_space_cast(ptr, 0, 1)`: converts a raw AS1 (arena)
/// address into the kernel-dereferencable PTR_TO_ARENA form. Register-name-
/// sniffing trick, byte-for-byte the same as arena_atomics.rs's `cast_kern`.
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

const N: usize = 748;

// Same literal byte content as the reference object's `.addr_space.1`
// section for `glob_tests` (extracted via `objcopy -O binary
// --only-section=.addr_space.1`), reproduced here rather than
// re-transcribed from the C source's string-literal concatenation to avoid
// any transcription error in the trickier character-class patterns.
#[allow(non_upper_case_globals)]
#[link_section = ".addr_space.1"]
static glob_tests: [u8; N] = *b"1a\0a\00a\0b\00a\0aa\00a\0\01\0\00\0a\01[a]\0a\00[a]\0b\00[!a]\0a\01[!a]\0b\01[ab]\0a\01[ab]\0b\00[ab]\0c\01[!ab]\0c\01[a-c]\0b\00[a-c]\0d\01[a-c-e-g]\0-\00[a-c-e-g]\0d\01[a-c-e-g]\0f\01[]a-ceg-ik[]\0a\01[]a-ceg-ik[]\0]\01[]a-ceg-ik[]\0[\01[]a-ceg-ik[]\0h\00[]a-ceg-ik[]\0f\00[!]a-ceg-ik[]\0h\00[!]a-ceg-ik[]\0]\01[!]a-ceg-ik[]\0f\01?\0a\00?\0aa\00??\0a\01?x?\0axb\00?x?\0abx\00?x?\0xab\00*??\0a\01*??\0ab\01*??\0abc\01*??\0abcd\00??*\0a\01??*\0ab\01??*\0abc\01??*\0abcd\00?*?\0a\01?*?\0ab\01?*?\0abc\01?*?\0abcd\01*b\0b\01*b\0ab\00*b\0ba\01*b\0bb\01*b\0abb\01*b\0bab\01*bc\0abbc\01*bc\0bc\01*bc\0bbc\01*bc\0bcbc\01*ac*\0abacadaeafag\01*ac*ae*ag*\0abacadaeafag\01*a*b*[bc]*[ef]*g*\0abacadaeafag\00*a*b*[ef]*[cd]*g*\0abacadaeafag\01*abcd*\0abcabcabcabcdefg\01*ab*cd*\0abcabcabcabcdefg\01*abcd*abcdef*\0abcabcdabcdeabcdefg\00*abcd*\0abcabcabcabcefg\00*ab*cd*\0abcabcabcabcefg\0\0";

#[no_mangle]
static mut skip: bool = false;

/// bpf_may_goto.h's `can_loop`/`__cond_break(expr)`, non-`__BPF_FEATURE_MAY_GOTO`
/// hand-encoding: a real `may_goto` (BPF_JMP|BPF_JCOND, opcode 0xe5)
/// instruction with its branch offset computed by the assembler via GAS
/// local-label arithmetic. Returns `true` when the verifier/runtime budget
/// this instruction guards is exhausted (call-site should break/return),
/// matching `cond_break`'s effective semantics. Self-contained (all labels
/// local to the single asm block), so safe to place at every loop's
/// safepoint without any cross-callsite label collision.
#[inline(always)]
unsafe fn should_break() -> bool {
    let mut r: u64 = 0;
    core::arch::asm!(
        "1:",
        ".byte 0xe5",
        ".byte 0",
        ".long ((2f - 1b - 8) / 8) & 0xffff",
        ".short 0",
        "goto 3f",
        "2:",
        "{r} = 1",
        "3:",
        r = inout(reg) r,
        options(nostack, preserves_flags),
    );
    r != 0
}

#[inline(never)]
unsafe fn bpf_arena_strlen(s: *const u8) -> i32 {
    let mut sc = s;
    let mut len: i32 = 0;
    while *sc != 0 {
        if should_break() {
            break;
        }
        sc = sc.add(1);
        len += 1;
    }
    len
}

#[inline(never)]
unsafe fn glob_match(pat0: *const u8, str0: *const u8) -> bool {
    unsafe {
        let mut pat = pat0;
        let mut str_ = str0;
        let mut back_pat: *const u8 = core::ptr::null();
        let mut back_str: *const u8 = core::ptr::null();

        loop {
            let c = *str_;
            str_ = str_.add(1);
            let d = *pat;
            pat = pat.add(1);

            match d {
                b'?' => {
                    if c == 0 {
                        return false;
                    }
                }
                b'*' => {
                    if *pat == 0 {
                        return true;
                    }
                    back_pat = pat;
                    str_ = str_.sub(1);
                    back_str = str_;
                }
                b'[' => {
                    let inverted = *pat == b'!';
                    let mut class = if inverted { pat.add(1) } else { pat };
                    let mut a = *class;
                    class = class.add(1);
                    let mut matched = false;
                    let mut malformed = false;

                    loop {
                        let mut b = a;
                        if a == 0 {
                            malformed = true;
                            break;
                        }
                        if *class == b'-' && *class.add(1) != b']' {
                            b = *class.add(1);
                            if b == 0 {
                                malformed = true;
                                break;
                            }
                            class = class.add(2);
                        }
                        matched |= a <= c && c <= b;
                        if should_break() {
                            break;
                        }
                        a = *class;
                        class = class.add(1);
                        if a == b']' {
                            break;
                        }
                    }

                    if malformed {
                        // goto literal (d is still '[' here).
                        if c == d {
                            if d == 0 {
                                return true;
                            }
                        } else {
                            if c == 0 || back_pat.is_null() {
                                return false;
                            }
                            pat = back_pat;
                            back_str = back_str.add(1);
                            str_ = back_str;
                        }
                    } else if matched == inverted {
                        // goto backtrack
                        if c == 0 || back_pat.is_null() {
                            return false;
                        }
                        pat = back_pat;
                        back_str = back_str.add(1);
                        str_ = back_str;
                    } else {
                        pat = class;
                    }
                }
                b'\\' => {
                    let d2 = *pat;
                    pat = pat.add(1);
                    if c == d2 {
                        if d2 == 0 {
                            return true;
                        }
                    } else {
                        if c == 0 || back_pat.is_null() {
                            return false;
                        }
                        pat = back_pat;
                        back_str = back_str.add(1);
                        str_ = back_str;
                    }
                }
                _ => {
                    if c == d {
                        if d == 0 {
                            return true;
                        }
                    } else {
                        if c == 0 || back_pat.is_null() {
                            return false;
                        }
                        pat = back_pat;
                        back_str = back_str.add(1);
                        str_ = back_str;
                    }
                }
            }

            if should_break() {
                break;
            }
        }
        false
    }
}

#[inline(never)]
unsafe fn test(pat: *const u8, s: *const u8, expected: bool) -> bool {
    let m = glob_match(pat, s);
    m == expected
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arena_strsearch(_ctx: *const c_void) -> i32 {
    unsafe {
        let mut p: *const u8 = cast_kern(core::ptr::addr_of!(glob_tests) as *mut u8) as *const u8;
        let mut successes: u32 = 0;
        let mut n: u32 = 0;

        while *p != 0 {
            let expected = (*p & 1) != 0;
            p = p.add(1);
            let pat = p;

            if should_break() {
                break;
            }
            let len1 = bpf_arena_strlen(p) as usize;
            p = p.add(len1 + 1);
            if test(pat, p, expected) {
                successes += 1;
            }
            let len2 = bpf_arena_strlen(p) as usize;
            p = p.add(len2 + 1);
            n += 1;
        }

        n -= successes;
        if n != 0 {
            -1
        } else {
            0
        }
    }
}

bpf_object!("GPL");
