"""Unit tests for the non-solver parts: symbol demangling, CO-RE matching,
and the translation linter. All hermetic."""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EQUIV = os.path.dirname(HERE)
REPO = os.path.dirname(EQUIV)
sys.path.insert(0, EQUIV)

import bpfcore  # noqa: E402
from bpfelf import normalize_name  # noqa: E402


# ------------------------------------------------------ symbol demangling

def test_v0_mangled_single_digit_length():
    assert normalize_name("_RNvCs123_13modify_return8sequence.0") == "sequence"


def test_v0_mangled_multi_digit_length():
    """A greedy regex used to grab only the LAST digit of a two-digit
    length, so every name of 10+ characters stayed mangled — which silently
    broke callback-identity and global-region matching."""
    assert normalize_name(
        "_RNvCsbhNUiiKqe0L_5timer15timer_cb_pinned") == "timer_cb_pinned"
    assert normalize_name(
        "_RNvCs7wFjWr1qPR7_7lru_bug13last_ptr_addr.0") == "last_ptr_addr"


def test_function_local_statics_from_both_compilers():
    """clang emits `<func>.<var>`, rustc (demoted) emits `<var>.<n>`;
    both must reduce to the same region name."""
    assert normalize_name("xsk_xdp_drop.drop_idx") == "drop_idx"
    assert normalize_name("drop_idx.0") == "drop_idx"


def test_plain_names_are_untouched():
    assert normalize_name("count_hardirq") == "count_hardirq"


# ------------------------------------------------------------ CO-RE logic

def test_essential_name_strips_flavor():
    assert bpfcore.essential_name("task_struct___local") == "task_struct"
    assert bpfcore.essential_name("task_struct") == "task_struct"


def test_names_match_treats_empty_target_as_wildcard():
    assert bpfcore._names_match("anything", "") is False
    assert bpfcore._names_match("", "") is True
    assert bpfcore._names_match("sock___v2", "sock") is True


def test_relo_kind_tables_are_disjoint_and_complete():
    """Every kind 0..12 must be classified exactly once."""
    all_kinds = (bpfcore.FIELD_RELOS | bpfcore.TYPE_RELOS
                 | bpfcore.ENUM_RELOS)
    assert all_kinds == set(range(13))
    assert not (bpfcore.FIELD_RELOS & bpfcore.TYPE_RELOS)
    assert not (bpfcore.FIELD_RELOS & bpfcore.ENUM_RELOS)
    assert not (bpfcore.TYPE_RELOS & bpfcore.ENUM_RELOS)


# --------------------------------------------------------------- translint

def _lint(source):
    """Run translint against a temporary translation and return its output."""
    progs = os.path.join(REPO, "progs")
    fd, path = tempfile.mkstemp(suffix=".rs", prefix="ztranslint_",
                                dir=progs)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(source)
        name = os.path.basename(path)[:-3]
        p = subprocess.run([sys.executable,
                            os.path.join(REPO, "scripts", "translint.py"),
                            name],
                           capture_output=True, text=True)
        return p.stdout
    finally:
        os.unlink(path)


def test_lint_flags_branched_bool_global():
    out = _lint("static mut flag: bool = false;\n"
                "fn f() -> i32 { if unsafe { flag } { 1 } else { 0 } }\n")
    assert "bool-global" in out and "ERROR" in out


def test_lint_ignores_write_only_bool_global():
    out = _lint("static mut skip: bool = false;\n"
                "fn f() { unsafe { skip = true; } }\n")
    assert "ERROR" not in out


def test_lint_ignores_bool_mentioned_only_in_a_comment():
    """Comments must not count as uses (they did, and produced false
    positives on already-proved files)."""
    out = _lint("// the flag is compared == 1 by clang here\n"
                "static mut flag: bool = false;\n"
                "fn f() { unsafe { flag = true; } }\n")
    assert "ERROR" not in out


def test_lint_flags_implicit_struct_padding():
    out = _lint("#[repr(C)]\nstruct v { a: u8, b: u32 }\n")
    assert "padding" in out


def test_lint_accepts_explicit_padding():
    out = _lint("#[repr(C)]\nstruct v { a: u8, _pad: [u8; 3], b: u32 }\n")
    assert "padding" not in out


def test_lint_flags_out_of_int_hex_literal():
    out = _lint("const MAGIC: i64 = 0xabcd1234;\n")
    assert "big-hex" in out
