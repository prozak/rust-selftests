"""Hermetic prover tests: no kernel, no build tree, no binary fixtures.

These encode the negative controls the model was validated against while
it was being built — each one is a property the prover must keep: an
equivalent pair proves EQUIV, and each class of divergence we have
actually seen in real translations is DETECTED.
"""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from testkit import asm, compare  # noqa: E402

R0, R1, R2, R6, R10 = 0, 1, 2, 6, 10
MAP = {"m": {"key_size": 4, "value_size": 8, "map_type": 1,
             "max_entries": 4, "inner": None}}


def verdict(a, b, **kw):
    return compare(a, b, **kw)[0]


# ---------------------------------------------------------------- baseline

def test_identical_programs_prove_equivalent():
    p = asm.prog(asm.mov64_imm(R0, 7), asm.exit_())
    assert verdict(p, p) == "EQUIV"


def test_same_value_computed_differently_is_equivalent():
    """The prover must see through syntactic differences."""
    a = asm.prog(asm.mov64_imm(R0, 6), asm.add64_imm(R0, 1), asm.exit_())
    b = asm.prog(asm.mov64_imm(R0, 7), asm.exit_())
    assert verdict(a, b) == "EQUIV"


def test_differing_return_constant_is_detected():
    a = asm.prog(asm.mov64_imm(R0, 1), asm.exit_())
    b = asm.prog(asm.mov64_imm(R0, 2), asm.exit_())
    assert verdict(a, b) == "INEQUIV"


# ------------------------------------------------- divergence classes seen

def test_differing_ctx_load_offset_is_detected():
    """A field read at the wrong offset — the commonest CO-RE-style bug."""
    a = asm.prog(asm.ldx(4, R0, R1, 0), asm.exit_())
    b = asm.prog(asm.ldx(4, R0, R1, 4), asm.exit_())
    assert verdict(a, b) == "INEQUIV"


def test_differing_store_width_is_detected():
    """A 4-byte store where C writes 8 leaves residue (skmsg class)."""
    g = {"out": b"\x00" * 8}
    store8 = asm.prog(asm.ld_imm64(R1, 0), asm.st_imm(8, R1, 0, 5),
                      asm.mov64_imm(R0, 0), asm.exit_())
    store4 = asm.prog(asm.ld_imm64(R1, 0), asm.st_imm(4, R1, 0, 5),
                      asm.mov64_imm(R0, 0), asm.exit_())
    assert verdict(store8, store4, globals_=g,
                   relocs={0: "out"}) == "INEQUIV"


def test_signed_vs_unsigned_compare_is_detected():
    """`u32 > int` compares unsigned in C (sockmap_strp class)."""
    # load a scalar from the ctx first (r1 itself is the ctx POINTER),
    # then compare it signed vs unsigned
    signed = asm.prog(asm.ldx(8, R1, R1, 0),
                      asm.raw(0x65, R1, off=1, imm=10),   # JSGT r1, 10
                      asm.mov64_imm(R0, 0), asm.exit_())
    unsigned = asm.prog(asm.ldx(8, R1, R1, 0),
                        asm.jgt_imm(R1, 10, 1),
                        asm.mov64_imm(R0, 0), asm.exit_())
    assert verdict(signed, unsigned) == "INEQUIV"


def test_bool_compare_against_one_vs_zero_is_detected():
    """clang emits `jne 1` at some sites and `jne 0` at others; a
    translation must mirror its own site (test_sockmap_listen class)."""
    ne_one = asm.prog(asm.ldx(1, R1, R1, 0), asm.jne_imm(R1, 1, 1),
                      asm.mov64_imm(R0, 9), asm.exit_())
    ne_zero = asm.prog(asm.ldx(1, R1, R1, 0), asm.jne_imm(R1, 0, 1),
                       asm.mov64_imm(R0, 9), asm.exit_())
    assert verdict(ne_one, ne_zero) == "INEQUIV"


def test_masking_a_ctx_word_is_detected():
    """Masking to a byte/half where C tests the full word
    (timer_start_deadlock / test_tc_dtime class)."""
    full = asm.prog(asm.ldx(8, R1, R1, 16), asm.jeq_imm(R1, 0, 1),
                    asm.mov64_imm(R0, 1), asm.exit_())
    masked = asm.prog(asm.ldx(8, R1, R1, 16), asm.and64_imm(R1, 0xFF),
                      asm.jeq_imm(R1, 0, 1),
                      asm.mov64_imm(R0, 1), asm.exit_())
    assert verdict(full, masked) == "INEQUIV"


def test_dropped_helper_call_is_detected():
    """A missing side-effecting call diverges the trace observable
    (the dropped-bpf_printk class, 13 real sites)."""
    with_call = asm.prog(asm.ld_imm64(R1, 0), asm.mov64_imm(R2, 4),
                         asm.call(6), asm.mov64_imm(R0, 0), asm.exit_())
    without = asm.prog(asm.mov64_imm(R0, 0), asm.exit_())
    assert verdict(with_call, without, rodata=b"hi\x00\x00",
                   relocs={0: ".rodata"}) == "INEQUIV"


def test_equivalent_helper_sequences_prove():
    """Identical call sequences must still prove (no false positives from
    the trace machinery)."""
    p = asm.prog(asm.call(5), asm.mov64_imm(R0, 0), asm.exit_())
    assert verdict(p, p) == "EQUIV"


def test_shared_oracle_makes_env_reads_agree():
    """Two calls to the same env helper agree across objects, so a program
    that returns ktime proves equivalent to itself."""
    p = asm.prog(asm.call(5), asm.exit_())          # r0 = ktime
    assert verdict(p, p) == "EQUIV"


def test_extra_env_call_shifts_the_oracle_stream():
    """An extra environment read is a real difference: the nth call is what
    is shared, so an added call makes the returned values disagree."""
    one = asm.prog(asm.call(5), asm.exit_())
    two = asm.prog(asm.call(5), asm.mov64_reg(R6, R0), asm.call(5),
                   asm.exit_())
    assert verdict(one, two) == "INEQUIV"


# ------------------------------------------------------------- path logic

def test_branch_both_sides_equivalent():
    a = asm.prog(asm.jeq_imm(R1, 0, 2),
                 asm.mov64_imm(R0, 1), asm.exit_(),
                 asm.mov64_imm(R0, 2), asm.exit_())
    b = asm.prog(asm.jne_imm(R1, 0, 2),
                 asm.mov64_imm(R0, 2), asm.exit_(),
                 asm.mov64_imm(R0, 1), asm.exit_())
    assert verdict(a, b) == "EQUIV"


def test_inverted_branch_is_detected():
    a = asm.prog(asm.jeq_imm(R1, 0, 2),
                 asm.mov64_imm(R0, 1), asm.exit_(),
                 asm.mov64_imm(R0, 2), asm.exit_())
    b = asm.prog(asm.jeq_imm(R1, 0, 2),
                 asm.mov64_imm(R0, 2), asm.exit_(),
                 asm.mov64_imm(R0, 1), asm.exit_())
    assert verdict(a, b) == "INEQUIV"


@pytest.mark.parametrize("width", [1, 2, 4, 8])
def test_stack_roundtrip_is_equivalent(width):
    p = asm.prog(asm.mov64_imm(R1, 42),
                 asm.stx(width, R10, R1, -8),
                 asm.ldx(width, R0, R10, -8),
                 asm.exit_())
    assert verdict(p, p) == "EQUIV"


# ---------------------------------------------- bpf2bpf frame semantics

def test_subprog_call_preserves_the_caller_frame():
    """A bpf2bpf call gives the callee its OWN frame: the verifier keeps
    the caller's whole register file and copies back only r0
    (prepare_func_exit). A callee that clobbers r6 must NOT disturb the
    caller's r6 — modelling this wrong made a saved ctx pointer come back
    as a packet-derived scalar (the test_tc_dtime divergence)."""
    # caller: r6 = ctx; call subprog (which clobbers r6); return *(r6+0)
    caller = asm.prog(
        asm.mov64_reg(R6, R1),
        asm.raw(0x85, src=1, imm=2),      # call -> insn 4 (the subprog)
        asm.ldx(8, R0, R6, 0),
        asm.exit_(),
        # subprog: clobber r6 and return
        asm.mov64_imm(R6, 0x1234),
        asm.mov64_imm(R0, 0),
        asm.exit_())
    # equivalent program that simply reads the ctx without any call
    inlined = asm.prog(asm.ldx(8, R0, R1, 0), asm.exit_())
    assert verdict(caller, inlined) == "EQUIV"


def test_subprog_return_value_flows_back():
    """r0 IS copied back from the callee."""
    with_call = asm.prog(
        asm.raw(0x85, src=1, imm=1),      # call +1
        asm.exit_(),
        asm.mov64_imm(R0, 77),
        asm.exit_())
    direct = asm.prog(asm.mov64_imm(R0, 77), asm.exit_())
    assert verdict(with_call, direct) == "EQUIV"
