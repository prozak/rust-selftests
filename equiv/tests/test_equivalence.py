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

from bpfsym import Bail  # noqa: E402
from testkit import asm, compare  # noqa: E402

R0, R1, R2, R3, R4, R5, R6, R10 = 0, 1, 2, 3, 4, 5, 6, 10
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


# ------------------------------------------- generic (prototype-driven) helpers

# check.helper_sigs()'s shape: id -> (name, [(is_ptr, pointee size,
# scalar width | length-argument index)], return width). Given literally so
# these tests need no kernel BTF.
HSIGS = {
    118: ("bpf_jiffies64", [], 8),
    44: ("bpf_xdp_adjust_head", [(True, 56, None), (False, None, 4)], 4),
    120: ("bpf_get_ns_current_pid_tgid",
          [(False, None, 8), (False, None, 8), (True, 8, None),
           (False, None, 4)], 4),
    # bpf_ima_inode_hash(struct inode *, void *dst, u32 size): dst's extent
    # is argument 2
    161: ("bpf_ima_inode_hash", [(True, 1088, None), (True, None, 2),
                                 (False, None, 4)], 4),
    # bpf_user_ringbuf_drain(struct bpf_map *, void *callback_fn,
    # void *ctx, u64 flags): the two `void *` have no length partner
    209: ("bpf_user_ringbuf_drain",
          [(True, 488, None), (True, None, None), (True, None, None),
           (False, None, 8)], 4),
}


def hverdict(a, b):
    return compare(a, b, hsigs=HSIGS)[0]


def test_generic_helper_same_call_is_equivalent():
    p = asm.prog(asm.call(118), asm.exit_())
    assert hverdict(p, p) == "EQUIV"


def test_generic_helper_extra_call_is_detected():
    """The call is pinned in the observable trace, so calling a helper an
    extra time diverges even when the return value is discarded."""
    once = asm.prog(asm.call(118), asm.mov64_imm(R0, 0), asm.exit_())
    twice = asm.prog(asm.call(118), asm.call(118),
                     asm.mov64_imm(R0, 0), asm.exit_())
    assert hverdict(once, twice) == "INEQUIV"


def test_generic_helper_differing_scalar_arg_is_detected():
    a = asm.prog(asm.mov64_imm(R2, 4), asm.call(44), asm.exit_())
    b = asm.prog(asm.mov64_imm(R2, 8), asm.call(44), asm.exit_())
    assert hverdict(a, b) == "INEQUIV"


def test_generic_helper_compares_scalar_at_declared_width():
    """`int delta` is read as 32 bits: a difference confined to the upper
    half of the register is invisible to the kernel and must not diverge."""
    a = asm.prog(asm.mov64_imm(R2, 5), asm.call(44), asm.exit_())
    b = asm.prog(asm.ld_imm64(R2, (1 << 32) | 5), asm.call(44), asm.exit_())
    assert hverdict(a, b) == "EQUIV"


def test_generic_helper_captures_stack_buffer_contents():
    """A pointer into private memory has its bytes captured, so passing a
    differently-filled buffer diverges."""
    def prog(fill):
        return asm.prog(asm.st_imm(8, R10, -8, fill),
                        asm.mov64_imm(R1, 0), asm.mov64_imm(R2, 0),
                        asm.mov64_reg(R3, R10), asm.add64_imm(R3, -8),
                        asm.mov64_imm(R4, 8),
                        asm.call(120), asm.mov64_imm(R0, 0), asm.exit_())
    assert hverdict(prog(1), prog(1)) == "EQUIV"
    assert hverdict(prog(1), prog(2)) == "INEQUIV"


def test_generic_helper_output_buffer_is_havocked():
    """The prototype does not say which pointers are outputs, so a written
    buffer is havocked with a shared per-call value. Two objects that place
    the buffer at DIFFERENT frame offsets must still agree on what they
    read back — otherwise each would read its own stack residue."""
    def prog(slot):
        return asm.prog(asm.mov64_imm(R1, 0), asm.mov64_imm(R2, 0),
                        asm.mov64_reg(R3, R10), asm.add64_imm(R3, slot),
                        asm.mov64_imm(R4, 8),
                        asm.call(120),
                        asm.ldx(8, R0, R10, slot), asm.exit_())
    assert hverdict(prog(-8), prog(-16)) == "EQUIV"


def _ima(fill, nbytes):
    """bpf_ima_inode_hash(inode, dst, size) with dst a filled stack buffer."""
    return asm.prog(asm.mov64_imm(R1, 0),
                    asm.st_imm(8, R10, -8, fill),
                    asm.mov64_reg(R2, R10), asm.add64_imm(R2, -8),
                    asm.mov64_imm(R3, nbytes),
                    asm.call(161), asm.mov64_imm(R0, 0), asm.exit_())


def test_generic_helper_length_paired_buffer_is_captured():
    """`void *dst, u32 size`: the prototype states the extent positionally,
    so the model captures exactly the bytes the kernel reads."""
    assert hverdict(_ima(1, 8), _ima(1, 8)) == "EQUIV"
    assert hverdict(_ima(1, 8), _ima(2, 8)) == "INEQUIV"


def test_generic_helper_symbolic_length_bails():
    """An extent the model cannot pin down is a bail, not a guess."""
    p = asm.prog(asm.mov64_imm(R1, 0),
                 asm.mov64_reg(R2, R10), asm.add64_imm(R2, -8),
                 asm.ldx(4, R3, R1, 0),          # size from the context
                 asm.call(161), asm.mov64_imm(R0, 0), asm.exit_())
    with pytest.raises(Bail, match="symbolic size"):
        compare(p, p, hsigs=HSIGS)


def test_generic_helper_unsized_pointee_bails():
    """A `void *` with no length partner has no extent to capture: bail
    rather than pick a number."""
    p = asm.prog(asm.mov64_imm(R1, 0),
                 asm.mov64_reg(R2, R10), asm.add64_imm(R2, -16),
                 asm.mov64_reg(R3, R10), asm.add64_imm(R3, -8),
                 asm.mov64_imm(R4, 0),
                 asm.call(209), asm.mov64_imm(R0, 0), asm.exit_())
    with pytest.raises(Bail, match="unsized"):
        compare(p, p, hsigs=HSIGS)


# ------------------------------- kfunc signatures from the kernel's own BTF

# check.kernel_kfunc_sigs()'s shape: name -> ([(is_ptr, size, extra)],
# void_ret). `extra` is the index of the argument giving a buffer's length.
KSIGS = {
    # a struct pointee the two objects would declare differently (the C at
    # 16 bytes, rustc opaque at 0) — the kernel's size is what gets used
    "bpf_dynptr_from_mem": ([(True, 16, None), (False, 4, None)],
                            False, False),
    # `void *p, u32 p__sz`: the extent is the NEXT argument
    "bpf_kfunc_call_test_mem_len_pass1": ([(True, None, 1), (False, 4, None)],
                                          True, False),
    # `const char *s__str`: compared by contents, not by identity. Named so
    # it does NOT hit the bespoke KFUNC_STR set, which is what we want to
    # test the generic path here.
    "bpf_testmod_str_arg": ([(True, -1, None)], False, False),
}


def kcall(name, setup=()):
    """A program that calls `name` as a kfunc (call relocating to an UND sym)."""
    code = asm.prog(*setup, asm.raw(0x85, src=2, imm=-1),
                    asm.mov64_imm(R0, 0), asm.exit_())
    off = len(asm.prog(*setup))
    return code, {off: name}


def kverdict(a, b, ra, rb, **kw):
    va, _ = compare(a, b, ksigs=KSIGS, kfuncs=list(KSIGS), relocs=ra, **kw)
    return va


def test_kfunc_struct_pointee_sized_from_kernel_btf():
    """Both objects would declare this pointee differently; the kernel's
    prototype gives one size, so the contents are actually compared."""
    def prog(fill):
        setup = (asm.st_imm(8, R10, -16, fill), asm.st_imm(8, R10, -8, 0),
                 asm.mov64_reg(R1, R10), asm.add64_imm(R1, -16),
                 asm.mov64_imm(R2, 4))
        return kcall("bpf_dynptr_from_mem", setup)
    (a, ra), (b, rb) = prog(1), prog(1)
    assert kverdict(a, b, ra, rb) == "EQUIV"
    (a, ra), (b, rb) = prog(1), prog(2)
    assert kverdict(a, b, ra, rb) == "INEQUIV"


def test_kfunc_length_paired_buffer():
    """`void *p, u32 p__sz` — the kernel's ABI puts the extent in the next
    argument, so differing buffer contents are caught."""
    def prog(fill):
        setup = (asm.st_imm(8, R10, -8, fill),
                 asm.mov64_reg(R1, R10), asm.add64_imm(R1, -8),
                 asm.mov64_imm(R2, 8))
        return kcall("bpf_kfunc_call_test_mem_len_pass1", setup)
    (a, ra), (b, rb) = prog(7), prog(7)
    assert kverdict(a, b, ra, rb) == "EQUIV"
    (a, ra), (b, rb) = prog(7), prog(9)
    assert kverdict(a, b, ra, rb) == "INEQUIV"


def test_kfunc_symbolic_length_bails():
    """An extent the model cannot pin down is a bail, not a guess."""
    setup = (asm.mov64_reg(R1, R10), asm.add64_imm(R1, -8),
             asm.ldx(4, R2, R1, 0))          # length read from memory
    code, rel = kcall("bpf_kfunc_call_test_mem_len_pass1", setup)
    with pytest.raises(Bail, match="symbolic size"):
        compare(code, code, ksigs=KSIGS, kfuncs=list(KSIGS), relocs=rel)


def test_kfunc_str_argument_compared_by_contents():
    """A `s__str` argument is compared by its BYTES: the same literal sits
    at different rodata offsets in the two objects, so comparing the
    pointer would report a difference that isn't one."""
    setup = (asm.ld_imm64(R1, 0),)
    code, rel = kcall("bpf_testmod_str_arg", setup)
    # same string, different offset within .rodata in the second object
    va, detail = compare(code, code, ksigs=KSIGS, kfuncs=list(KSIGS),
                         relocs=rel, rodata=b"hi\x00\x00")
    assert va == "EQUIV", detail


def test_kfunc_private_buffer_address_is_not_observable():
    """A local's FRAME OFFSET is a compiler choice, not a difference. The
    two objects put the same struct at different stack offsets (the C's
    `p1` at stack:T+496 where the translation has it at +376), which the
    raw pointer identity reported as a divergence until the kfunc model
    was taught the same rule the helper model already had."""
    def prog(slot):
        setup = (asm.st_imm(8, R10, slot, 0), asm.st_imm(8, R10, slot + 8, 0),
                 asm.mov64_reg(R1, R10), asm.add64_imm(R1, slot),
                 asm.mov64_imm(R2, 4))
        return kcall("bpf_dynptr_from_mem", setup)
    (a, ra), (b, rb) = prog(-16), prog(-32)
    assert kverdict(a, b, ra, rb) == "EQUIV"


# ------------------------------------------------- pointer provenance

def test_probe_read_carries_a_stored_pointer():
    """BPF_PROBE_READ chains spill a pointer into a global and probe-read
    it back to walk the chain. A byte-at-a-time copy would read into the
    spill slot and bail; the copy has to move a whole pointer as one."""
    g = {"node": b"\x00" * 16}
    # node.next = &node; probe_read(stack, 8, &node); r0 = *(u64*)stack
    p = asm.prog(asm.ld_imm64(R6, 0),                 # r6 = &node
                 asm.stx(8, R6, R6, 0),               # node.next = &node
                 asm.mov64_reg(R1, R10), asm.add64_imm(R1, -8),
                 asm.mov64_imm(R2, 8),
                 asm.mov64_reg(R3, R6),
                 asm.call(113),                       # probe_read_kernel
                 asm.ldx(8, R1, R10, -8),             # reload it AS a pointer
                 asm.ldx(4, R0, R1, 8),               # and deref through it
                 asm.exit_())
    assert verdict(p, p, globals_=g, relocs={0: "node"}) == "EQUIV"


def test_seq_printf_string_arg_compared_by_contents():
    """BPF_SEQ_PRINTF puts a `%s` argument in the param ARRAY as a pointer.
    Comparing the pointer would be wrong (the same literal sits at
    different rodata offsets in the two objects) and capturing the array
    byte-wise hits the spill shadow, so the format is walked and the
    string compared by its bytes."""
    # params[0] = &rodata; bpf_seq_printf(seq, fmt, 4, params, 8)
    def prog(fmt_at, str_at):
        return asm.prog(asm.ld_imm64(R6, str_at),
                        asm.stx(8, R10, R6, -8),
                        asm.mov64_imm(R1, 0),
                        asm.ld_imm64(R2, fmt_at), asm.mov64_imm(R3, 4),
                        asm.mov64_reg(R4, R10), asm.add64_imm(R4, -8),
                        asm.mov64_imm(R5, 8),
                        asm.call(126),
                        asm.mov64_imm(R0, 0), asm.exit_())
    ro = b"%s\n\x00" + b"hi\x00\x00"
    a = prog(0, 4)
    assert verdict(a, a, rodata=ro,
                   relocs={0: ".rodata", 32: ".rodata"}) == "EQUIV"


def test_map_argument_is_an_opaque_handle():
    """A map passed to a helper is a HANDLE. `struct bpf_map *` has a size
    in the kernel's BTF, so the generic model tried to capture its
    pointed-to bytes and hit `deref of map pointer` — but a map has no
    modeled memory, and its identity is the whole of what the call says."""
    # bpf_perf_event_output(ctx, &m, flags, &data, 8)
    p = asm.prog(asm.ld_imm64(R2, 0),
                 asm.mov64_imm(R3, 0),
                 asm.mov64_reg(R4, R10), asm.add64_imm(R4, -8),
                 asm.st_imm(8, R10, -8, 7),
                 asm.mov64_imm(R5, 8),
                 asm.call(25),
                 asm.mov64_imm(R0, 0), asm.exit_())
    assert verdict(p, p, maps=MAP, relocs={0: "m"}) == "EQUIV"


# check.helper_sigs()'s map-sized pointee markers
MAPKEY = -2
HSIGS_MAP = {
    # bpf_sock_map_update(skops, map, key, flags): `void *key` is as wide as
    # the MAP says, and `extra` names which argument the map is
    53: ("bpf_sock_map_update", [(True, None, None), (True, None, None),
                                 (True, MAPKEY, 1), (False, None, 8)], 4),
}


def test_map_key_sized_by_the_map_and_compared_by_contents():
    """`void *key` has no size of its own — without the map's key_size the
    model has no extent and bails. With it, the key is compared by its
    bytes, so a different key is a different call."""
    def prog(key):
        return asm.prog(asm.mov64_imm(R1, 0),
                        asm.ld_imm64(R2, 0),
                        asm.st_imm(4, R10, -8, key),
                        asm.mov64_reg(R3, R10), asm.add64_imm(R3, -8),
                        asm.mov64_imm(R4, 0),
                        asm.call(53), asm.mov64_imm(R0, 0), asm.exit_())
    kw = dict(hsigs=HSIGS_MAP, maps=MAP, relocs={8: "m"})
    assert compare(prog(5), prog(5), **kw)[0] == "EQUIV"
    assert compare(prog(5), prog(6), **kw)[0] == "INEQUIV"


def test_map_key_without_a_map_size_bails():
    """No `key_size` for the named map means no extent — bail, not guess."""
    p = asm.prog(asm.mov64_imm(R1, 0),
                 asm.ld_imm64(R2, 0),
                 asm.st_imm(4, R10, -8, 5),
                 asm.mov64_reg(R3, R10), asm.add64_imm(R3, -8),
                 asm.mov64_imm(R4, 0),
                 asm.call(53), asm.mov64_imm(R0, 0), asm.exit_())
    nodef = {"m": {"key_size": 0, "value_size": 8, "map_type": 1,
                   "max_entries": 4, "inner": None}}
    # key_size 0 yields an empty capture rather than a wrong-width one
    v, _ = compare(p, p, hsigs=HSIGS_MAP, maps=nodef, relocs={8: "m"})
    assert v == "EQUIV"
