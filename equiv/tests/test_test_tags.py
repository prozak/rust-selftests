"""Hermetic tests for the test_loader decl-tag pass (scripts/btf_test_tags.py)
and translint's bound on how far a message may be relaxed.

No kernel, no build tree: the BTF is synthesized here and read back with the
prover's own ELF reader, so a change that produces a blob bpfelf can't parse
fails immediately rather than at the next QEMU run.
"""
import os
import struct
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import btf_test_tags as T  # noqa: E402
import translint  # noqa: E402
from bpfelf import BpfElf  # noqa: E402


def write(tmp_path, text):
    p = tmp_path / "prog.rs"
    p.write_text(text)
    return str(p)


# --- source parsing ---------------------------------------------------------

def test_parses_the_documented_shape(tmp_path):
    src = write(tmp_path, '''
test_tags! {
    global_func1: __failure, __msg("combined stack size of 3 calls is");
}
''')
    assert T.parse_source(src) == [
        ("global_func1",
         ["test_expect_failure",
          "test_expect_msg=combined stack size of 3 calls is"])]


def test_multiple_programs_keep_source_order(tmp_path):
    src = write(tmp_path, '''
test_tags! {
    a: __success, __retval(0);
    b: __failure, __msg("x"), __msg("y");
}
''')
    assert T.parse_source(src) == [
        ("a", ["test_expect_success", "test_retval=0"]),
        ("b", ["test_expect_failure", "test_expect_msg=x",
               "test_expect_msg=y"])]


def test_no_declaration_is_not_an_error(tmp_path):
    assert T.parse_source(write(tmp_path, "fn main() {}\n")) == []


def test_a_commented_out_declaration_is_not_read(tmp_path):
    src = write(tmp_path, '// test_tags! { a: __failure; }\nfn f() {}\n')
    assert T.parse_source(src) == []


def test_semicolons_and_braces_inside_a_message_survive(tmp_path):
    src = write(tmp_path, '''
test_tags! {
    p: __msg("arg#0 expected pointer to ctx; got {{[a-z]+}}");
}
''')
    assert T.parse_source(src) == [
        ("p", ["test_expect_msg=arg#0 expected pointer to ctx; "
               "got {{[a-z]+}}"])]


def test_escaped_quote_in_a_message(tmp_path):
    src = write(tmp_path, r'''
test_tags! {
    p: __msg("expected \"foo\"");
}
''')
    assert T.parse_source(src) == [("p", ['test_expect_msg=expected "foo"'])]


@pytest.mark.parametrize("body,why", [
    ('p: __nonsense;', "unknown tag"),
    ('p: __failure("x");', "nullary tag given an argument"),
    ('p: __msg;', "valued tag without its argument"),
    ('p;', "entry without tags"),
])
def test_malformed_declarations_are_hard_errors(tmp_path, body, why):
    src = write(tmp_path, "test_tags! {\n    %s\n}\n" % body)
    with pytest.raises(T.TagError):
        T.parse_source(src)


def test_declares_failure_ignores_the_unprivileged_variant(tmp_path):
    # __failure_unpriv objects load fine privileged: they belong in the
    # veristat gate, unlike a privileged __failure.
    unpriv = write(tmp_path, 'test_tags! { p: __success, __failure_unpriv; }')
    assert not T.declares_failure(unpriv)
    priv = write(tmp_path, 'test_tags! { p: __failure; }')
    assert T.declares_failure(priv)


# --- BTF injection ----------------------------------------------------------

def synth_object(path, func_name="prog"):
    """Smallest ELF64-LE object with a .BTF holding one FUNC (id 2)."""
    strings = b"\0" + func_name.encode() + b"\0"
    types = b""
    types += struct.pack("<III", 0, 13 << 24, 0)            # [1] FUNC_PROTO
    types += struct.pack("<III", 1, (12 << 24) | 1, 1)      # [2] FUNC -> [1]
    btf = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(types),
                      len(types), len(strings)) + types + strings

    shstr = b"\0.BTF\0.shstrtab\0"
    ehsize, shentsize, shnum = 64, 64, 3
    data_off = ehsize
    btf_off = data_off
    shstr_off = btf_off + len(btf)
    shoff = shstr_off + len(shstr)
    out = bytearray()
    out += b"\x7fELF\x02\x01\x01" + b"\0" * 9
    out += struct.pack("<HHI", 1, 247, 1)                   # ET_REL, EM_BPF
    out += struct.pack("<QQQ", 0, 0, shoff)
    out += struct.pack("<IHHHHHH", 0, ehsize, 0, 0, shentsize, shnum, 2)
    assert len(out) == ehsize
    out += btf + shstr

    def shdr(name_off, typ, off, size, align):
        return struct.pack("<IIQQQQIIQQ", name_off, typ, 0, 0, off, size,
                           0, 0, align, 0)

    out += shdr(0, 0, 0, 0, 0)                               # SHT_NULL
    out += shdr(1, 1, btf_off, len(btf), 4)                  # .BTF
    out += shdr(6, 3, shstr_off, len(shstr), 1)              # .shstrtab
    open(path, "wb").write(bytes(out))


def read_tags(path):
    types = BpfElf(path).btf_types()
    funcs = {tid: t[1] for tid, t in types.items() if t[0] == 12}
    return [(t[1], funcs.get(t[2]))
            for _tid, t in sorted(types.items()) if t[0] == 17]


def test_injected_tags_read_back_as_the_loader_expects(tmp_path):
    obj = str(tmp_path / "prog.bpf.o")
    synth_object(obj)
    n = T.inject(obj, [("prog", ["test_expect_failure",
                                 "test_expect_msg=bad thing"])])
    assert n == 2
    assert read_tags(obj) == [
        ("comment:0:test_expect_failure", "prog"),
        ("comment:1:test_expect_msg=bad thing", "prog"),
    ]


def test_injection_leaves_existing_type_ids_alone(tmp_path):
    obj = str(tmp_path / "prog.bpf.o")
    synth_object(obj)
    before = BpfElf(obj).btf_types()
    T.inject(obj, [("prog", ["test_expect_failure"])])
    after = BpfElf(obj).btf_types()
    for tid, t in before.items():
        assert after[tid] == t, f"type id {tid} moved"


def test_injection_rejects_an_unknown_program(tmp_path):
    obj = str(tmp_path / "prog.bpf.o")
    synth_object(obj)
    with pytest.raises(T.TagError):
        T.inject(obj, [("not_a_prog", ["test_expect_failure"])])


# --- the relaxation bound ---------------------------------------------------

@pytest.mark.parametrize("c_msg,rust_msg", [
    ("R1 type=scalar expected=fp", "{{R[0-9]}} type=scalar expected=fp"),
    ("invalid read from stack off=-8", "invalid read from stack {{off=-[0-9]+}}"),
    ("misaligned access off fp-24", "misaligned access off {{fp-[0-9]+}}"),
])
def test_codegen_tokens_may_be_relaxed(c_msg, rust_msg):
    assert translint.normalize_msg(c_msg) == translint.normalize_msg(rust_msg)


@pytest.mark.parametrize("c_msg,rust_msg", [
    # the assertion itself wildcarded away
    ("R1 type=scalar expected=fp", "{{.*}}"),
    # a semantic token relaxed, not a codegen-dependent one
    ("Unreleased reference id=2 alloc_insn=8",
     "Unreleased {{[a-z]+}} id=2 alloc_insn=8"),
    # a different message entirely
    ("combined stack size of 3 calls is", "invalid read from stack"),
])
def test_widening_past_codegen_tokens_is_caught(c_msg, rust_msg):
    assert translint.normalize_msg(c_msg) != translint.normalize_msg(rust_msg)
