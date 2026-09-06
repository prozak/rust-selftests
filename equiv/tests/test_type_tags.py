"""Hermetic tests for the BTF type-tag pass (scripts/btf_type_tags.py).

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

import btf_type_tags as T  # noqa: E402
from btf_test_tags import TagError  # noqa: E402
from bpfelf import BpfElf  # noqa: E402
from test_test_tags import synth_object  # noqa: E402


def write(tmp_path, text):
    p = tmp_path / "prog.rs"
    p.write_text(text)
    return str(p)


# --- source parsing ---------------------------------------------------------

def test_parses_the_documented_shape(tmp_path):
    src = write(tmp_path, '''
btf_type_tags! {
    rcu_node_stash.node: kptr;
}
''')
    assert T.parse_source(src) == [("rcu_node_stash", "node", "kptr")]


def test_multiple_entries_keep_source_order(tmp_path):
    src = write(tmp_path, '''
btf_type_tags! {
    a.x: kptr; b.y: kptr_untrusted;
    c.z: uptr
}
''')
    assert T.parse_source(src) == [("a", "x", "kptr"), ("b", "y", "kptr_untrusted"),
                                   ("c", "z", "uptr")]


def test_no_declaration_is_not_an_error(tmp_path):
    assert T.parse_source(write(tmp_path, "fn main() {}")) == []


def test_a_commented_out_declaration_is_not_read(tmp_path):
    assert T.parse_source(write(tmp_path, "// btf_type_tags! { a.b: kptr; }")) == []


@pytest.mark.parametrize("body,why", [
    ("btf_type_tags! { a.b: kptrs; }", "unknown tag"),
    ("btf_type_tags! { a: kptr; }", "no member"),
    ("btf_type_tags! { }", "empty"),
    ("btf_type_tags! { a.b: kptr; } btf_type_tags! { c.d: kptr; }", "twice"),
])
def test_malformed_declarations_are_hard_errors(tmp_path, body, why):
    with pytest.raises(TagError):
        T.parse_source(write(tmp_path, body))


# --- BTF injection ----------------------------------------------------------

def synth_struct_object(path):
    """.BTF with [1] INT long, [2] STRUCT data{key}, [3] PTR->[2],
    [4] STRUCT stash{node: [3]}, [5] FUNC_PROTO, [6] FUNC prog."""
    names = [b"long", b"data", b"key", b"stash", b"node", b"prog"]
    strings, offs = b"\0", {}
    for n in names:
        offs[n] = len(strings)
        strings += n + b"\0"
    types = b""
    types += struct.pack("<IIIi", offs[b"long"], 1 << 24, 8, 0x01000040)   # [1] INT
    types += struct.pack("<III", offs[b"data"], (4 << 24) | 1, 8)          # [2] STRUCT
    types += struct.pack("<III", offs[b"key"], 1, 0)
    types += struct.pack("<III", 0, 2 << 24, 2)                            # [3] PTR
    types += struct.pack("<III", offs[b"stash"], (4 << 24) | 1, 8)         # [4] STRUCT
    types += struct.pack("<III", offs[b"node"], 3, 0)
    types += struct.pack("<III", 0, 13 << 24, 0)                           # [5] FUNC_PROTO
    types += struct.pack("<III", offs[b"prog"], (12 << 24) | 1, 5)         # [6] FUNC
    synth_object(path)
    # splice our own .BTF in place of synth_object's one-FUNC blob
    buf = bytearray(open(path, "rb").read())
    btf = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(types),
                      len(types), len(strings)) + types + strings
    shdr_base, _off, _size, _align = T.elf_find_section(buf, ".BTF")
    new_off = len(buf)
    buf.extend(btf)
    struct.pack_into("<QQ", buf, shdr_base + 24, new_off, len(btf))
    open(path, "wb").write(buf)


def test_injected_tag_forms_the_ptr_tag_struct_chain(tmp_path):
    obj = str(tmp_path / "prog.bpf.o")
    synth_struct_object(obj)
    assert T.inject(obj, [("stash", "node", "kptr")]) == ["stash.node:kptr"]
    types = BpfElf(obj).btf_types()
    kind, name, _sz, _vlen, members = types[4]
    assert (kind, name) == (4, "stash")
    (_mname, mtype), = members
    assert mtype == 8, "member repointed at the appended PTR"
    assert types[8][:3] == (2, "", 7), "PTR -> TYPE_TAG"
    assert types[7][:3] == (18, "kptr", 2), "TYPE_TAG 'kptr' -> STRUCT data"
    assert types[3][:3] == (2, "", 2), "the original PTR is untouched"


def test_injection_leaves_existing_type_ids_alone(tmp_path):
    obj = str(tmp_path / "prog.bpf.o")
    synth_struct_object(obj)
    before = BpfElf(obj).btf_types()
    T.inject(obj, [("stash", "node", "kptr")])
    after = BpfElf(obj).btf_types()
    for tid, t in before.items():
        if tid == 4:
            continue   # the struct whose member we repointed
        assert after[tid] == t, f"type id {tid} moved"


@pytest.mark.parametrize("entry", [
    ("nope", "node", "kptr"),     # no such struct
    ("stash", "nope", "kptr"),    # no such member
    ("data", "key", "kptr"),      # member is not a pointer
])
def test_injection_rejects_a_bad_target(tmp_path, entry):
    obj = str(tmp_path / "prog.bpf.o")
    synth_struct_object(obj)
    with pytest.raises(TagError):
        T.inject(obj, [entry])


def test_tagging_twice_is_refused(tmp_path):
    obj = str(tmp_path / "prog.bpf.o")
    synth_struct_object(obj)
    T.inject(obj, [("stash", "node", "kptr")])
    with pytest.raises(TagError):
        T.inject(obj, [("stash", "node", "kptr")])
