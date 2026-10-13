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


def test_an_entry_without_a_struct_names_a_global(tmp_path):
    src = write(tmp_path, "btf_type_tags! { global_mask: kptr; s.m: kptr; }")
    assert T.parse_source(src) == [(None, "global_mask", "kptr"), ("s", "m", "kptr")]


def test_no_declaration_is_not_an_error(tmp_path):
    assert T.parse_source(write(tmp_path, "fn main() {}")) == []


def test_a_commented_out_declaration_is_not_read(tmp_path):
    assert T.parse_source(write(tmp_path, "// btf_type_tags! { a.b: kptr; }")) == []


@pytest.mark.parametrize("body,why", [
    ("btf_type_tags! { a.b: kptrs; }", "unknown tag"),
    ("btf_type_tags! { a.b.c: kptr; }", "two dots"),
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


@pytest.mark.parametrize("array", [False, True])
def test_arena_void_pointer_and_array_preserve_other_users(tmp_path, array):
    obj = str(tmp_path / "arena.bpf.o")
    synth_struct_object(obj)
    buf = bytearray(open(obj, "rb").read())
    sh, off, size, align = T.elf_find_section(buf, ".BTF")
    data = bytearray(buf[off:off + size])
    _, _, _, hdr, toff, tlen, soff, slen = struct.unpack_from("<HBBIIIII", data)
    types = T.walk_types(data, hdr, toff, tlen)
    # Original PTR becomes PTR -> void. kptr must still reject this target.
    struct.pack_into("<I", data, types[2][0] + 8, 0)
    if array:
        added = struct.pack("<IIIIII", 0, 3 << 24, 0, 3, 1, 1)
        data = data[:hdr + tlen] + added + data[hdr + tlen:]
        struct.pack_into("<III", data, 12, tlen + 24, soff + 24, slen)
        struct.pack_into("<I", data, types[3][0] + 16, 7)
    newoff = len(buf)
    buf.extend(data)
    struct.pack_into("<QQ", buf, sh + 24, newoff, len(data))
    open(obj, "wb").write(buf)
    with pytest.raises(TagError):
        T.inject(obj, [("stash", "node", "kptr")])
    T.inject(obj, [("stash", "node", "arena")])
    after = BpfElf(obj).btf_types()
    assert after[3][:3] == (2, "", 0)
    member = after[4][4][0][1]
    if array:
        assert after[member][0] == 3
        # Inspect raw array element type (bpfelf's public tuple shape differs).
        raw = bytearray(open(obj, 'rb').read())
        _, off, size, _ = T.elf_find_section(raw, '.BTF')
        blob = raw[off:off + size]
        _, _, _, hdr, toff, tlen, _, _ = struct.unpack_from('<HBBIIIII', blob)
        ts = T.walk_types(blob, hdr, toff, tlen)
        member = struct.unpack_from('<I', blob, ts[member - 1][0] + 12)[0]
    assert after[member][0] == 2
    assert after[after[member][2]][:3] == (18, 'arena', 0)


# --- globals and arrays of kptrs ---------------------------------------------

def synth_globals_object(path):
    """synth_struct_object plus [7] ARRAY [3] x1, [8] ARRAY [7] x2,
    [9] VAR 'g' -> [3], [10] VAR (mangled) 'garr' -> [8], [11] VAR 'n' -> [1],
    and stash.node repointed at the [7] array."""
    synth_struct_object(path)
    buf = bytearray(open(path, "rb").read())
    sh, off, size, _align = T.elf_find_section(buf, ".BTF")
    data = bytearray(buf[off:off + size])
    _, _, _, hdr, toff, tlen, soff, slen = struct.unpack_from("<HBBIIIII", data)
    types = T.walk_types(data, hdr, toff, tlen)
    names = [b"g", b"_RNvCs1a2B3c_4prog4garr", b"n"]
    strings, offs = b"", {}
    for n in names:
        offs[n] = slen + len(strings)
        strings += n + b"\0"
    added = struct.pack("<IIIIII", 0, 3 << 24, 0, 3, 1, 1)                 # [7]
    added += struct.pack("<IIIIII", 0, 3 << 24, 0, 7, 1, 2)                # [8]
    added += struct.pack("<IIII", offs[names[0]], 14 << 24, 3, 0)          # [9]
    added += struct.pack("<IIII", offs[names[1]], 14 << 24, 8, 0)          # [10]
    added += struct.pack("<IIII", offs[names[2]], 14 << 24, 1, 1)          # [11]
    struct.pack_into("<I", data, types[3][0] + 16, 7)                      # stash.node
    data = data[:hdr + tlen] + added + data[hdr + tlen:] + strings
    struct.pack_into("<III", data, 12, tlen + len(added), soff + len(added),
                     slen + len(strings))
    newoff = len(buf)
    buf.extend(data)
    struct.pack_into("<QQ", buf, sh + 24, newoff, len(data))
    open(path, "wb").write(buf)


def raw_types(path):
    raw = open(path, "rb").read()
    _, off, size, _ = T.elf_find_section(bytearray(raw), ".BTF")
    blob = raw[off:off + size]
    _, _, _, hdr, toff, tlen, _, _ = struct.unpack_from("<HBBIIIII", blob)
    return blob, T.walk_types(blob, hdr, toff, tlen)


def array_elem(blob, ts, tid):
    assert ts[tid - 1][1] == 3, f"type {tid} is not an ARRAY"
    elem, _idx, nelems = struct.unpack_from("<III", blob, ts[tid - 1][0] + 12)
    return elem, nelems


def assert_kptr_ptr(ts, tid, pointee):
    assert ts[tid - 1][1] == 2, f"type {tid} is not a PTR"
    tag = ts[ts[tid - 1][3] - 1]
    assert (tag[1], tag[3]) == (18, pointee)


def test_a_global_pointer_is_tagged_through_its_var(tmp_path):
    obj = str(tmp_path / "g.bpf.o")
    synth_globals_object(obj)
    assert T.inject(obj, [(None, "g", "kptr")]) == ["g:kptr"]
    blob, ts = raw_types(obj)
    assert_kptr_ptr(ts, ts[9 - 1][3], 2)
    assert ts[3 - 1][3] == 2, "the shared PTR is untouched"


def test_a_static_global_is_found_under_its_mangled_name_and_arrays_are_cloned(tmp_path):
    obj = str(tmp_path / "g.bpf.o")
    synth_globals_object(obj)
    T.inject(obj, [(None, "garr", "kptr")])
    blob, ts = raw_types(obj)
    outer = ts[10 - 1][3]
    assert outer > 11, "the VAR points at a cloned array"
    inner, n = array_elem(blob, ts, outer)
    assert n == 2
    ptr, n = array_elem(blob, ts, inner)
    assert n == 1
    assert_kptr_ptr(ts, ptr, 2)
    assert array_elem(blob, ts, 8) == (7, 2), "the original arrays are untouched"
    assert array_elem(blob, ts, 7) == (3, 1)


def test_a_member_array_of_kptrs_is_tagged(tmp_path):
    obj = str(tmp_path / "g.bpf.o")
    synth_globals_object(obj)
    T.inject(obj, [("stash", "node", "kptr")])
    blob, ts = raw_types(obj)
    member = struct.unpack_from("<I", blob, ts[4 - 1][0] + 16)[0]
    ptr, n = array_elem(blob, ts, member)
    assert n == 1
    assert_kptr_ptr(ts, ptr, 2)


@pytest.mark.parametrize("name", ["nope", "n", "arr"])
def test_a_bad_global_target_is_rejected(tmp_path, name):
    # no such variable; not a pointer; "arr" must not match the mangled
    # "...4garr" (the whole last path element has to be the name)
    obj = str(tmp_path / "g.bpf.o")
    synth_globals_object(obj)
    with pytest.raises(TagError):
        T.inject(obj, [(None, name, "kptr")])


@pytest.mark.parametrize("sym,name", [
    ("_RNvCsayMV1tQyH8U_15cpumask_success11global_mask", "global_mask"),
    ("_RNvCs1a2B3c_4prog4garr", "garr"),
    ("_RNvCs1a2B3c_4prog5foo1x", "foo1x"),
    ("global_mask", None),
    ("_RNvNvCs1a2B3c_4prog4main3FMT", None),   # a static inside a function
])
def test_rust_static_name(sym, name):
    assert T.rust_static_name(sym) == name
