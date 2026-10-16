"""Hermetic tests for the map-slot pass (scripts/btf_map_slots.py).

No kernel, no build tree: the BTF is synthesized here and read back with the
prover's own ELF reader. The pass must treat a slot that points at a map
(map-in-map) the same as one that points at a program (prog-array).
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import btf_map_slots as S  # noqa: E402
from btf_test_tags import elf_find_section  # noqa: E402
from bpfelf import BpfElf  # noqa: E402
from test_test_tags import synth_object  # noqa: E402

INT, PTR, ARRAY, STRUCT, FUNC_PROTO, VAR, DATASEC = 1, 2, 3, 4, 13, 14, 15


def synth_maps_object(path, maps, last="values"):
    """.BTF with one `.maps` DATASEC. `maps` is [(var name, slot kind, nelems)]
    where slot kind is "prog" (PTR -> FUNC_PROTO), "map" (PTR -> STRUCT inner)
    or None for a map with no slot member.

    Fixed ids: [1] INT int, [2] FUNC_PROTO, [3] PTR->[2], [4] STRUCT inner,
    [5] PTR->[4], [6] PTR->[1] (a void slot), [7] int[3], [8] PTR->[7] (a
    prog array's `type`). ARRAY types follow, one per distinct (kind, nelems), then
    for each map a STRUCT and a VAR, then the DATASEC."""
    strings, offs = b"\0", {}

    def s(name):
        nonlocal strings
        if name not in offs:
            offs[name] = len(strings)
            strings += name.encode() + b"\0"
        return offs[name]

    types, ids = [], {}

    def add(blob):
        types.append(blob)
        return len(types)

    add(struct.pack("<IIII", s("int"), INT << 24, 4, 0x01000020))        # [1]
    add(struct.pack("<III", 0, FUNC_PROTO << 24, 1))                     # [2]
    add(struct.pack("<III", 0, PTR << 24, 2))                            # [3]
    add(struct.pack("<III", s("inner"), (STRUCT << 24) | 1, 8)
        + struct.pack("<III", s("type"), 1, 0))                          # [4]
    add(struct.pack("<III", 0, PTR << 24, 4))                            # [5]
    add(struct.pack("<III", 0, PTR << 24, 1))                            # [6] PTR -> int (a void slot)
    add(struct.pack("<III", 0, ARRAY << 24, 0)
        + struct.pack("<III", 1, 1, 3))                                  # [7] int[3]: BPF_MAP_TYPE_PROG_ARRAY
    add(struct.pack("<III", 0, PTR << 24, 7))                            # [8] PTR -> int[3]
    elem = {"prog": 3, "map": 5, "void_prog": 6}
    arrays = {}
    for _name, kind, nelems in maps:
        if kind and (kind, nelems) not in arrays:
            arrays[(kind, nelems)] = add(
                struct.pack("<III", 0, ARRAY << 24, 0)
                + struct.pack("<III", elem[kind], 1, nelems))
    var_ids = []
    for name, kind, nelems in maps:
        members = struct.pack("<III", s("type"), 8 if kind == "void_prog" else 1, 0)
        if kind:
            members += struct.pack("<III", s(last), arrays[(kind, nelems)], 64)
        st = add(struct.pack("<III", s(name + "_def"),
                             (STRUCT << 24) | (2 if kind else 1), 16) + members)
        ids[name] = st
        var_ids.append(add(struct.pack("<IIII", s(name), VAR << 24, st, 1)))
    add(struct.pack("<III", s(".maps"), (DATASEC << 24) | len(var_ids), 0)
        + b"".join(struct.pack("<III", v, 0, 16) for v in var_ids))

    blob = b"".join(types)
    btf = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(blob),
                      len(blob), len(strings)) + blob + strings
    synth_object(path)
    buf = bytearray(open(path, "rb").read())
    shdr_base, _off, _size, _align = elf_find_section(buf, ".BTF")
    new_off = len(buf)
    buf.extend(btf)
    struct.pack_into("<QQ", buf, shdr_base + 24, new_off, len(btf))
    open(path, "wb").write(buf)
    return ids, arrays


def values_array(types, struct_id):
    """(array type id, elem type id, nelems) of a map struct's last member."""
    _name, arr = types[struct_id][4][-1]
    return (arr,) + types[arr][4]


def test_a_program_slot_array_becomes_zero_length(tmp_path):
    obj = str(tmp_path / "prog.bpf.o")
    ids, arrays = synth_maps_object(obj, [("jmp_table", "prog", 2)])
    assert S.patch(obj) == [("jmp_table", 2)]
    types = BpfElf(obj).btf_types()
    arr, elem, nelems = values_array(types, ids["jmp_table"])
    assert arr != arrays[("prog", 2)], "member repointed, array not edited"
    assert (types[arr][0], elem, nelems) == (ARRAY, 3, 0)


def test_a_map_slot_array_becomes_zero_length(tmp_path):
    obj = str(tmp_path / "prog.bpf.o")
    ids, _arrays = synth_maps_object(obj, [("outer_arr", "map", 3)])
    assert S.patch(obj) == [("outer_arr", 3)]
    types = BpfElf(obj).btf_types()
    arr, elem, nelems = values_array(types, ids["outer_arr"])
    assert (types[arr][0], elem, nelems) == (ARRAY, 5, 0)
    assert types[elem][:3] == (PTR, "", 4), "slot still points at the inner map def"
    assert types[4][:2] == (STRUCT, "inner")


def test_existing_types_keep_their_ids_and_contents(tmp_path):
    obj = str(tmp_path / "prog.bpf.o")
    ids, arrays = synth_maps_object(obj, [("outer_arr", "map", 3)])
    before = BpfElf(obj).btf_types()
    S.patch(obj)
    after = BpfElf(obj).btf_types()
    for tid, t in before.items():
        if tid != ids["outer_arr"]:
            assert after[tid] == t, f"type id {tid} changed"
    assert after[arrays[("map", 3)]][4] == (5, 3), "the shared ARRAY is untouched"
    assert len(after) == len(before) + 1


def test_maps_sharing_an_array_type_share_the_zero_length_one(tmp_path):
    obj = str(tmp_path / "prog.bpf.o")
    ids, _arrays = synth_maps_object(
        obj, [("outer_arr", "map", 1), ("outer_hash", "map", 1),
              ("jmp_table", "prog", 1)])
    assert S.patch(obj) == [("outer_arr", 1), ("outer_hash", 1), ("jmp_table", 1)]
    types = BpfElf(obj).btf_types()
    a = values_array(types, ids["outer_arr"])
    h = values_array(types, ids["outer_hash"])
    j = values_array(types, ids["jmp_table"])
    assert a == h and a[1:] == (5, 0)
    assert j[0] != a[0] and j[1:] == (3, 0)


def test_objects_with_nothing_to_patch_are_left_byte_identical(tmp_path):
    for i, maps in enumerate([[("plain", None, 0)],
                              [("outer_arr", "map", 0)],
                              []]):
        obj = str(tmp_path / f"prog{i}.bpf.o")
        synth_maps_object(obj, maps)
        before = open(obj, "rb").read()
        assert S.patch(obj) == []
        assert open(obj, "rb").read() == before


def test_only_a_last_member_named_values_is_a_slot_array(tmp_path):
    obj = str(tmp_path / "prog.bpf.o")
    synth_maps_object(obj, [("m", "map", 2)], last="slots")
    before = open(obj, "rb").read()
    assert S.patch(obj) == []
    assert open(obj, "rb").read() == before


def test_patching_twice_changes_nothing_more(tmp_path):
    obj = str(tmp_path / "prog.bpf.o")
    synth_maps_object(obj, [("outer_arr", "map", 2)])
    S.patch(obj)
    once = open(obj, "rb").read()
    assert S.patch(obj) == []
    assert open(obj, "rb").read() == once


def test_prog_array_void_slots_get_a_function_pointer_element(tmp_path):
    # A translation with an empty slot declares `[*const c_void; N]`: the
    # zero-length array must point at PTR -> FUNC_PROTO, which libbpf
    # requires of a prog-array value spec (the fixture has no .maps
    # relocations, so the pass falls back to the object's first FUNC_PROTO).
    obj = str(tmp_path / "void_slots.bpf.o")
    ids, _arrays = synth_maps_object(obj, [("jmp", "void_prog", 2)])
    assert S.patch(obj) == [("jmp", 2)]
    types = BpfElf(obj).btf_types()
    _arr, elem, nelems = values_array(types, ids["jmp"])
    assert nelems == 0
    assert types[elem][0] == PTR and types[types[elem][2]][0] == FUNC_PROTO
