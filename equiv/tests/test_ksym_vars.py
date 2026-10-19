"""External data symbols retain the C oracle's types and weak linkage; so does
an extern kfunc's prototype when its declaration is selected, a `.kconfig`
extern its C object's int/bool/char[]/tristate type, and a cross-object
extern (`// BTF_EXTERN:`) its C declaration and DATASEC."""
from pathlib import Path
import re
import struct
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from ksym_vars import declarations, contract, lower
from bpfcore import Btf
from bpfelf import Symbol


BODY = "define i64 @prog() {\n  ret i64 ptrtoint (ptr @optional to i64)\n}\n"
IR = ('@scalar = external global i32\n'
      '@optional = external global i8\n'
      '@runqueues = external global i8\n' + BODY +
      '!llvm.dbg.cu = !{!0}\n'
      '!0 = distinct !DICompileUnit(language: DW_LANG_Rust, file: !1, emissionKind: FullDebug)\n'
      '!1 = !DIFile(filename: "prog.rs", directory: "/tmp")\n')


def fixture_btf():
    strings = b"\0int\0rq\0acquire\0"
    types = struct.pack("<IIII", 1, 1 << 24, 4, 0x01000020)  # 1: signed int
    types += struct.pack("<III", 0, 10 << 24, 1)  # 2: const int
    types += struct.pack("<III", 5, 4 << 24, 32)  # 3: struct rq
    types += struct.pack("<III", 0, 10 << 24, 3)  # 4: const struct rq
    types += struct.pack("<III", 0, 10 << 24, 0)  # 5: const void
    types += struct.pack("<III", 0, 2 << 24, 3)  # 6: struct rq *
    types += struct.pack("<III", 0, 2 << 24, 0)  # 7: void *
    # 8: struct rq *acquire(struct rq *, void *, int)
    types += struct.pack("<III", 0, (13 << 24) | 3, 6)
    types += struct.pack("<IIIIII", 0, 6, 0, 7, 0, 1)
    types += struct.pack("<III", 8, (12 << 24) | 2, 8)  # 9: extern FUNC acquire
    return Btf(struct.pack("<HBBIIIII", 0xeb9f, 1, 0, 24, 0, len(types),
                           len(types), len(strings)) + types + strings)


def test_qualifiers_struct_identity_and_weak_address_are_preserved():
    result = lower(IR, ["scalar", "optional", "runqueues"], fixture_btf(),
                   {"scalar": (2, False, False, ".ksyms"), "optional": (5, True, False, ".ksyms"),
                    "runqueues": (4, False, False, ".ksyms")})
    assert '@optional = extern_weak global i8, section ".ksyms"' in result
    assert '@scalar = external global i32, section ".ksyms"' in result
    assert BODY in result  # Address computation is unchanged; no C body is imported.
    assert "DW_TAG_const_type, baseType: null" in result
    assert 'DW_TAG_structure_type, name: "rq"' in result
    assert 'size: 32, encoding: DW_ATE_signed' in result
    assert result.count("isDefinition: false") == 3
    assert result.count("!DIGlobalVariableExpression(") == 3
    definitions = re.findall(r"^!(\d+) =", result, re.M)
    assert len(definitions) == len(set(definitions))


@pytest.mark.parametrize("replacement", ["global i32 0", 'external global i32, section ".data"'])
def test_cannot_turn_a_definition_or_other_section_into_a_ksym(replacement):
    with pytest.raises(ValueError, match="undefined Rust|overwrite"):
        lower(IR.replace("external global i32", replacement), ["scalar"],
              fixture_btf(), {"scalar": (2, False, False, ".ksyms")})


def test_unselected_objects_are_unchanged():
    assert lower(IR, [], None, {}) == IR
    assert declarations("// ordinary comment\n") == {}


def test_integer_width_mismatch_is_not_hidden_by_c_metadata():
    with pytest.raises(ValueError, match="integer width differs"):
        lower(IR.replace("global i32", "global i64"), ["scalar"],
              fixture_btf(), {"scalar": (2, False, False, ".ksyms")})


@pytest.mark.parametrize("source", ["// BTF_KSYM: typo!", "// BTF_KSYM: x\n// BTF_KSYM: x"])
def test_bad_annotations_fail(source):
    with pytest.raises(ValueError, match="invalid or duplicate"):
        declarations(source)


def test_c_contract_requires_undefined_ksym_data_and_preserves_weakness():
    types = {1: (14, "optional", 5, 0, None), 2: (15, ".ksyms", 0, 1, [1])}
    elf = SimpleNamespace(btf_types=lambda: types,
                          symbols=[Symbol(1, "optional", 0, 0, 2, 0, 0)])
    assert contract(elf, ["optional"]) == {"optional": (5, True, False, ".ksyms")}
    with pytest.raises(ValueError, match="C object must declare"):
        contract(elf, ["unknown"])
    elf.symbols = [Symbol(1, "optional", 0, 4, 1, 1, 3)]
    with pytest.raises(ValueError, match="C object must declare"):
        contract(elf, ["optional"])


def test_unsupported_types_do_not_get_a_guessed_descriptor():
    btf = fixture_btf()
    btf.types[1].kind = 16  # FLOAT descriptor support has not been implemented.
    with pytest.raises(ValueError, match="unsupported ksym BTF kind"):
        lower(IR, ["scalar"], btf, {"scalar": (1, False, False, ".ksyms")})


FUNC_IR = ('declare noundef ptr @acquire(ptr noundef, ptr noundef, i32 noundef) unnamed_addr #1\n'
           + BODY +
           '!llvm.dbg.cu = !{!0}\n'
           '!0 = distinct !DICompileUnit(language: DW_LANG_Rust, file: !1, emissionKind: FullDebug)\n'
           '!1 = !DIFile(filename: "prog.rs", directory: "/tmp")\n')


def test_selected_function_gets_the_c_prototype_and_the_ksyms_section():
    result = lower(FUNC_IR, ["acquire"], fixture_btf(), {"acquire": (8, True, True, ".ksyms")})
    decl = re.search(r"^declare !dbg (!\d+) noundef ptr @acquire\(ptr noundef, ptr noundef, "
                     r'i32 noundef\) unnamed_addr #1 section "\.ksyms"$', result, re.M)
    assert decl
    sp = re.search(re.escape(decl[1]) + r' = !DISubprogram\(name: "acquire", .*type: (!\d+), '
                   r"flags: DIFlagPrototyped, spFlags: DISPFlagOptimized\)", result)
    assert sp
    sub = re.search(re.escape(sp[1]) + r" = !DISubroutineType\(types: !\{(!\d+), (!\d+), (!\d+), (!\d+)\}\)",
                    result)
    assert sub and sub[1] == sub[2]
    assert re.search(re.escape(sub[1]) + r" = !DIDerivedType\(tag: DW_TAG_pointer_type, baseType: (!\d+), size: 64\)",
                     result)
    assert re.search(re.escape(sub[3]) + r" = !DIDerivedType\(tag: DW_TAG_pointer_type, baseType: null, size: 64\)",
                     result)
    assert re.search(re.escape(sub[4]) + r' = !DIBasicType\(name: "int", size: 32, encoding: DW_ATE_signed\)', result)
    assert re.search(r'!DICompositeType\(tag: DW_TAG_structure_type, name: "rq", file: !1, size: 256, elements: ', result)
    # the Rust declaration keeps its own argument list; a second declaration or
    # one with metadata already is refused
    with pytest.raises(ValueError, match="expected one Rust function declaration"):
        lower(FUNC_IR.replace("@acquire(", "@other("), ["acquire"], fixture_btf(), {"acquire": (8, True, True, ".ksyms")})
    with pytest.raises(ValueError, match="refusing to overwrite"):
        lower(FUNC_IR.replace("unnamed_addr #1", 'unnamed_addr #1 section ".ksyms"'), ["acquire"],
              fixture_btf(), {"acquire": (8, True, True, ".ksyms")})
    with pytest.raises(ValueError, match="not a function prototype"):
        lower(FUNC_IR, ["acquire"], fixture_btf(), {"acquire": (3, True, True, ".ksyms")})


def test_c_contract_selects_an_extern_function_by_its_prototype():
    types = {1: (12, "acquire", 7, 2, None), 2: (15, ".ksyms", 0, 1, [1])}
    elf = SimpleNamespace(btf_types=lambda: types,
                          symbols=[Symbol(1, "acquire", 0, 0, 2, 0, 0)])
    assert contract(elf, ["acquire"]) == {"acquire": (7, True, True, ".ksyms")}


def kconfig_btf():
    strings = b"\0int\0_Bool\0bool\0libbpf_tristate\0TRI_NO\0TRI_YES\0TRI_MODULE\0char\0"
    types = struct.pack("<IIII", 1, 1 << 24, 4, 0x01000020)  # 1: int
    types += struct.pack("<IIII", 5, 1 << 24, 1, 0x04000008)  # 2: _Bool
    types += struct.pack("<III", 11, 8 << 24, 2)  # 3: typedef bool
    types += struct.pack("<III", 16, (6 << 24) | 3, 4)  # 4: enum libbpf_tristate
    types += struct.pack("<IiIiIi", 32, 0, 39, 1, 47, 2)
    types += struct.pack("<IIII", 58, 1 << 24, 1, 0x01000008)  # 5: char
    types += struct.pack("<IIIIII", 0, 3 << 24, 0, 5, 1, 8)  # 6: char[8]
    return Btf(struct.pack("<HBBIIIII", 0xeb9f, 1, 0, 24, 0, len(types),
                           len(types), len(strings)) + types + strings)


KCONFIG_IR = ('@CONFIG_BOOL = external global i8\n'
              '@CONFIG_TRI = external global i32\n'
              '@CONFIG_STR = external global [8 x i8]\n'
              '@LINUX_KERNEL_VERSION = external global i32\n' + BODY +
              '!llvm.dbg.cu = !{!0}\n'
              '!0 = distinct !DICompileUnit(language: DW_LANG_Rust, file: !1, emissionKind: FullDebug)\n'
              '!1 = !DIFile(filename: "prog.rs", directory: "/tmp")\n')
KCONFIG_NAMES = {"CONFIG_BOOL": ".kconfig", "CONFIG_TRI": ".kconfig",
                 "CONFIG_STR": ".kconfig", "LINUX_KERNEL_VERSION": ".kconfig"}
KCONFIG_VARS = {"CONFIG_BOOL": (3, True, False, ".kconfig"), "CONFIG_TRI": (4, True, False, ".kconfig"),
                "CONFIG_STR": (6, True, False, ".kconfig"),
                "LINUX_KERNEL_VERSION": (1, False, False, ".kconfig")}


def test_kconfig_externs_mirror_the_c_types_in_the_kconfig_section():
    result = lower(KCONFIG_IR, KCONFIG_NAMES, kconfig_btf(), KCONFIG_VARS)
    assert '@CONFIG_BOOL = extern_weak global i8, section ".kconfig", !dbg' in result
    assert '@LINUX_KERNEL_VERSION = external global i32, section ".kconfig", !dbg' in result
    assert '@CONFIG_STR = extern_weak global [8 x i8], section ".kconfig", !dbg' in result
    assert re.search(r'!DIDerivedType\(tag: DW_TAG_typedef, baseType: (!\d+), name: "bool"\)', result)
    assert '!DIBasicType(name: "_Bool", size: 8, encoding: DW_ATE_boolean)' in result
    enum = re.search(r'distinct !DICompositeType\(tag: DW_TAG_enumeration_type, name: "libbpf_tristate", '
                     r'file: !1, baseType: (!\d+), size: 32, elements: (!\d+)\)', result)
    assert enum
    assert re.search(re.escape(enum[1]) + r' = !DIBasicType\(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned\)', result)
    assert '!DIEnumerator(name: "TRI_MODULE", value: 2, isUnsigned: true)' in result
    array = re.search(r'!DICompositeType\(tag: DW_TAG_array_type, baseType: (!\d+), size: 64, elements: (!\d+)\)', result)
    assert array
    assert re.search(re.escape(array[2]) + r" = !\{(!\d+)\}", result)
    assert "!DISubrange(count: 8)" in result
    assert result.count("isDefinition: false") == 4
    assert BODY in result


def test_kconfig_externs_keep_libbpf_s_type_restrictions():
    btf = kconfig_btf()
    btf.types[4].kind = 4  # a struct is not a kconfig type
    with pytest.raises(ValueError, match="libbpf allows only"):
        lower(KCONFIG_IR, {"CONFIG_TRI": ".kconfig"}, btf, {"CONFIG_TRI": (4, True, False, ".kconfig")})
    with pytest.raises(ValueError, match="array shape differs"):
        lower(KCONFIG_IR.replace("[8 x i8]", "[4 x i8]"), {"CONFIG_STR": ".kconfig"},
              kconfig_btf(), {"CONFIG_STR": (6, True, False, ".kconfig")})
    with pytest.raises(ValueError, match="integer width differs"):
        lower(KCONFIG_IR.replace("@CONFIG_TRI = external global i32", "@CONFIG_TRI = external global i64"),
              {"CONFIG_TRI": ".kconfig"}, kconfig_btf(), {"CONFIG_TRI": (4, True, False, ".kconfig")})


def test_kconfig_contract_reads_the_kconfig_datasec_only():
    types = {1: (14, "CONFIG_X", 5, 0, None), 2: (15, ".kconfig", 0, 1, [1]),
             3: (14, "sym", 6, 0, None), 4: (15, ".ksyms", 0, 1, [3]),
             5: (12, "kfunc", 7, 2, None), 6: (15, ".ksyms", 0, 1, [5])}
    elf = SimpleNamespace(btf_types=lambda: types,
                          symbols=[Symbol(1, "CONFIG_X", 0, 0, 2, 0, 0),
                                   Symbol(2, "sym", 0, 0, 1, 0, 0),
                                   Symbol(3, "kfunc", 0, 0, 1, 0, 0)])
    assert contract(elf, {"CONFIG_X": ".kconfig", "sym": ".ksyms"}) == {
        "CONFIG_X": (5, True, False, ".kconfig"), "sym": (6, False, False, ".ksyms")}
    with pytest.raises(ValueError, match="undefined .kconfig"):
        contract(elf, {"sym": ".kconfig"})
    with pytest.raises(ValueError, match="undefined .ksyms"):
        contract(elf, {"CONFIG_X": ".ksyms"})
    assert declarations("// BTF_KCONFIG: CONFIG_X\n// BTF_KSYM: sym\n") == {
        "CONFIG_X": ".kconfig", "sym": ".ksyms"}
    with pytest.raises(ValueError, match="invalid or duplicate"):
        declarations("// BTF_KCONFIG: x\n// BTF_KSYM: x\n")


def test_extern_contract_mirrors_the_c_declaration_and_its_datasec():
    types = {1: (14, "my_pid", 1, 0, None), 2: (14, "map2", 9, 0, None),
             3: (15, ".maps", 0, 1, [2]), 4: (12, "lib_routine", 7, 2, None),
             5: (14, "CONFIG_X", 5, 0, None), 6: (15, ".kconfig", 0, 1, [5]),
             7: (12, "defined", 7, 1, None)}
    elf = SimpleNamespace(btf_types=lambda: types,
                          symbols=[Symbol(1, "my_pid", 0, 0, 1, 0, 0),
                                   Symbol(2, "map2", 0, 0, 1, 0, 0),
                                   Symbol(3, "lib_routine", 0, 0, 1, 0, 0),
                                   Symbol(4, "CONFIG_X", 0, 0, 2, 0, 0),
                                   Symbol(5, "defined", 0, 0, 1, 0, 0)])
    assert contract(elf, {"my_pid": "extern", "map2": "extern", "lib_routine": "extern"}) == {
        "my_pid": (1, False, False, None), "map2": (9, False, False, ".maps"),
        "lib_routine": (7, False, True, None)}
    with pytest.raises(ValueError, match="matching marker"):
        contract(elf, {"CONFIG_X": "extern"})
    with pytest.raises(ValueError, match="not an extern"):
        contract(elf, {"defined": "extern"})
    with pytest.raises(ValueError, match="one undefined extern"):
        contract(elf, {"unknown": "extern"})
    assert declarations("// BTF_EXTERN: my_pid\n") == {"my_pid": "extern"}


def test_extern_variables_keep_the_c_placement_and_functions_go_to_dot_extern():
    result = lower(IR, ["scalar"], fixture_btf(), {"scalar": (2, False, False, None)})
    assert re.search(r"^@scalar = external global i32, !dbg !\d+$", result, re.M)
    assert "isDefinition: false" in result
    result = lower(FUNC_IR, ["acquire"], fixture_btf(), {"acquire": (8, False, True, None)})
    assert re.search(r'^declare !dbg !\d+ noundef ptr @acquire\(.*\) unnamed_addr #1 section "\.extern"$',
                     result, re.M)


def map_btf():
    strings = b"\0int\0type\0key\0"
    types = struct.pack("<IIII", 1, 1 << 24, 4, 0x01000020)  # 1: int
    types += struct.pack("<III", 0, 2 << 24, 1)  # 2: int *
    # 3: anonymous map definition struct { int *type; int *key; }
    types += struct.pack("<III", 0, (4 << 24) | 2, 16)
    types += struct.pack("<IIIIII", 5, 2, 0, 10, 2, 64)
    return Btf(struct.pack("<HBBIIIII", 0xeb9f, 1, 0, 24, 0, len(types),
                           len(types), len(strings)) + types + strings)


def test_extern_map_definitions_are_mirrored_with_their_members():
    ir = IR.replace("@scalar = external global i32", "@map2 = external global [16 x i8]")
    result = lower(ir, ["map2"], map_btf(), {"map2": (3, False, False, ".maps")})
    assert '@map2 = external global [16 x i8], section ".maps", !dbg' in result
    anon = re.search(r"^(!\d+) = distinct !DICompositeType\(tag: DW_TAG_structure_type, file: !1, "
                     r"size: 128, elements: (!\d+)\)$", result, re.M)
    assert anon
    assert re.search(r'!DIDerivedType\(tag: DW_TAG_member, name: "type", scope: ' + re.escape(anon[1])
                     + r', file: !1, baseType: !\d+, size: 64, offset: 0\)', result)
    assert re.search(r'!DIDerivedType\(tag: DW_TAG_member, name: "key", scope: ' + re.escape(anon[1])
                     + r', file: !1, baseType: !\d+, size: 64, offset: 64\)', result)


def keyed_map_btf():
    strings = b"\0int\0type\0key\0my_key\0x\0long\0k\0"
    types = struct.pack("<IIII", 1, 1 << 24, 4, 0x01000020)  # 1: int
    types += struct.pack("<III", 0, 2 << 24, 1)  # 2: int *
    types += struct.pack("<IIII", 23, 1 << 24, 8, 0x01000040)  # 3: long
    types += struct.pack("<III", 14, (4 << 24) | 1, 8)  # 4: struct my_key { long x; }
    types += struct.pack("<III", 21, 3, 0)
    types += struct.pack("<III", 0, 2 << 24, 4)  # 5: struct my_key *
    # 6: anonymous map definition struct { int *type; struct my_key *key; }
    types += struct.pack("<III", 0, (4 << 24) | 2, 16)
    types += struct.pack("<IIIIII", 5, 2, 0, 10, 5, 64)
    # 7: struct my_key *k, a plain extern pointer to the struct
    types += struct.pack("<III", 28, (14 << 24), 5)
    return Btf(struct.pack("<HBBIIIII", 0xeb9f, 1, 0, 24, 0, len(types),
                           len(types), len(strings)) + types + strings)


def test_extern_map_key_types_are_mirrored_with_their_members():
    # The linker compares an extern map's key/value types exactly (member
    # by member, through the map definition's pointer), a plain pointer's
    # pointee only by name: the named struct gets its members in the
    # first case and stays a descriptor in the second (and for a ksym).
    ir = IR.replace("@scalar = external global i32", "@map1 = external global [16 x i8]")
    result = lower(ir, ["map1"], keyed_map_btf(), {"map1": (6, False, False, ".maps")})
    assert re.search(r'!DICompositeType\(tag: DW_TAG_structure_type, name: "my_key", file: !1, '
                     r'size: 64, elements: (!\d+)\)', result)
    assert re.search(r'!DIDerivedType\(tag: DW_TAG_member, name: "x", scope: !\d+, file: !1, '
                     r'baseType: !\d+, size: 64, offset: 0\)', result)
    assert '!DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)' in result

    ir = IR.replace("@scalar = external global i32", "@k = external global ptr")
    result = lower(ir, ["k"], keyed_map_btf(), {"k": (5, False, False, None)})
    assert re.search(r'!DICompositeType\(tag: DW_TAG_structure_type, name: "my_key", file: !1, '
                     r'size: 64, elements: (!\d+)\)', result)
    assert 'name: "x"' not in result
