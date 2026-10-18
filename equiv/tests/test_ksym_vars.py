"""External data symbols retain the C oracle's types and weak linkage; so does
an extern kfunc's prototype when its declaration is selected."""
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
                   {"scalar": (2, False), "optional": (5, True), "runqueues": (4, False)})
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
              fixture_btf(), {"scalar": (2, False)})


def test_unselected_objects_are_unchanged():
    assert lower(IR, [], None, {}) == IR
    assert declarations("// ordinary comment\n") == []


def test_integer_width_mismatch_is_not_hidden_by_c_metadata():
    with pytest.raises(ValueError, match="integer width differs"):
        lower(IR.replace("global i32", "global i64"), ["scalar"],
              fixture_btf(), {"scalar": (2, False)})


@pytest.mark.parametrize("source", ["// BTF_KSYM: typo!", "// BTF_KSYM: x\n// BTF_KSYM: x"])
def test_bad_annotations_fail(source):
    with pytest.raises(ValueError, match="invalid or duplicate"):
        declarations(source)


def test_c_contract_requires_undefined_ksym_data_and_preserves_weakness():
    types = {1: (14, "optional", 5, 0, None), 2: (15, ".ksyms", 0, 1, [1])}
    elf = SimpleNamespace(btf_types=lambda: types,
                          symbols=[Symbol(1, "optional", 0, 0, 2, 0, 0)])
    assert contract(elf, ["optional"]) == {"optional": (5, True)}
    with pytest.raises(ValueError, match="C object must declare"):
        contract(elf, ["unknown"])
    elf.symbols = [Symbol(1, "optional", 0, 4, 1, 1, 3)]
    with pytest.raises(ValueError, match="C object must declare"):
        contract(elf, ["optional"])


def test_unsupported_types_do_not_get_a_guessed_descriptor():
    btf = fixture_btf()
    btf.types[1].kind = 3  # Array descriptor support has not been implemented.
    with pytest.raises(ValueError, match="unsupported ksym BTF kind"):
        lower(IR, ["scalar"], btf, {"scalar": (1, False)})


FUNC_IR = ('declare noundef ptr @acquire(ptr noundef, ptr noundef, i32 noundef) unnamed_addr #1\n'
           + BODY +
           '!llvm.dbg.cu = !{!0}\n'
           '!0 = distinct !DICompileUnit(language: DW_LANG_Rust, file: !1, emissionKind: FullDebug)\n'
           '!1 = !DIFile(filename: "prog.rs", directory: "/tmp")\n')


def test_selected_function_gets_the_c_prototype_and_the_ksyms_section():
    result = lower(FUNC_IR, ["acquire"], fixture_btf(), {"acquire": (8, True, True)})
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
        lower(FUNC_IR.replace("@acquire(", "@other("), ["acquire"], fixture_btf(), {"acquire": (8, True, True)})
    with pytest.raises(ValueError, match="refusing to overwrite"):
        lower(FUNC_IR.replace("unnamed_addr #1", 'unnamed_addr #1 section ".ksyms"'), ["acquire"],
              fixture_btf(), {"acquire": (8, True, True)})
    with pytest.raises(ValueError, match="not a function prototype"):
        lower(FUNC_IR, ["acquire"], fixture_btf(), {"acquire": (3, True, True)})


def test_c_contract_selects_an_extern_function_by_its_prototype():
    types = {1: (12, "acquire", 7, 2, None), 2: (15, ".ksyms", 0, 1, [1])}
    elf = SimpleNamespace(btf_types=lambda: types,
                          symbols=[Symbol(1, "acquire", 0, 0, 2, 0, 0)])
    assert contract(elf, ["acquire"]) == {"acquire": (7, True, True)}
