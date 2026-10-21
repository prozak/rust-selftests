"""The opt-in type-ID bridge preserves identity and rejects invalid contracts."""
from pathlib import Path
import re
import struct
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import type_id
from bpfcore import Btf


def fixture_btf():
    strings = b'\0int\0thing\0alias\0mode\0ON\0'
    data = struct.pack('<IIII', 1, 1 << 24, 4, 0x01000020)
    data += struct.pack('<III', 5, 4 << 24, 64)
    data += struct.pack('<III', 11, 8 << 24, 1)
    data += struct.pack('<III', 17, (6 << 24) | 1, 4)
    data += struct.pack('<Ii', 22, 1)
    data += struct.pack('<III', 0, 4 << 24, 8)  # [5] an anonymous struct
    return Btf(struct.pack('<HBBIIIII', 0xeb9f, 1, 0, 24, 0, len(data),
                           len(data), len(strings)) + data + strings)


def fixture_ir(names, ret='i64'):
    return ('define i64 @prog() !dbg !2 {\n' +
            ''.join(f'  %r{i} = tail call noundef {ret} @{name}(), !dbg !3\n' for i, name in enumerate(names)) +
            '  ret i64 %r0\n}\n' +
            ''.join(f'declare noundef {ret} @{name}()\n' for name in names) +
            '!1 = !DIFile(filename: "test.rs", directory: "/tmp")\n')


def decl(kind, name, local=False, anon=False):
    """A BTF_TYPE_ID declaration in the test's tuple shorthand."""
    return type_id.Decl('local' if local else 'id', kind, name, anon=anon)


def as_tuple(d):
    return (d.op, d.kind, d.name, d.member, d.anon)


def targets(names):
    """{function: C type id} -> the contract shape lower() takes."""
    return {n: (decl(4, n) if not isinstance(t, tuple) else decl(t[0], t[1], local=True), t)
            for n, t in names.items()}


def contract(btf, names):
    return {n: t for n, (_d, t) in type_id.contract(None, btf, names).items()}


def test_standard_intrinsics_retain_type_identity_without_pinning_target_ids():
    names = {'tid_int': 1, 'tid_thing': 2, 'tid_alias': 3, 'tid_mode': 4}
    result = type_id.lower(fixture_ir(names), targets(names), fixture_btf())
    assert result.count('call i64 @llvm.bpf.btf.type.id(') == 4
    assert result.count('!llvm.preserve.access.index') == 4
    assert 'DW_TAG_structure_type, name: "thing"' in result
    assert 'DW_TAG_typedef, name: "alias"' in result
    assert 'DW_TAG_enumeration_type, name: "mode"' in result
    assert '!DIEnumerator(name: "ON", value: 1)' in result
    assert 'ret i64 %r0' in result
    assert not re.search(r'@tid_\w+', result)
    definitions = re.findall(r'^!(\d+) =', result, re.M)
    assert len(set(definitions)) == len(definitions)


@pytest.mark.parametrize('replacement', ['declare i32 @tid()', 'define i64 @tid() {', 'declare i64 @tid(i64)'])
def test_rejects_incompatible_rust_declaration(replacement):
    with pytest.raises(ValueError, match='extern fn'):
        type_id.lower(fixture_ir(['tid']).replace('declare noundef i64 @tid()', replacement),
                      targets({'tid': 2}), fixture_btf())


def test_rejects_address_taken_polyfill():
    ir = fixture_ir(['tid']) + '@address = global ptr @tid\n'
    with pytest.raises(ValueError, match='unsupported use'):
        type_id.lower(ir, targets({'tid': 2}), fixture_btf())


def test_requires_c_target_relocation_with_same_kind_and_name(monkeypatch):
    monkeypatch.setattr(type_id, 'core_relo_records', lambda _: {'prog': [(0, 2, '0', 7), (1, 3, '0', 6)]})
    assert contract(fixture_btf(), {'tid': decl(4, 'thing')}) == {'tid': 2}
    for kind, name in [(5, 'thing'), (8, 'alias'), (4, 'missing')]:
        with pytest.raises(ValueError, match='C TYPE_ID_TARGET'):
            type_id.contract(None, fixture_btf(), {'tid': decl(kind, name)})


def test_local_ids_need_a_c_local_relocation(monkeypatch):
    # [2] thing carries only a TARGET relocation: not enough for a local ID
    monkeypatch.setattr(type_id, 'core_relo_records', lambda _: {'prog': [(0, 2, '0', 7)]})
    with pytest.raises(ValueError, match='C TYPE_ID_LOCAL'):
        type_id.contract(None, fixture_btf(), {'tid': decl(4, 'thing', local=True)})
    monkeypatch.setattr(type_id, 'core_relo_records', lambda _: {'prog': [(0, 2, '0', 6)]})
    assert contract(fixture_btf(), {'tid': decl(4, 'thing', local=True)}) == {'tid': (4, 'thing')}


def test_an_anonymous_c_type_needs_a_local_relocation_of_its_kind(monkeypatch):
    # [5] is anonymous: the Rust stand-in may have any name, but a C local
    # relocation for SOME anonymous struct must exist
    monkeypatch.setattr(type_id, 'core_relo_records', lambda _: {'prog': [(0, 5, '0', 6)]})
    assert contract(fixture_btf(), {'tid': decl(4, 'stand_in', True, True)}) == {'tid': (4, 'stand_in')}
    with pytest.raises(ValueError, match='anonymous type of kind 5'):
        type_id.contract(None, fixture_btf(), {'tid': decl(5, 'stand_in', True, True)})
    monkeypatch.setattr(type_id, 'core_relo_records', lambda _: {'prog': [(0, 2, '0', 6)]})
    with pytest.raises(ValueError, match='anonymous type of kind 4'):
        type_id.contract(None, fixture_btf(), {'tid': decl(4, 'stand_in', True, True)})


def test_a_local_int_id_needs_the_c_int_relocation(monkeypatch):
    monkeypatch.setattr(type_id, 'core_relo_records', lambda _: {'prog': [(0, 1, '0', 6)]})
    assert contract(fixture_btf(), {'tid': decl(1, 'int', local=True)}) == {'tid': (1, 'int')}


def declarations(source):
    return {n: as_tuple(d) for n, d in type_id.declarations(source).items()}


def test_declarations_parse_the_local_form():
    assert declarations('// BTF_TYPE_ID: new_id local struct node_data') == {
        'new_id': ('local', 4, 'node_data', None, False)}
    assert declarations('// BTF_TYPE_ID: int_id local int int') == {'int_id': ('local', 1, 'int', None, False)}
    assert declarations('// BTF_TYPE_ID: u_id local union stand_in (anonymous)') == {
        'u_id': ('local', 5, 'stand_in', None, True)}
    assert declarations('// BTF_TYPE_ID: t_id struct task_struct') == {'t_id': ('id', 4, 'task_struct', None, False)}
    with pytest.raises(ValueError, match='struct, union or int'):
        type_id.declarations('// BTF_TYPE_ID: new_id local typedef u32')
    with pytest.raises(ValueError, match='anonymous'):
        type_id.declarations('// BTF_TYPE_ID: new_id struct node_data (anonymous)')
    with pytest.raises(ValueError, match='unknown C integer type'):
        type_id.declarations('// BTF_TYPE_ID: new_id local int size_t')


RUST_COMPOSITE = ('!7 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "thing", '
                  'scope: !1, file: !1, size: 64, align: 64, elements: !8)\n!8 = !{}\n')


def test_a_local_id_points_at_rustcs_own_composite():
    result = type_id.lower(fixture_ir(['tid']) + RUST_COMPOSITE, targets({'tid': (4, 'thing')}), fixture_btf())
    assert 'call i64 @llvm.bpf.btf.type.id(i32 1, i64 0), !dbg !3, !llvm.preserve.access.index !7' in result
    # no synthesized stand-in: the layout must be Rust's own
    assert result.count('DW_TAG_structure_type, name: "thing"') == 1


def test_a_local_int_id_points_at_rustcs_base_type():
    ir = fixture_ir(['tid']) + '!7 = !DIBasicType(name: "i32", size: 32, encoding: DW_ATE_signed)\n'
    result = type_id.lower(ir, targets({'tid': (1, 'int')}), fixture_btf())
    assert 'call i64 @llvm.bpf.btf.type.id(i32 1, i64 0), !dbg !3, !llvm.preserve.access.index !7' in result
    with pytest.raises(ValueError, match='base type i32'):
        type_id.lower(fixture_ir(['tid']), targets({'tid': (1, 'int')}), fixture_btf())


@pytest.mark.parametrize('extra', ['', RUST_COMPOSITE + RUST_COMPOSITE.replace('!7 =', '!9 =')])
def test_a_local_id_needs_exactly_one_rust_composite(extra):
    with pytest.raises(ValueError, match='expected one Rust debug-info structure thing'):
        type_id.lower(fixture_ir(['tid']) + extra, targets({'tid': (4, 'thing')}), fixture_btf())


@pytest.mark.parametrize('source', ['// BTF_TYPE_ID: invalid', '// BTF_TYPE_ID: id struct x\n// BTF_TYPE_ID: id struct x',
                                    '// BTF_TYPE_INFO: id exists int int', '// BTF_ENUM_VALUE: id value enum mode'])
def test_invalid_annotations_fail(source):
    with pytest.raises(ValueError, match='invalid or duplicate'):
        type_id.declarations(source)


def test_unselected_ir_is_unchanged():
    assert type_id.declarations('// ordinary comment') == {}
    assert type_id.lower('unchanged', {}, None) == 'unchanged'


# --- TYPE_EXISTS / TYPE_SIZE / TYPE_MATCHES and ENUMVAL_EXISTS / ENUMVAL_VALUE ---

def test_declarations_parse_the_type_info_and_enum_forms():
    assert declarations('// BTF_TYPE_INFO: sz size struct a_struct') == {'sz': ('size', 4, 'a_struct', None, False)}
    assert declarations('// BTF_TYPE_INFO: m matches typedef fn_t') == {'m': ('matches', 8, 'fn_t', None, False)}
    assert declarations('// BTF_ENUM_VALUE: v value enum mode ON') == {'v': ('enum_value', 6, 'mode', 'ON', False)}
    assert declarations('// BTF_ENUM_VALUE: e exists typedef anon_enum X') == {
        'e': ('enum_exists', 8, 'anon_enum', 'X', False)}


def test_type_info_needs_the_c_relocation_of_the_same_kind(monkeypatch):
    monkeypatch.setattr(type_id, 'core_relo_records',
                        lambda _: {'prog': [(0, 2, '0', 8), (1, 2, '0', 9), (2, 3, '0', 12)]})
    assert contract(fixture_btf(), {'e': type_id.Decl('exists', 4, 'thing'),
                                    's': type_id.Decl('size', 4, 'thing'),
                                    'm': type_id.Decl('matches', 8, 'alias')}) == {'e': 2, 's': 2, 'm': 3}
    for op, kind, name in [('matches', 4, 'thing'), ('exists', 8, 'alias'), ('size', 5, 'thing')]:
        with pytest.raises(ValueError, match=f'C TYPE_{op.upper()}'):
            type_id.contract(None, fixture_btf(), {'x': type_id.Decl(op, kind, name)})


def test_enum_values_need_the_c_relocation_on_that_enumerator(monkeypatch):
    monkeypatch.setattr(type_id, 'core_relo_records', lambda _: {'prog': [(0, 4, '0', 10), (1, 4, '0', 11)]})
    assert contract(fixture_btf(), {'e': type_id.Decl('enum_exists', 6, 'mode', 'ON'),
                                    'v': type_id.Decl('enum_value', 6, 'mode', 'ON')}) == {'e': (4, 0, 1), 'v': (4, 0, 1)}
    with pytest.raises(ValueError, match='ENUMVAL_VALUE relocation on mode.OFF'):
        type_id.contract(None, fixture_btf(), {'v': type_id.Decl('enum_value', 6, 'mode', 'OFF')})


def test_type_info_lowers_to_the_preserve_type_info_intrinsic():
    names = {'e': (type_id.Decl('exists', 4, 'thing'), 2), 's': (type_id.Decl('size', 8, 'alias'), 3),
             'm': (type_id.Decl('matches', 6, 'mode'), 4)}
    result = type_id.lower(fixture_ir(names, ret='i32'), names, fixture_btf())
    assert 'call i32 @llvm.bpf.preserve.type.info(i32 1, i64 0), !dbg !3, !llvm.preserve.access.index' in result
    assert 'call i32 @llvm.bpf.preserve.type.info(i32 2, i64 1)' in result
    assert 'call i32 @llvm.bpf.preserve.type.info(i32 3, i64 2)' in result
    assert 'declare i32 @llvm.bpf.preserve.type.info(i32, i64)' in result
    assert 'DW_TAG_typedef, name: "alias", file: !1, baseType: !' in result  # the full chain, down to int
    assert 'DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)' in result
    with pytest.raises(ValueError, match='extern fn\\(\\) -> u32'):
        type_id.lower(fixture_ir(names), names, fixture_btf())


def test_enum_values_lower_to_the_preserve_enum_value_intrinsic():
    names = {'e': (type_id.Decl('enum_exists', 6, 'mode', 'ON'), (4, 0, 1)),
             'v': (type_id.Decl('enum_value', 6, 'mode', 'ON'), (4, 0, 1))}
    result = type_id.lower(fixture_ir(names), names, fixture_btf())
    assert '@.core_enum.0 = private unnamed_addr constant [5 x i8] c"ON:1\\00", align 1' in result
    assert 'call i64 @llvm.bpf.preserve.enum.value(i32 1, ptr @.core_enum.0, i64 0), !dbg !3' in result
    assert 'call i64 @llvm.bpf.preserve.enum.value(i32 2, ptr @.core_enum.1, i64 1), !dbg !3' in result
    assert 'declare i64 @llvm.bpf.preserve.enum.value(i32, ptr, i64)' in result
    assert result.count('DW_TAG_enumeration_type, name: "mode"') == 1
