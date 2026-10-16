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


def fixture_ir(names):
    return ('define i64 @prog() !dbg !2 {\n' +
            ''.join(f'  %r{i} = tail call noundef i64 @{name}(), !dbg !3\n' for i, name in enumerate(names)) +
            '  ret i64 %r0\n}\n' +
            ''.join(f'declare noundef i64 @{name}()\n' for name in names) +
            '!1 = !DIFile(filename: "test.rs", directory: "/tmp")\n')


def test_standard_intrinsics_retain_type_identity_without_pinning_target_ids():
    names = {'tid_int': 1, 'tid_thing': 2, 'tid_alias': 3, 'tid_mode': 4}
    result = type_id.lower(fixture_ir(names), names, fixture_btf())
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
                      {'tid': 2}, fixture_btf())


def test_rejects_address_taken_polyfill():
    ir = fixture_ir(['tid']) + '@address = global ptr @tid\n'
    with pytest.raises(ValueError, match='unsupported use'):
        type_id.lower(ir, {'tid': 2}, fixture_btf())


def test_requires_c_target_relocation_with_same_kind_and_name(monkeypatch):
    monkeypatch.setattr(type_id, 'core_relo_records', lambda _: {'prog': [(0, 2, '0', 7), (1, 3, '0', 6)]})
    assert type_id.contract(None, fixture_btf(), {'tid': (4, 'thing', False, False)}) == {'tid': 2}
    for kind, name in [(5, 'thing'), (8, 'alias'), (4, 'missing')]:
        with pytest.raises(ValueError, match='C TYPE_ID_TARGET'):
            type_id.contract(None, fixture_btf(), {'tid': (kind, name, False, False)})


def test_local_ids_need_a_c_local_relocation(monkeypatch):
    # [2] thing carries only a TARGET relocation: not enough for a local ID
    monkeypatch.setattr(type_id, 'core_relo_records', lambda _: {'prog': [(0, 2, '0', 7)]})
    with pytest.raises(ValueError, match='C TYPE_ID_LOCAL'):
        type_id.contract(None, fixture_btf(), {'tid': (4, 'thing', True, False)})
    monkeypatch.setattr(type_id, 'core_relo_records', lambda _: {'prog': [(0, 2, '0', 6)]})
    assert type_id.contract(None, fixture_btf(), {'tid': (4, 'thing', True, False)}) == {'tid': (4, 'thing')}


def test_an_anonymous_c_type_needs_a_local_relocation_of_its_kind(monkeypatch):
    # [5] is anonymous: the Rust stand-in may have any name, but a C local
    # relocation for SOME anonymous struct must exist
    monkeypatch.setattr(type_id, 'core_relo_records', lambda _: {'prog': [(0, 5, '0', 6)]})
    assert type_id.contract(None, fixture_btf(), {'tid': (4, 'stand_in', True, True)}) == {'tid': (4, 'stand_in')}
    with pytest.raises(ValueError, match='anonymous type of kind 5'):
        type_id.contract(None, fixture_btf(), {'tid': (5, 'stand_in', True, True)})
    monkeypatch.setattr(type_id, 'core_relo_records', lambda _: {'prog': [(0, 2, '0', 6)]})
    with pytest.raises(ValueError, match='anonymous type of kind 4'):
        type_id.contract(None, fixture_btf(), {'tid': (4, 'stand_in', True, True)})


def test_a_local_int_id_needs_the_c_int_relocation(monkeypatch):
    monkeypatch.setattr(type_id, 'core_relo_records', lambda _: {'prog': [(0, 1, '0', 6)]})
    assert type_id.contract(None, fixture_btf(), {'tid': (1, 'int', True, False)}) == {'tid': (1, 'int')}


def test_declarations_parse_the_local_form():
    assert type_id.declarations('// BTF_TYPE_ID: new_id local struct node_data') == {
        'new_id': (4, 'node_data', True, False)}
    assert type_id.declarations('// BTF_TYPE_ID: int_id local int int') == {'int_id': (1, 'int', True, False)}
    assert type_id.declarations('// BTF_TYPE_ID: u_id local union stand_in (anonymous)') == {
        'u_id': (5, 'stand_in', True, True)}
    assert type_id.declarations('// BTF_TYPE_ID: t_id struct task_struct') == {'t_id': (4, 'task_struct', False, False)}
    with pytest.raises(ValueError, match='struct, union or int'):
        type_id.declarations('// BTF_TYPE_ID: new_id local typedef u32')
    with pytest.raises(ValueError, match='anonymous'):
        type_id.declarations('// BTF_TYPE_ID: new_id struct node_data (anonymous)')
    with pytest.raises(ValueError, match='unknown C integer type'):
        type_id.declarations('// BTF_TYPE_ID: new_id local int size_t')


RUST_COMPOSITE = ('!7 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "thing", '
                  'scope: !1, file: !1, size: 64, align: 64, elements: !8)\n!8 = !{}\n')


def test_a_local_id_points_at_rustcs_own_composite():
    result = type_id.lower(fixture_ir(['tid']) + RUST_COMPOSITE, {'tid': (4, 'thing')}, fixture_btf())
    assert 'call i64 @llvm.bpf.btf.type.id(i32 1, i64 0), !dbg !3, !llvm.preserve.access.index !7' in result
    # no synthesized stand-in: the layout must be Rust's own
    assert result.count('DW_TAG_structure_type, name: "thing"') == 1


def test_a_local_int_id_points_at_rustcs_base_type():
    ir = fixture_ir(['tid']) + '!7 = !DIBasicType(name: "i32", size: 32, encoding: DW_ATE_signed)\n'
    result = type_id.lower(ir, {'tid': (1, 'int')}, fixture_btf())
    assert 'call i64 @llvm.bpf.btf.type.id(i32 1, i64 0), !dbg !3, !llvm.preserve.access.index !7' in result
    with pytest.raises(ValueError, match='base type i32'):
        type_id.lower(fixture_ir(['tid']), {'tid': (1, 'int')}, fixture_btf())


@pytest.mark.parametrize('extra', ['', RUST_COMPOSITE + RUST_COMPOSITE.replace('!7 =', '!9 =')])
def test_a_local_id_needs_exactly_one_rust_composite(extra):
    with pytest.raises(ValueError, match='expected one Rust debug-info structure thing'):
        type_id.lower(fixture_ir(['tid']) + extra, {'tid': (4, 'thing')}, fixture_btf())


@pytest.mark.parametrize('source', ['// BTF_TYPE_ID: invalid', '// BTF_TYPE_ID: id struct x\n// BTF_TYPE_ID: id struct x'])
def test_invalid_annotations_fail(source):
    with pytest.raises(ValueError, match='invalid or duplicate'):
        type_id.declarations(source)


def test_unselected_ir_is_unchanged():
    assert type_id.declarations('// ordinary comment') == {}
    assert type_id.lower('unchanged', {}, None) == 'unchanged'
