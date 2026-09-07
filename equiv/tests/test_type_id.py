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
    assert type_id.contract(None, fixture_btf(), {'tid': (4, 'thing')}) == {'tid': 2}
    for kind, name in [(5, 'thing'), (8, 'alias'), (4, 'missing')]:
        with pytest.raises(ValueError, match='C TYPE_ID_TARGET'):
            type_id.contract(None, fixture_btf(), {'tid': (kind, name)})


@pytest.mark.parametrize('source', ['// BTF_TYPE_ID: invalid', '// BTF_TYPE_ID: id struct x\n// BTF_TYPE_ID: id struct x'])
def test_invalid_annotations_fail(source):
    with pytest.raises(ValueError, match='invalid or duplicate'):
        type_id.declarations(source)


def test_unselected_ir_is_unchanged():
    assert type_id.declarations('// ordinary comment') == {}
    assert type_id.lower('unchanged', {}, None) == 'unchanged'
