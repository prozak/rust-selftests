#!/usr/bin/env python3
"""Lower explicit Rust type-ID polyfills to LLVM's CO-RE target-ID intrinsic.

`// BTF_TYPE_ID: function KIND NAME` declares an extern fn() -> u64.
KIND is struct, union, enum, typedef, or int. The pristine C object's
TYPE_ID_TARGET relocation supplies type identity, never a kernel ID or code.
LLVM emits the relocation and libbpf resolves it against the loading kernel.
Aggregate descriptors only need names/kinds; Rust field access remains CO-RE.
"""
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'equiv'))
from bpfelf import BpfElf
from bpfcore import Btf, core_relo_records

KINDS = {'int': 1, 'struct': 4, 'union': 5, 'enum': 6, 'typedef': 8}


def declarations(source):
    result = {}
    for line in source.splitlines():
        if not line.startswith('// BTF_TYPE_ID:'):
            continue
        m = re.fullmatch(r'// BTF_TYPE_ID: ([A-Za-z_]\w*) (int|struct|union|enum|typedef) ([A-Za-z_][\w ]*)', line)
        if not m or m[1] in result:
            raise ValueError(f'invalid or duplicate type-ID declaration: {line}')
        result[m[1]] = (KINDS[m[2]], m[3])
    return result


def contract(elf, btf, names):
    ids = {tid for records in core_relo_records(elf).values()
           for _, tid, _, kind in records if kind == 7}
    result = {}
    for function, (kind, name) in names.items():
        matches = [tid for tid in ids if btf.types[tid].kind == kind and btf.types[tid].name == name]
        if len(matches) != 1:
            raise ValueError(f'{function}: expected one C TYPE_ID_TARGET type for {name}')
        result[function] = matches[0]
    return result


def lower(ir, types, btf):
    if not types:
        return ir
    file = re.search(r'^(!\d+) = !DIFile\(', ir, re.M)
    if not file:
        raise ValueError('type-ID relocations require debug info')
    next_id = max(map(int, re.findall(r'!(\d+)', ir)), default=0) + 1
    metadata = []

    def add(value):
        nonlocal next_id
        ref = f'!{next_id}'
        next_id += 1
        metadata.append(f'{ref} = {value}')
        return ref

    empty = add('!{}')
    emitted = {}

    def quoted(name):
        return '"' + ''.join(chr(c) if 32 <= c < 127 and c not in (34, 92)
                             else f'\\{c:02X}' for c in name.encode()) + '"'

    def typ(tid):
        if tid in emitted:
            return emitted[tid]
        t = btf.types[tid]
        if t.kind == 1:
            value = (f'!DIBasicType(name: {quoted(t.name)}, size: {t.size * 8}, '
                     f'encoding: DW_ATE_{"signed" if t.int_signed else "unsigned"})')
        elif t.kind in (4, 5):
            tag = 'structure' if t.kind == 4 else 'union'
            value = (f'distinct !DICompositeType(tag: DW_TAG_{tag}_type, '
                     f'name: {quoted(t.name)}, file: {file[1]}, size: {t.size * 8}, elements: {empty})')
        elif t.kind == 8:
            value = f'!DIDerivedType(tag: DW_TAG_typedef, name: {quoted(t.name)}, baseType: {typ(t.type)})'
        elif t.kind == 6:
            elements = add('!{' + ', '.join(add(f'!DIEnumerator(name: {quoted(n)}, value: {v})')
                                          for n, v in t.enums) + '}')
            base = add(f'!DIBasicType(name: "{ "int" if t.kflag else "unsigned int"}", '
                       f'size: {t.size * 8}, encoding: DW_ATE_{"signed" if t.kflag else "unsigned"})')
            value = (f'!DICompositeType(tag: DW_TAG_enumeration_type, name: {quoted(t.name)}, '
                     f'file: {file[1]}, baseType: {base}, size: {t.size * 8}, elements: {elements})')
        else:
            raise ValueError(f'unsupported type-ID BTF kind {t.kind}')
        emitted[tid] = add(value)
        return emitted[tid]

    call_id = 0
    for name, tid in types.items():
        declaration = r'^declare (?:noundef )?i64 @' + re.escape(name) + r'\(\)[^\n]*\n'
        if len(re.findall(declaration, ir, re.M)) != 1:
            raise ValueError(f'{name}: expected an extern fn() -> u64')
        ir = re.sub(declaration, '', ir, flags=re.M)
        pattern = r'((?:tail )?call )(?:noundef )?i64 @' + re.escape(name) + r'\(\)([^\n]*)'
        count = 0

        def replace(m):
            nonlocal call_id, count
            count += 1
            call_id += 1
            return (f'{m[1]}i64 @llvm.bpf.btf.type.id(i32 {call_id}, i64 1){m[2]}, '
                    f'!llvm.preserve.access.index {typ(tid)}')

        ir = re.sub(pattern, replace, ir)
        if not count or re.search(r'@' + re.escape(name) + r'\b', ir):
            raise ValueError(f'{name}: missing calls or unsupported use of type-ID polyfill')
    ir += '\ndeclare i64 @llvm.bpf.btf.type.id(i32, i64)\n'
    return ir + '\n'.join(metadata) + '\n'


if __name__ == '__main__':
    path, source, oracle = map(Path, sys.argv[1:])
    original = Path(str(oracle) + '.corig')
    elf = BpfElf(original if original.exists() else oracle)
    btf = Btf(elf.section_by_name('.BTF').data)
    path.write_text(lower(path.read_text(), contract(elf, btf, declarations(source.read_text())), btf))
