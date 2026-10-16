#!/usr/bin/env python3
"""Lower explicit Rust type-ID polyfills to LLVM's CO-RE target-ID intrinsic.

`// BTF_TYPE_ID: function KIND NAME` declares an extern fn() -> u64.
KIND is struct, union, enum, typedef, or int. The pristine C object's
TYPE_ID_TARGET relocation supplies type identity, never a kernel ID or code.
LLVM emits the relocation and libbpf resolves it against the loading kernel.
Aggregate descriptors only need names/kinds; Rust field access remains CO-RE.

`// BTF_TYPE_ID: function local struct NAME` is bpf_core_type_id_local(), the
id of the object's OWN type (bpf_obj_new(typeof(*n)) in C). The pristine C
object must carry a TYPE_ID_LOCAL relocation for it. The relocation points at
rustc's own debug-info composite for NAME, so llc emits that struct with all
of its members into .BTF -- the kernel reads the layout from there.

`local int NAME` is the local id of a C integer type (bpf_core_type_id_local(int)),
pointing at rustc's debug-info base type that scripts/btf_rename.py renames to
NAME (int -> i32). `local struct NAME (anonymous)` / `local union NAME (anonymous)`
names the Rust type NAME standing in for a C type that has no name
(bpf_obj_new(struct { int data; })); the C object must carry a TYPE_ID_LOCAL
relocation for an anonymous type of that kind, but as several may share the
kind nothing further is checked. The verifier's messages for the negative
tests these serve never print the type's name.
"""
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'equiv'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from bpfelf import BpfElf
from bpfcore import Btf, core_relo_records
from btf_rename import RENAME

KINDS = {'int': 1, 'struct': 4, 'union': 5, 'enum': 6, 'typedef': 8}
# C integer type name -> rustc's debug-info name (btf_rename.py's inverse)
RUST_INT = {c: rust for rust, c in RENAME.items()}


def declarations(source):
    """function -> (BTF kind, name, local, anonymous in C)."""
    result = {}
    for line in source.splitlines():
        if not line.startswith('// BTF_TYPE_ID:'):
            continue
        m = re.fullmatch(r'// BTF_TYPE_ID: ([A-Za-z_]\w*) (local )?(int|struct|union|enum|typedef) '
                         r'([A-Za-z_][\w ]*?)( \(anonymous\))?', line)
        if not m or m[1] in result:
            raise ValueError(f'invalid or duplicate type-ID declaration: {line}')
        if m[2] and m[3] not in ('struct', 'union', 'int'):
            raise ValueError(f'a local type ID must name a struct, union or int: {line}')
        if m[5] and not (m[2] and m[3] in ('struct', 'union')):
            raise ValueError(f'only a local struct or union can be anonymous in C: {line}')
        if m[2] and m[3] == 'int' and m[4] not in RUST_INT:
            raise ValueError(f'unknown C integer type {m[4]!r} (one of {sorted(RUST_INT)}): {line}')
        result[m[1]] = (KINDS[m[3]], m[4], bool(m[2]), bool(m[5]))
    return result


def contract(elf, btf, names):
    """function -> C type id, or -> (kind, name) for a local type ID."""
    relos = [(tid, kind) for records in core_relo_records(elf).values()
             for _, tid, _, kind in records]
    result = {}
    for function, (kind, name, local, anon) in names.items():
        want = 6 if local else 7
        ids = {tid for tid, k in relos if k == want}
        if anon:
            if not any(btf.types[tid].kind == kind and not btf.types[tid].name for tid in ids):
                raise ValueError(f'{function}: expected a C TYPE_ID_LOCAL anonymous type of kind {kind}')
            result[function] = (kind, name)
            continue
        matches = [tid for tid in ids if btf.types[tid].kind == kind and btf.types[tid].name == name]
        if len(matches) != 1:
            raise ValueError(f'{function}: expected one C TYPE_ID_{"LOCAL" if local else "TARGET"} '
                             f'type for {name}')
        result[function] = (kind, name) if local else matches[0]
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

    def local(kind, name):
        if kind == 1:
            rust = RUST_INT[name]
            found = re.findall(r'^(!\d+) = !DIBasicType\(name: ' + re.escape(quoted(rust)) + r',', ir, re.M)
            if len(found) != 1:
                raise ValueError(f'expected one Rust debug-info base type {rust} (C {name}), found {len(found)}')
            return found[0]
        tag = 'structure' if kind == 4 else 'union'
        found = re.findall(r'^(!\d+) = (?:distinct )?!DICompositeType\(tag: DW_TAG_' + tag
                           + r'_type, name: ' + re.escape(quoted(name)) + r',', ir, re.M)
        if len(found) != 1:
            raise ValueError(f'expected one Rust debug-info {tag} {name}, found {len(found)}')
        return found[0]

    call_id = 0
    for name, tid in types.items():
        if isinstance(tid, tuple):
            flag, target = 0, local(*tid)
        else:
            flag, target = 1, None
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
            return (f'{m[1]}i64 @llvm.bpf.btf.type.id(i32 {call_id}, i64 {flag}){m[2]}, '
                    f'!llvm.preserve.access.index {target or typ(tid)}')

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
