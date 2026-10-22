#!/usr/bin/env python3
"""Lower explicit Rust CO-RE type polyfills to LLVM's CO-RE intrinsics.

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

`// BTF_TYPE_ID: function local KIND NAME (copy)` is bpf_core_type_id_local()
on a type the Rust object does not define: the C object's TYPE_ID_LOCAL type of
that kind and name is synthesized in full (as the type-info markers below do),
so the object's BTF carries one type of exactly the C shape and the relocation
points at it. KIND adds ptr and array; for an anonymous type NAME is its C
spelling (`void *`, `_Bool (*)(int)`, `_Bool[47]`, `struct { int marker_field; }`,
`enum { MARKER_ENUM_VAL }`), matched by cspell() below.

`// BTF_TYPE_INFO: function exists|size|matches KIND NAME` declares an extern
fn() -> u32 standing for bpf_core_type_exists / bpf_core_type_size /
bpf_core_type_matches (TYPE_EXISTS / TYPE_SIZE / TYPE_MATCHES relocations).
`// BTF_ENUM_VALUE: function exists|value enum|typedef NAME MEMBER` declares an
extern fn() -> u64 for bpf_core_enum_value_exists / bpf_core_enum_value
(ENUMVAL_EXISTS / ENUMVAL_VALUE). libbpf answers these by walking INTO the
local type (member names, func-proto arity, enum members ...), so the local
type is synthesized in full from the pristine C object's BTF, which must carry
a relocation of the same kind on a type of that kind and name (and, for enums,
on that member). The TYPE_ID kinds above keep their shallow (name-only)
descriptors: only the name and kind reach the kernel there.
"""
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'equiv'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from bpfelf import BpfElf
from bpfcore import Btf, core_relo_records
from btf_rename import RENAME

KINDS = {'int': 1, 'ptr': 2, 'array': 3, 'struct': 4, 'union': 5, 'enum': 6, 'typedef': 8}
# C integer type name -> rustc's debug-info name (btf_rename.py's inverse)
RUST_INT = {c: rust for rust, c in RENAME.items()}
# op -> (bpf_core_relo_kind of the C object, llvm intrinsic flag)
TYPE_INFO_OPS = {'exists': (8, 0), 'size': (9, 1), 'matches': (12, 2)}
ENUM_OPS = {'exists': (10, 0), 'value': (11, 1)}


class Decl:
    """One polyfill: op is id / local (BTF_TYPE_ID), exists / size / matches
    (BTF_TYPE_INFO) or enum_exists / enum_value (BTF_ENUM_VALUE)."""

    def __init__(self, op, kind, name, member=None, anon=False, copy=False):
        self.op, self.kind, self.name, self.member = op, kind, name, member
        self.anon, self.copy = anon, copy


def declarations(source):
    """function -> Decl."""
    result = {}
    for line in source.splitlines():
        if line.startswith('// BTF_TYPE_ID:'):
            m = re.fullmatch(r'// BTF_TYPE_ID: ([A-Za-z_]\w*) (local )?(int|ptr|array|struct|union|enum|typedef) '
                             r'([A-Za-z_][\w \*\(\)\[\]{};]*?)( \(anonymous\)| \(copy\))?', line)
            if not m or m[1] in result:
                raise ValueError(f'invalid or duplicate type-ID declaration: {line}')
            copy = m[5] == ' (copy)'
            if copy and not m[2]:
                raise ValueError(f'only a local type ID can be a copy of the C type: {line}')
            if m[3] in ('ptr', 'array') and not copy:
                raise ValueError(f'a ptr or array type ID must be a local copy: {line}')
            if m[2] and not copy and m[3] not in ('struct', 'union', 'int'):
                raise ValueError(f'a local type ID must name a struct, union or int, or be a copy: {line}')
            if m[5] == ' (anonymous)' and not (m[2] and m[3] in ('struct', 'union')):
                raise ValueError(f'only a local struct or union can be anonymous in C: {line}')
            if m[2] and not copy and m[3] == 'int' and m[4] not in RUST_INT:
                raise ValueError(f'unknown C integer type {m[4]!r} (one of {sorted(RUST_INT)}): {line}')
            result[m[1]] = Decl('local' if m[2] else 'id', KINDS[m[3]], m[4],
                                anon=m[5] == ' (anonymous)', copy=copy)
        elif line.startswith('// BTF_TYPE_INFO:'):
            m = re.fullmatch(r'// BTF_TYPE_INFO: ([A-Za-z_]\w*) (exists|size|matches) '
                             r'(struct|union|enum|typedef) ([A-Za-z_]\w*)', line)
            if not m or m[1] in result:
                raise ValueError(f'invalid or duplicate type-info declaration: {line}')
            result[m[1]] = Decl(m[2], KINDS[m[3]], m[4])
        elif line.startswith('// BTF_ENUM_VALUE:'):
            m = re.fullmatch(r'// BTF_ENUM_VALUE: ([A-Za-z_]\w*) (exists|value) (enum|typedef) '
                             r'([A-Za-z_]\w*) ([A-Za-z_]\w*)', line)
            if not m or m[1] in result:
                raise ValueError(f'invalid or duplicate enum-value declaration: {line}')
            result[m[1]] = Decl('enum_' + m[2], KINDS[m[3]], m[4], member=m[5])
    return result


def enum_of(btf, tid):
    """The ENUM/ENUM64 behind a (possibly typedef'd) type, or None."""
    while btf.types[tid].kind in (8, 9, 10, 11):
        tid = btf.types[tid].type
    return btf.types[tid] if btf.types[tid].kind in (6, 19) else None


def cspell(btf, tid):
    """The C spelling of a BTF type, enough to tell anonymous TYPE_ID_LOCAL
    types apart (a named aggregate is `struct NAME`, an anonymous one is
    `struct { <first member> }`)."""
    if tid == 0:
        return 'void'
    t = btf.types[tid]
    if t.kind in (1, 16, 8) or (t.kind in (4, 5, 6, 19, 7) and t.name):
        prefix = {4: 'struct ', 5: 'union ', 6: 'enum ', 19: 'enum ', 7: 'union ' if t.fwd_union else 'struct '}
        return prefix.get(t.kind, '') + t.name
    if t.kind == 2:
        if t.type and btf.types[t.type].kind == 13:
            ret, params = btf.types[t.type].proto
            return f'{cspell(btf, ret)} (*)({", ".join(cspell(btf, p) for p in params) or "void"})'
        return cspell(btf, t.type) + ' *'
    if t.kind == 3:
        et, n = t.array
        return f'{cspell(btf, et)}[{n}]'
    if t.kind in (4, 5):
        tag = 'struct' if t.kind == 4 else 'union'
        m = t.members[0] if t.members else None
        return f'{tag} {{ {cspell(btf, m.type)} {m.name}; }}' if m else f'{tag} {{ }}'
    if t.kind in (6, 19):
        return f'enum {{ {t.enums[0][0]} }}' if t.enums else 'enum { }'
    if t.kind in (9, 10, 11):
        return {9: 'volatile ', 10: 'const ', 11: 'restrict '}[t.kind] + cspell(btf, t.type)
    raise ValueError(f'no C spelling for BTF kind {t.kind}')


def contract(elf, btf, names):
    """function -> (Decl, target): the C type id, or (kind, name) for a
    local type ID, or (type id, member index, value) for an enum value."""
    relos = [(tid, kind, acc) for records in core_relo_records(elf).values()
             for _, tid, acc, kind in records]
    result = {}
    for function, d in names.items():
        if d.op in ('id', 'local'):
            want = 6 if d.op == 'local' else 7
            ids = {tid for tid, k, _ in relos if k == want}
            if d.copy:
                matches = [tid for tid in ids if btf.types[tid].kind == d.kind
                           and (btf.types[tid].name == d.name if btf.types[tid].name
                                else cspell(btf, tid) == d.name)]
                if len(matches) != 1:
                    raise ValueError(f'{function}: expected one C TYPE_ID_LOCAL type spelled {d.name!r} '
                                     f'of kind {d.kind}, found {len(matches)}')
                result[function] = (d, matches[0])
                continue
            if d.anon:
                if not any(btf.types[tid].kind == d.kind and not btf.types[tid].name for tid in ids):
                    raise ValueError(f'{function}: expected a C TYPE_ID_LOCAL anonymous type of kind {d.kind}')
                result[function] = (d, (d.kind, d.name))
                continue
            matches = [tid for tid in ids if btf.types[tid].kind == d.kind and btf.types[tid].name == d.name]
            if len(matches) != 1:
                raise ValueError(f'{function}: expected one C TYPE_ID_{"LOCAL" if d.op == "local" else "TARGET"} '
                                 f'type for {d.name}')
            result[function] = (d, (d.kind, d.name) if d.op == 'local' else matches[0])
        elif d.op in TYPE_INFO_OPS:
            want = TYPE_INFO_OPS[d.op][0]
            matches = {tid for tid, k, _ in relos
                       if k == want and btf.types[tid].kind == d.kind and btf.types[tid].name == d.name}
            if len(matches) != 1:
                raise ValueError(f'{function}: expected one C TYPE_{d.op.upper()} relocation on {d.name}')
            result[function] = (d, matches.pop())
        else:
            want = ENUM_OPS[d.op[5:]][0]
            kinds = (6, 19) if d.kind == 6 else (d.kind,)  # `enum` covers ENUM64 too
            matches = {(tid, int(acc)) for tid, k, acc in relos
                       if k == want and btf.types[tid].kind in kinds and btf.types[tid].name == d.name
                       and enum_of(btf, tid) and int(acc) < len(enum_of(btf, tid).enums)
                       and enum_of(btf, tid).enums[int(acc)][0] == d.member}
            if len(matches) != 1:
                raise ValueError(f'{function}: expected one C ENUMVAL_{d.op[5:].upper()} relocation '
                                 f'on {d.name}.{d.member}')
            tid, idx = matches.pop()
            result[function] = (d, (tid, idx, enum_of(btf, tid).enums[idx][1]))
    return result


def lower(ir, types, btf):
    if not types:
        return ir
    file = re.search(r'^(!\d+) = !DIFile\(', ir, re.M)
    if not file:
        raise ValueError('type-ID relocations require debug info')
    next_id = max(map(int, re.findall(r'!(\d+)', ir)), default=0) + 1
    metadata = []
    globals_ = []

    def reserve():
        nonlocal next_id
        ref = f'!{next_id}'
        next_id += 1
        return ref

    def add(value, ref=None):
        ref = ref or reserve()
        metadata.append(f'{ref} = {value}')
        return ref

    empty = add('!{}')
    emitted = {}

    def quoted(name):
        return '"' + ''.join(chr(c) if 32 <= c < 127 and c not in (34, 92)
                             else f'\\{c:02X}' for c in name.encode()) + '"'

    def named(t):
        return f'name: {quoted(t.name)}, ' if t.name else ''

    def basic(t):
        if t.kind == 16:
            return f'!DIBasicType(name: {quoted(t.name)}, size: {t.size * 8}, encoding: DW_ATE_float)'
        enc = t.int_enc
        encoding = ('DW_ATE_boolean' if enc & 4 else 'DW_ATE_signed_char' if enc == 3
                    else 'DW_ATE_unsigned_char' if enc & 2 else 'DW_ATE_signed' if enc & 1
                    else 'DW_ATE_unsigned')
        return f'!DIBasicType(name: {quoted(t.name)}, size: {t.size * 8}, encoding: {encoding})'

    def enum(t):
        wide = t.kind == 19
        # a value past int64 needs the unsigned form, as clang writes it
        elements = add('!{' + ', '.join(
            add(f'!DIEnumerator(name: {quoted(n)}, value: {v}' + (', isUnsigned: true' if v >= 1 << 63 else '') + ')')
            for n, v in t.enums) + '}')
        cname = ('long' if wide else 'int') if t.kflag else ('unsigned long' if wide else 'unsigned int')
        base = add(f'!DIBasicType(name: "{cname}", size: {t.size * 8}, '
                   f'encoding: DW_ATE_{"signed" if t.kflag else "unsigned"})')
        return (f'!DICompositeType(tag: DW_TAG_enumeration_type, {named(t)}'
                f'file: {file[1]}, baseType: {base}, size: {t.size * 8}, elements: {elements})')

    def typ(tid):
        """Shallow descriptor (TYPE_ID_TARGET): name and kind only."""
        if tid in emitted:
            return emitted[tid]
        t = btf.types[tid]
        if t.kind == 1:
            value = basic(t)
        elif t.kind in (4, 5):
            tag = 'structure' if t.kind == 4 else 'union'
            value = (f'distinct !DICompositeType(tag: DW_TAG_{tag}_type, '
                     f'name: {quoted(t.name)}, file: {file[1]}, size: {t.size * 8}, elements: {empty})')
        elif t.kind == 8:
            # the target is matched by name and kind only; a ptr / array base
            # just has to be a valid node, and deep() is the one that has them
            base = typ(t.type) if btf.types[t.type].kind in (1, 4, 5, 6, 8) else deep(t.type)
            value = f'!DIDerivedType(tag: DW_TAG_typedef, name: {quoted(t.name)}, baseType: {base})'
        elif t.kind == 6:
            value = enum(t)
        else:
            raise ValueError(f'unsupported type-ID BTF kind {t.kind}')
        emitted[tid] = add(value)
        return emitted[tid]

    deep_emitted = {}
    MODS = {9: 'volatile', 10: 'const', 11: 'restrict'}

    def deep(tid):
        """Full descriptor (TYPE_EXISTS / SIZE / MATCHES / ENUMVAL): the C
        BTF type with everything it reaches, as clang's debug info has it."""
        if tid == 0:
            return 'null'
        if tid in deep_emitted:
            return deep_emitted[tid]
        t = btf.types[tid]
        if t.kind in (1, 16):
            return add_deep(tid, basic(t))
        if t.kind == 2:
            ref = deep_emitted[tid] = reserve()
            return add(f'!DIDerivedType(tag: DW_TAG_pointer_type, baseType: {deep(t.type)}, size: 64)', ref)
        if t.kind == 3:
            et, n = t.array
            ref = deep_emitted[tid] = reserve()
            sub = add(f'!{{{add(f"!DISubrange(count: {n})")}}}')
            return add(f'!DICompositeType(tag: DW_TAG_array_type, baseType: {deep(et)}, '
                       f'size: {btf.type_size(tid) * 8}, elements: {sub})', ref)
        if t.kind in (4, 5):
            tag = 'structure' if t.kind == 4 else 'union'
            ref = deep_emitted[tid] = reserve()
            members = []
            for m in t.members:
                size = m.bitfield_size if m.bitfield_size else btf.type_size(m.type) * 8
                extra = f', flags: DIFlagBitField, extraData: i64 {m.bit_offset // 8 * 8}' if m.bitfield_size else ''
                offset = f', offset: {m.bit_offset}' if m.bit_offset else ''
                members.append(add(f'!DIDerivedType(tag: DW_TAG_member, {named(m)}scope: {ref}, '
                                   f'file: {file[1]}, baseType: {deep(m.type)}, size: {size}{offset}{extra})'))
            elements = add('!{' + ', '.join(members) + '}') if members else empty
            return add(f'distinct !DICompositeType(tag: DW_TAG_{tag}_type, {named(t)}file: {file[1]}, '
                       f'size: {t.size * 8}, elements: {elements})', ref)
        if t.kind in (6, 19):
            ref = deep_emitted[tid] = reserve()
            return add(enum(t), ref)
        if t.kind == 7:
            tag = 'union' if t.fwd_union else 'structure'
            return add_deep(tid, f'!DICompositeType(tag: DW_TAG_{tag}_type, name: {quoted(t.name)}, '
                                 f'file: {file[1]}, flags: DIFlagFwdDecl)')
        if t.kind == 8:
            ref = deep_emitted[tid] = reserve()
            return add(f'!DIDerivedType(tag: DW_TAG_typedef, name: {quoted(t.name)}, file: {file[1]}, '
                       f'baseType: {deep(t.type)})', ref)
        if t.kind in MODS:
            ref = deep_emitted[tid] = reserve()
            return add(f'!DIDerivedType(tag: DW_TAG_{MODS[t.kind]}_type, baseType: {deep(t.type)})', ref)
        if t.kind == 13:
            ref = deep_emitted[tid] = reserve()
            ret, params = t.proto
            types = add('!{' + ', '.join([deep(ret)] + [deep(p) for p in params]) + '}')
            return add(f'!DISubroutineType(types: {types})', ref)
        raise ValueError(f'unsupported BTF kind {t.kind} reached from a type-info polyfill')

    def add_deep(tid, value):
        deep_emitted[tid] = add(value)
        return deep_emitted[tid]

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
    used = set()
    for name, (d, target) in types.items():
        if d.op == 'local':
            node = deep(target) if d.copy else local(*target)
            ret, intrinsic, args = 'i64', 'llvm.bpf.btf.type.id', lambda: 'i64 0'
        elif d.op == 'id':
            ret, intrinsic, args, node = 'i64', 'llvm.bpf.btf.type.id', lambda: 'i64 1', typ(target)
        elif d.op in TYPE_INFO_OPS:
            flag = TYPE_INFO_OPS[d.op][1]
            ret, intrinsic, args, node = 'i32', 'llvm.bpf.preserve.type.info', lambda: f'i64 {flag}', deep(target)
        else:
            tid, _idx, value = target
            flag = ENUM_OPS[d.op[5:]][1]
            text = f'{d.member}:{value}'
            glob = f'@.core_enum.{len(globals_)}'
            globals_.append(f'{glob} = private unnamed_addr constant [{len(text) + 1} x i8] '
                            f'c"{text}\\00", align 1')
            ret, intrinsic, node = 'i64', 'llvm.bpf.preserve.enum.value', deep(tid)
            args = lambda glob=glob, flag=flag: f'ptr {glob}, i64 {flag}'
        used.add((ret, intrinsic))
        declaration = r'^declare (?:noundef )?' + ret + r' @' + re.escape(name) + r'\(\)[^\n]*\n'
        if len(re.findall(declaration, ir, re.M)) != 1:
            raise ValueError(f'{name}: expected an extern fn() -> {"u32" if ret == "i32" else "u64"}')
        ir = re.sub(declaration, '', ir, flags=re.M)
        pattern = r'((?:tail )?call )(?:noundef )?' + ret + r' @' + re.escape(name) + r'\(\)([^\n]*)'
        count = 0

        def replace(m):
            nonlocal call_id, count
            count += 1
            call_id += 1
            return (f'{m[1]}{ret} @{intrinsic}(i32 {call_id}, {args()}){m[2]}, '
                    f'!llvm.preserve.access.index {node}')

        ir = re.sub(pattern, replace, ir)
        if not count or re.search(r'@' + re.escape(name) + r'\b', ir):
            raise ValueError(f'{name}: missing calls or unsupported use of type-ID polyfill')
    decls = {'llvm.bpf.btf.type.id': 'declare i64 @llvm.bpf.btf.type.id(i32, i64)',
             'llvm.bpf.preserve.type.info': 'declare i32 @llvm.bpf.preserve.type.info(i32, i64)',
             'llvm.bpf.preserve.enum.value': 'declare i64 @llvm.bpf.preserve.enum.value(i32, ptr, i64)'}
    ir += '\n' + '\n'.join(globals_ + [decls[i] for _, i in sorted(used)]) + '\n'
    return ir + '\n'.join(metadata) + '\n'


if __name__ == '__main__':
    path, source, oracle = map(Path, sys.argv[1:])
    original = Path(str(oracle) + '.corig')
    elf = BpfElf(original if original.exists() else oracle)
    btf = Btf(elf.section_by_name('.BTF').data)
    path.write_text(lower(path.read_text(), contract(elf, btf, declarations(source.read_text())), btf))
