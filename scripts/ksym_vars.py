#!/usr/bin/env python3
"""Emit debug declarations for explicitly selected external kernel symbols.

Rust emits undefined ELF data symbols without the BTF VAR/.ksyms declarations
libbpf needs. Each `// BTF_KSYM: symbol` selects an existing Rust extern and
mirrors its C object's ksym type and weak linkage before LLVM optimization.
Scalar types retain size/signedness and qualifiers. Named struct/union
descriptors identify kernel types; field accesses still use Rust's CO-RE.
No program instructions or definitions are copied from the C oracle.

A `// BTF_KSYM:` name may also be a kfunc the C object declares in .ksyms:
its FUNC_PROTO is mirrored the same way (empty named structs for struct
pointees), for the externs whose prototype must be the C declaration's rather
than the running kernel's, which rust-bpf's add_ksyms.py mirrors by exact
name: a `___flavor` of a kfunc (libbpf strips the suffix for the lookup and
then checks the declared prototype against the kernel's, which is what such
a test is about). The declaration is left for add_ksyms.py to skip (it has a
section already), so the Rust extern keeps the C's argument list.

`// BTF_KCONFIG: NAME` selects a `.kconfig` extern the same way (C's
`extern int CONFIG_X __kconfig;`): the C object's `.kconfig` DATASEC VAR
gives the type (libbpf allows int, bool, char, char[] and the libbpf_tristate
enum) and its undefined ELF symbol the weakness, and the Rust extern is
rewritten into section ".kconfig" with the same declaration shape, so llc
emits the VAR with linkage=extern inside `DATASEC '.kconfig'` and libbpf
fills it from the running kernel's config at load time. The value is read
through the symbol, as in C: a declaration without an initializer cannot be
folded, so a plain Rust read is the C load.

`// BTF_EXTERN: NAME` selects a cross-object extern, the C's `extern int
var;`, `extern struct { ... } map SEC(".maps");` or `extern int fn(void);`
that the static linker (bpftool gen object, Makefile.skel's linked
skeletons) resolves against another object's definition. The C object's
extern VAR or FUNC gives the type, in whatever DATASEC the C keeps it (an
extern map sits in `.maps`, a plain variable or function in none), and the
Rust extern is declared the same way; an extern function is put in the
`.extern` section libbpf's linker reserves for such externs, which also
keeps rust-bpf's add_ksyms.py from making it a kfunc. An anonymous
aggregate (a map definition) is mirrored with its members, so the linker
can match the extern map against the definition.
"""
import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "equiv"))
from bpfelf import BpfElf
from bpfcore import Btf


MARKERS = {"// BTF_KSYM:": ".ksyms", "// BTF_KCONFIG:": ".kconfig",
           "// BTF_EXTERN:": "extern"}


def declarations(source):
    """name -> section (".ksyms" or ".kconfig"), in source order."""
    names = {}
    for line in source.splitlines():
        marker = next((m for m in MARKERS if line.startswith(m)), None)
        if marker is None:
            continue
        match = re.fullmatch(re.escape(marker) + r" ([A-Za-z_]\w*)\s*", line)
        if not match or match[1] in names:
            raise ValueError(f"invalid or duplicate ksym declaration: {line}")
        names[match[1]] = MARKERS[marker]
    return names


def sections_of(names):
    """A plain list of names selects `.ksyms` declarations."""
    return names if isinstance(names, dict) else {n: ".ksyms" for n in names}


def contract(elf, names):
    """name -> (BTF type id of the C's declaration, weak, is_function,
    section): the type is the VAR's type or the FUNC's prototype, the
    section the DATASEC the C object keeps the declaration in (None for a
    cross-object extern outside any)."""
    names = sections_of(names)
    types = elf.btf_types()
    result = {}
    for name, section in names.items():
        symbols = [s for s in elf.symbols if s.name == name and s.shndx == 0
                   and s.bind in (1, 2)]
        weak = len(symbols) == 1 and symbols[0].bind == 2
        if section == "extern":
            # The C's cross-object extern: one extern VAR or FUNC of that
            # name, in whatever DATASEC the C object keeps it.
            candidates = [tid for tid, t in types.items()
                          if t[0] in (12, 14) and t[1] == name]
            if len(symbols) != 1 or len(candidates) != 1:
                raise ValueError(f"{name}: C object must declare one undefined "
                                 "extern variable or function")
            tid = candidates[0]
            is_func = types[tid][0] == 12
            if is_func and types[tid][3] != 2:
                raise ValueError(f"{name}: the C object's function is not an extern")
            containing = [t[1] for t in types.values() if t[0] == 15 and tid in t[4]]
            if containing and containing[0] in MARKERS.values():
                raise ValueError(f"{name}: a {containing[0]} extern, select it with "
                                 "the matching marker")
            result[name] = (types[tid][2], weak, is_func,
                            containing[0] if containing else None)
            continue
        datasecs = [t for t in types.values() if t[0] == 15 and t[1] == section]
        variables = {types[tid][1]: types[tid][2]
                     for sec in datasecs for tid in sec[4] if types[tid][0] == 14}
        functions = {types[tid][1]: types[tid][2]
                     for sec in datasecs for tid in sec[4] if types[tid][0] == 12}
        if len(symbols) != 1 or (name not in variables and name not in functions):
            raise ValueError(f"{name}: C object must declare one undefined {section} "
                             "variable or function")
        if name in variables:
            result[name] = (variables[name], weak, False, section)
        else:
            if section != ".ksyms":
                raise ValueError(f"{name}: only .ksyms declarations may be functions")
            result[name] = (functions[name], weak, True, section)
    return result


def lower(ir, names, btf, variables):
    names = sections_of(names)
    if not names:
        return ir
    file = re.search(r"^(!\d+) = !DIFile\(", ir, re.M)
    units = re.search(r"^!llvm.dbg.cu = !\{([^\n]*)\}$", ir, re.M)
    if not file or not units:
        raise ValueError("ksym declarations require debug info and a compile unit")
    metadata = []
    next_id = max(map(int, re.findall(r"!(\d+)", ir)), default=0) + 1

    def reserve():
        nonlocal next_id
        ref = f"!{next_id}"
        next_id += 1
        return ref

    def add(value):
        ref = reserve()
        metadata.append(f"{ref} = {value}")
        return ref

    empty = add("!{}")
    cu = reserve()
    emitted = {0: "null"}

    def quoted(name):
        # LLVM metadata strings use hexadecimal escapes, not JSON escapes.
        return '"' + ''.join(chr(c) if 32 <= c < 127 and c not in (34, 92)
                             else f"\\{c:02X}" for c in name.encode()) + '"'

    def typ(tid):
        if tid in emitted:
            return emitted[tid]
        t = btf.types[tid]
        if t.kind == 1:
            # clang spells the only BTF_INT_BOOL integer `_Bool`; bpfcore
            # does not keep the bool encoding bit (it is the prover's and
            # not to be changed for this), so the name selects it.
            encoding = ("boolean" if t.name == "_Bool"
                        else "signed" if t.int_signed else "unsigned")
            value = (f"!DIBasicType(name: {quoted(t.name)}, size: {t.size * 8}, "
                     f"encoding: DW_ATE_{encoding})")
        elif t.kind == 3:
            elem, count = t.array
            size = btf.type_size(tid)
            if size is None:
                raise ValueError(f"unsizeable array type {tid}")
            subrange = add(f"!DISubrange(count: {count})")
            elements = add("!{" + subrange + "}")
            value = (f"!DICompositeType(tag: DW_TAG_array_type, baseType: {typ(elem)}, "
                     f"size: {size * 8}, elements: {elements})")
        elif t.kind == 6:
            if not t.name:
                raise ValueError("anonymous enum externs are unsupported")
            # BTF ENUM signedness comes from the base type (llc), the
            # enumerators' isUnsigned from the kflag.
            signed = bool(t.kflag)
            base = add(f"!DIBasicType(name: {quoted('int' if signed else 'unsigned int')}, "
                       f"size: {t.size * 8}, encoding: DW_ATE_{'signed' if signed else 'unsigned'})")
            enumerators = [add(f"!DIEnumerator(name: {quoted(n)}, value: {v}"
                               + ("" if signed else ", isUnsigned: true") + ")")
                           for n, v in t.enums]
            elements = add("!{" + ", ".join(enumerators) + "}")
            value = (f"distinct !DICompositeType(tag: DW_TAG_enumeration_type, "
                     f"name: {quoted(t.name)}, file: {file[1]}, baseType: {base}, "
                     f"size: {t.size * 8}, elements: {elements})")
        elif t.kind in (4, 5):
            tag = "structure" if t.kind == 4 else "union"
            if not t.name:
                # The C's anonymous aggregate (a map definition): mirrored
                # with its members, so the linker can match the extern
                # against the definition it resolves it with.
                ref = reserve()
                emitted[tid] = ref
                members = []
                for m in t.members:
                    size = btf.type_size(m.type)
                    if size is None or m.bitfield_size:
                        raise ValueError(f"unsupported member {m.name} of an anonymous extern aggregate")
                    members.append(add(
                        f"!DIDerivedType(tag: DW_TAG_member, name: {quoted(m.name)}, "
                        f"scope: {ref}, file: {file[1]}, baseType: {typ(m.type)}, "
                        f"size: {size * 8}, offset: {m.bit_offset})"))
                elements = add("!{" + ", ".join(members) + "}")
                metadata.append(f"{ref} = distinct !DICompositeType(tag: DW_TAG_{tag}_type, "
                                f"file: {file[1]}, size: {t.size * 8}, elements: {elements})")
                return ref
            value = (f"distinct !DICompositeType(tag: DW_TAG_{tag}_type, "
                     f"name: {quoted(t.name)}, file: {file[1]}, "
                     f"size: {t.size * 8}, elements: {empty})")
        elif t.kind in (2, 8, 9, 10, 11):
            tags = {2: "pointer_type", 8: "typedef", 9: "volatile_type",
                    10: "const_type", 11: "restrict_type"}
            extras = ", size: 64" if t.kind == 2 else (
                f", name: {quoted(t.name)}" if t.kind == 8 else "")
            value = f"!DIDerivedType(tag: DW_TAG_{tags[t.kind]}, baseType: {typ(t.type)}{extras})"
        elif t.kind == 13:
            ret, params = t.proto
            value = ("!DISubroutineType(types: !{" +
                     ", ".join([typ(ret)] + [typ(p) for p in params]) + "})")
        else:
            raise ValueError(f"unsupported ksym BTF kind {t.kind} for {t.name or tid}")
        emitted[tid] = add(value)
        return emitted[tid]

    def lower_function(ir, name, tid, section):
        pattern = r"^declare ([^\n]*?@" + re.escape(name) + r"\([^\n]*)$"
        matches = list(re.finditer(pattern, ir, re.M))
        if len(matches) != 1:
            raise ValueError(f"{name}: expected one Rust function declaration")
        match = matches[0]
        if "!dbg" in match[1] or "section " in match[1]:
            raise ValueError(f"{name}: refusing to overwrite existing section/debug metadata")
        if btf.types[tid].kind != 13:
            raise ValueError(f"{name}: the C declaration is not a function prototype")
        sp = add(f"!DISubprogram(name: {quoted(name)}, scope: {file[1]}, file: {file[1]}, "
                 f"type: {typ(tid)}, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)")
        declaration = f'declare !dbg {sp} {match[1]} section "{section}"'
        return ir[:match.start()] + declaration + ir[match.end():]

    expressions = []
    for name in names:
        tid, weak, is_func, section = variables[name]
        if is_func:
            # libbpf's linker resolves `.extern` functions against other
            # objects' definitions (and add_ksyms.py leaves a declaration
            # with a section alone), `.ksyms` ones are kfuncs.
            ir = lower_function(ir, name, tid, section or ".extern")
            continue
        pattern = r"^@" + re.escape(name) + r" = (external|extern_weak) ([^\n]+)$"
        matches = list(re.finditer(pattern, ir, re.M))
        if len(matches) != 1 or not re.search(r"\b(global|constant)\b", matches[0][2]):
            raise ValueError(f"{name}: expected one undefined Rust data symbol")
        match = matches[0]
        if "!dbg" in match[2] or "section " in match[2]:
            raise ValueError(f"{name}: refusing to overwrite existing section/debug metadata")
        base = btf.resolve(tid)
        if section == ".kconfig" and not (
                base.kind in (1, 6) or
                (base.kind == 3 and btf.resolve(base.array[0]).kind == 1
                 and btf.resolve(base.array[0]).size == 1)):
            raise ValueError(f"{name}: libbpf allows only int, bool, char, char[] and "
                             "libbpf_tristate .kconfig externs")
        if base.kind in (1, 6):
            scalar = re.search(r"\b(?:global|constant) i(\d+)(?:,|$)", match[2])
            if not scalar or int(scalar[1]) != base.size * 8:
                raise ValueError(f"{name}: Rust integer width differs from its C {section} declaration")
        elif base.kind == 3:
            elem = btf.resolve(base.array[0])
            array = re.search(r"\b(?:global|constant) \[(\d+) x i(\d+)\](?:,|$)", match[2])
            if (not array or elem.kind != 1 or int(array[1]) != base.array[1]
                    or int(array[2]) != elem.size * 8):
                raise ValueError(f"{name}: Rust array shape differs from its C {section} declaration")
        var = add(f"distinct !DIGlobalVariable(name: {quoted(name)}, scope: {cu}, "
                  f"file: {file[1]}, type: {typ(tid)}, isLocal: false, isDefinition: false)")
        expr = add(f"!DIGlobalVariableExpression(var: {var}, expr: !DIExpression())")
        expressions.append(expr)
        placement = f'section "{section}", ' if section else ""
        declaration = (f"@{name} = {'extern_weak' if weak else 'external'} {match[2]}, "
                       f"{placement}!dbg {expr}")
        ir = ir[:match.start()] + declaration + ir[match.end():]
    globals_ref = add("!{" + ", ".join(expressions) + "}")
    metadata.append(f"{cu} = distinct !DICompileUnit(language: DW_LANG_C11, file: {file[1]}, "
                    'producer: "rust-selftests ksym_vars", isOptimized: true, runtimeVersion: 0, '
                    f"emissionKind: FullDebug, globals: {globals_ref})")
    ir = re.sub(r"^!llvm.dbg.cu = !\{([^\n]*)\}$",
                lambda m: "!llvm.dbg.cu = !{" + m[1] + ", " + cu + "}", ir, flags=re.M)
    return ir + "\n" + "\n".join(metadata) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ir", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("c_object", type=Path)
    args = parser.parse_args()
    names = declarations(args.source.read_text())
    if not names:
        return
    # A concurrent/previous swap must never make Rust its own ABI oracle.
    original = Path(str(args.c_object) + ".corig")
    elf = BpfElf(original if original.exists() else args.c_object)
    result = lower(args.ir.read_text(), names, Btf(elf.section_by_name(".BTF").data),
                   contract(elf, names))
    args.ir.write_text(result)


if __name__ == "__main__":
    main()
