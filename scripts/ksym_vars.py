#!/usr/bin/env python3
"""Emit debug declarations for explicitly selected external kernel variables.

Rust emits undefined ELF data symbols without the BTF VAR/.ksyms declarations
libbpf needs. Each `// BTF_KSYM: symbol` selects an existing Rust extern and
mirrors its C object's ksym type and weak linkage before LLVM optimization.
Scalar types retain size/signedness and qualifiers. Named struct/union
descriptors identify kernel types; field accesses still use Rust's CO-RE.
No program instructions or definitions are copied from the C oracle.
"""
import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "equiv"))
from bpfelf import BpfElf
from bpfcore import Btf


def declarations(source):
    names = []
    for line in source.splitlines():
        if not line.startswith("// BTF_KSYM:"):
            continue
        match = re.fullmatch(r"// BTF_KSYM: ([A-Za-z_]\w*)\s*", line)
        if not match or match[1] in names:
            raise ValueError(f"invalid or duplicate ksym declaration: {line}")
        names.append(match[1])
    return names


def contract(elf, names):
    types = elf.btf_types()
    datasecs = [t for t in types.values() if t[0] == 15 and t[1] == ".ksyms"]
    variables = {types[tid][1]: types[tid][2]
                 for sec in datasecs for tid in sec[4] if types[tid][0] == 14}
    result = {}
    for name in names:
        symbols = [s for s in elf.symbols if s.name == name and s.shndx == 0
                   and s.bind in (1, 2)]
        if name not in variables or len(symbols) != 1:
            raise ValueError(f"{name}: C object must declare one undefined .ksyms variable")
        result[name] = (variables[name], symbols[0].bind == 2)
    return result


def lower(ir, names, btf, variables):
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
            value = (f"!DIBasicType(name: {quoted(t.name)}, size: {t.size * 8}, "
                     f"encoding: DW_ATE_{'signed' if t.int_signed else 'unsigned'})")
        elif t.kind in (4, 5):
            if not t.name:
                raise ValueError("anonymous ksym aggregates are unsupported")
            tag = "structure" if t.kind == 4 else "union"
            value = (f"distinct !DICompositeType(tag: DW_TAG_{tag}_type, "
                     f"name: {quoted(t.name)}, file: {file[1]}, "
                     f"size: {t.size * 8}, elements: {empty})")
        elif t.kind in (2, 8, 9, 10, 11):
            tags = {2: "pointer_type", 8: "typedef", 9: "volatile_type",
                    10: "const_type", 11: "restrict_type"}
            extras = ", size: 64" if t.kind == 2 else (
                f", name: {quoted(t.name)}" if t.kind == 8 else "")
            value = f"!DIDerivedType(tag: DW_TAG_{tags[t.kind]}, baseType: {typ(t.type)}{extras})"
        else:
            raise ValueError(f"unsupported ksym BTF kind {t.kind} for {t.name or tid}")
        emitted[tid] = add(value)
        return emitted[tid]

    expressions = []
    for name in names:
        tid, weak = variables[name]
        pattern = r"^@" + re.escape(name) + r" = (external|extern_weak) ([^\n]+)$"
        matches = list(re.finditer(pattern, ir, re.M))
        if len(matches) != 1 or not re.search(r"\b(global|constant)\b", matches[0][2]):
            raise ValueError(f"{name}: expected one undefined Rust data symbol")
        match = matches[0]
        if "!dbg" in match[2] or "section " in match[2]:
            raise ValueError(f"{name}: refusing to overwrite existing section/debug metadata")
        base = btf.resolve(tid)
        if base.kind == 1:
            scalar = re.search(r"\b(?:global|constant) i(\d+)(?:,|$)", match[2])
            if not scalar or int(scalar[1]) != base.size * 8:
                raise ValueError(f"{name}: Rust integer width differs from its C ksym declaration")
        var = add(f"distinct !DIGlobalVariable(name: {quoted(name)}, scope: {cu}, "
                  f"file: {file[1]}, type: {typ(tid)}, isLocal: false, isDefinition: false)")
        expr = add(f"!DIGlobalVariableExpression(var: {var}, expr: !DIExpression())")
        expressions.append(expr)
        declaration = (f"@{name} = {'extern_weak' if weak else 'external'} {match[2]}, "
                       f'section ".ksyms", !dbg {expr}')
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
