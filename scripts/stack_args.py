#!/usr/bin/env python3
"""Refuse an object whose IR and BTF disagree on who takes stack arguments.

Since LLVM 23 a function's sixth and later IR parameters travel on the
stack (r11), and the verifier sizes the callee's incoming stack-argument
area from its BTF prototype, which the BPF backend takes from the debug
signature. rustc's argument promotion can turn a reference parameter into
several scalars without touching the debug signature (test_xdp_noinline's
encap_v4: `pckt: &PacketDescription` became two loaded fields, six IR
parameters against five in BTF), and the verifier then rejects the callee's
`r11 + 8` read. Fail the build on that mismatch, at the object that has it.
"""
import re
import sys


def split_params(plist):
    """Split an IR parameter list on the commas at nesting depth zero."""
    out, depth, start = [], 0, 0
    for i, ch in enumerate(plist):
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        elif ch == ',' and depth == 0:
            out.append(plist[start:i])
            start = i + 1
    out.append(plist[start:])
    return out


def check(ir):
    subprograms = {}
    for m in re.finditer(r'^!(\d+) = distinct !DISubprogram\((.*)$', ir, re.M):
        name = re.search(r'name: "([^"]+)"', m.group(2))
        ty = re.search(r'\btype: !(\d+)', m.group(2))
        if name and ty:
            subprograms[m.group(1)] = (name.group(1), ty.group(1))
    routine_types = dict(re.findall(r'^!(\d+) = !DISubroutineType\((?:[^)]*?)types: !(\d+)\)', ir, re.M))
    arrays = dict(re.findall(r'^!(\d+) = !\{(.*)\}$', ir, re.M))
    bad = []
    for m in re.finditer(r'^define [^@\n]*@[\w.$]+\(', ir, re.M):
        # the parameter list, with balanced parentheses (captures(address),
        # sret([16 x i8]) ...), then the rest of the header up to the body
        depth, i = 1, m.end()
        while depth:
            depth += {'(': 1, ')': -1}.get(ir[i], 0)
            i += 1
        plist = ir[m.end():i - 1]
        header = ir[i:ir.index('{', i)]
        dbg = re.search(r'!dbg !(\d+)', header)
        params = [p for p in split_params(plist) if p.strip()]
        if len(params) <= 5 or not dbg or dbg.group(1) not in subprograms:
            continue
        source_name, ty = subprograms[dbg.group(1)]
        types = arrays.get(routine_types.get(ty, ''))
        if types is None:
            continue
        # the first element is the return type
        di_params = len([t for t in types.split(',') if t.strip()]) - 1
        if di_params != len(params):
            bad.append((source_name, len(params), di_params))
    return bad


if __name__ == '__main__':
    path = sys.argv[1]
    with open(path) as f:
        bad = check(f.read())
    for name, ir_n, di_n in bad:
        print(f"[stack_args] ERROR: {name}: {ir_n} IR parameter(s) but {di_n} in the "
              f"debug signature; the {ir_n - 5} stack argument(s) have no BTF", file=sys.stderr)
    sys.exit(1 if bad else 0)
