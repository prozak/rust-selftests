#!/usr/bin/env python3
"""Lay out the maps of an object the way libbpf needs when one map's
`values` slots name other maps.

Two things go wrong for a Rust object, both because a map definition is an
immutable static:

- LLVM places it in a read-only `.maps`, but a map whose slots point at
  other symbols needs relocations and goes to a second, writable section of
  the same name. libbpf reads a single `.maps` section. clang never splits
  them: a C map is a non-const global and all of them are writable.
- rustc emits statics sorted by symbol name, not in source order. libbpf
  creates maps in section order and fills an outer map's slots as soon as
  it is created, so an inner map placed after its outer map is not created
  yet and the slot update fails with -EINVAL.

When any `.maps` definition carries a symbol reference, mark every `.maps`
definition `global` instead of `constant`, as clang does, and move each map
ahead of the maps whose slots name it. Objects without such a map are left
untouched.

Usage: maps_section.py <module.ll>
"""
import re
import sys

MAP_DEF = re.compile(r'^(@(\S+) = (?:[a-z_]+(?:\([a-z_]+\))? )*?)(constant|global) '
                     r'(.*, section "\.maps"(?:,.*)?)$')
REF = re.compile(r'\bptr @([A-Za-z_$.][\w$.]*)')


def unify(ir):
    lines = ir.split('\n')
    where, defs = [], {}
    for i, line in enumerate(lines):
        m = MAP_DEF.match(line)
        if m:
            init = m.group(4).split(', section ".maps"')[0]
            where.append(i)
            defs[m.group(2)] = (m.group(1) + 'global ' + m.group(4), REF.findall(init))
    if not any(refs for _line, refs in defs.values()):
        return ir

    order, seen = [], set()

    def place(name):
        if name in seen:
            return
        seen.add(name)
        for target in defs[name][1]:
            if target in defs:
                place(target)
        order.append(name)

    for name in defs:
        place(name)
    for i, name in zip(where, order):
        lines[i] = defs[name][0]
    return '\n'.join(lines)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        sys.exit(2)
    with open(sys.argv[1]) as f:
        ir = f.read()
    result = unify(ir)
    if result != ir:
        with open(sys.argv[1], 'w') as f:
            f.write(result)
