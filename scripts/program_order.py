#!/usr/bin/env python3
"""Preserve explicitly declared load order without changing function bodies."""
from pathlib import Path
import re
import sys


def lower(ir, source):
    lines = [line for line in source.splitlines() if line.startswith('// BPF_PROGRAM_ORDER:')]
    if not lines:
        return ir
    if len(lines) != 1:
        raise ValueError('expected one BPF_PROGRAM_ORDER declaration')
    names = lines[0].removeprefix('// BPF_PROGRAM_ORDER:').split()
    if not names or len(set(names)) != len(names):
        raise ValueError('program order must contain unique names')
    functions = list(re.finditer(r'^define [^\n]*\{\n.*?^}', ir, re.M | re.S))
    selected = {}
    sections = set()
    for name in names:
        if not re.fullmatch(r'[A-Za-z_]\w*', name):
            raise ValueError('invalid program name')
        matches = [m for m in functions if re.search(r'@' + name + r'\(', m[0].splitlines()[0])]
        if len(matches) != 1:
            raise ValueError(f'{name}: expected one function definition')
        selected[name] = matches[0]
        section = re.search(r'section "([^"]+)"', matches[0][0].splitlines()[0])
        if not section:
            raise ValueError(f'{name}: expected a program section')
        sections.add(section[1])
    # Require the whole section, so an omitted program cannot interleave.
    for m in functions:
        section = re.search(r'section "([^"]+)"', m[0].splitlines()[0])
        if section and section[1] in sections and m not in selected.values():
            raise ValueError('program order omits a function in the selected section')
    positions = sorted(selected.values(), key=lambda m: m.start())
    for position, name in reversed(list(zip(positions, names))):
        ir = ir[:position.start()] + selected[name][0] + ir[position.end():]
    return ir


if __name__ == '__main__':
    path, source = map(Path, sys.argv[1:])
    path.write_text(lower(path.read_text(), source.read_text()))
