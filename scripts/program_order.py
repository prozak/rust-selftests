#!/usr/bin/env python3
"""Preserve explicitly declared load order without changing function bodies.

A function without a section attribute is a .text subprogram; listing one
orders the whole of .text, as listing a program orders its section.
"""
from pathlib import Path
import re
import sys


def section_of(match):
    """The ELF section a definition lands in: its section attribute, else
    .text (a subprogram)."""
    section = re.search(r'section "([^"]+)"', match[0].splitlines()[0])
    return section[1] if section else '.text'


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
        sections.add(section_of(matches[0]))
    # Require the whole section, so an omitted program cannot interleave.
    for m in functions:
        if section_of(m) in sections and m not in selected.values():
            raise ValueError('program order omits a function in the selected section')
    positions = sorted(selected.values(), key=lambda m: m.start())
    for position, name in reversed(list(zip(positions, names))):
        ir = ir[:position.start()] + selected[name][0] + ir[position.end():]
    return ir


if __name__ == '__main__':
    path, source = map(Path, sys.argv[1:])
    path.write_text(lower(path.read_text(), source.read_text()))
