#!/usr/bin/env python3
"""Lay out a C `private(NAME)` section the way clang does.

C's `private(A)` is `SEC(".data.A") __hidden __attribute__((aligned(8)))`
(or `.bss.A`); its variables sit in the section in declaration order, each
8-byte aligned. rustc emits statics ordered by symbol name, which for a
mangled private static is the order of the identifiers, and keeps each
static's natural alignment. The verifier names a lock by its offset in the
map ("bpf_spin_lock at off=16 must be held for bpf_list_head"), so a
negative test's expected message only matches with C's layout, and the
proof compares the offsets the programs use.

For every `.data.X` / `.bss.X` section: order its statics by the source
line of their debug info and raise an alignment below 8 to 8. Nothing
else moves.

Usage: private_sections.py <module.ll>
"""
import re
import sys

GLOBAL = re.compile(r'^@(\S+) = (.*?)section "(\.(?:data|bss)\.[^"]+)"(.*?), align (\d+)(.*?!dbg !(\d+).*)$')


def line_of(var_expr, index):
    m = re.search(r'\bvar: !(\d+)', index.get(var_expr, ''))
    if not m:
        return None
    m = re.search(r'\bline: (\d+)', index.get(m.group(1), ''))
    return int(m.group(1)) if m else None


def layout(ir):
    lines = ir.split('\n')
    index = {}
    for line in lines:
        m = re.match(r'^!(\d+) = (.*)$', line)
        if m:
            index[m.group(1)] = m.group(2)
    sections = {}
    for i, line in enumerate(lines):
        m = GLOBAL.match(line)
        if not m:
            continue
        src = line_of(m.group(7), index)
        if src is None:
            continue
        align = max(int(m.group(5)), 8)
        rebuilt = f'@{m.group(1)} = {m.group(2)}section "{m.group(3)}"{m.group(4)}, align {align}{m.group(6)}'
        sections.setdefault(m.group(3), []).append((i, src, rebuilt))
    for members in sections.values():
        slots = [i for i, _, _ in members]
        ordered = sorted(members, key=lambda t: (t[1], t[0]))
        for slot, (_, _, text) in zip(slots, ordered):
            lines[slot] = text
    return '\n'.join(lines)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(sys.argv[1]) as f:
        ir = f.read()
    out = layout(ir)
    if out != ir:
        with open(sys.argv[1], 'w') as f:
            f.write(out)


if __name__ == '__main__':
    main()
