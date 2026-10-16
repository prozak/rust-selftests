#!/usr/bin/env python3
"""Lay out a C `private(NAME)` section the way the C object has it.

C's `private(A)` is `SEC(".data.A") __hidden __attribute__((aligned(8)))`
(or `.bss.A`). clang emits the section's variables in the order the code
FIRST REFERS to them, not in declaration order (refcounted_kptr.c declares
lock, root, head and gets head 0, root 16, lock 32; rbtree_fail.c declares
glock, groot, groot2 and gets groot 0, glock 16, groot2 24), each at its
own alignment (aligned(8) through private(), natural for a plain
SEC(".data.X") variable such as test_global_map_resize.c's). rustc emits
statics ordered by symbol name, which for a mangled private static is the
order of the identifiers, at their natural alignment. The verifier names a
lock by its offset in the map ("bpf_spin_lock at off=32 must be held for
bpf_list_head"), so a negative test's expected message only matches with
C's layout, and the proof compares the offsets the programs use.

Given the C object, every `.data.X` / `.bss.X` section the two share is
laid out as the C object has it: the statics whose debug-info name is a C
symbol of that section go first in the order of their C offsets, each with
the smallest alignment that puts it at the C offset after its predecessor
(C's size), the first one with the C section's alignment as well; any
other static follows in source order, 8-aligned. Without
the C object, or for a section it does not have, the statics are ordered
by source line and aligned to at least 8. scripts/translint.py's
private-layout check compares the resulting objects.

Usage: private_sections.py <module.ll> [<c object>]  (a `.corig` backup
of the C object is preferred when present)
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'equiv'))

GLOBAL = re.compile(r'^@(\S+) = (.*?)section "(\.(?:data|bss)\.[^"]+)"(.*?), align (\d+)(.*?!dbg !(\d+).*)$')
PRIVATE_SECTION = re.compile(r'^\.(data|bss)\.[A-Za-z_][A-Za-z0-9_]*$')


def var_of(var_expr, index):
    """(debug-info name, source line) of the global behind a
    DIGlobalVariableExpression reference."""
    m = re.search(r'\bvar: !(\d+)', index.get(var_expr, ''))
    if not m:
        return None, None
    var = index.get(m.group(1), '')
    name = re.search(r'\bname: "([^"]*)"', var)
    line = re.search(r'\bline: (\d+)', var)
    return (name.group(1) if name else None), (int(line.group(1)) if line else None)


class CSection:
    """A C object's `.data.X` / `.bss.X` section: its variables by name ->
    (offset, size), and its alignment (sh_addralign)."""

    def __init__(self, variables, align=0):
        self.variables = variables
        self.align = align


def section_aligns(path):
    """section name -> sh_addralign of a 64-bit little-endian ELF (bpfelf's
    Section does not carry it)."""
    import struct
    with open(path, 'rb') as f:
        buf = f.read()
    e_shoff = struct.unpack_from('<Q', buf, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', buf, 0x3A)
    headers = [struct.unpack_from('<IIQQQQIIQQ', buf, e_shoff + i * e_shentsize)
               for i in range(e_shnum)]
    strtab = headers[e_shstrndx][4]
    out = {}
    for name_off, _type, _flags, _addr, _off, _size, _link, _info, align, _ent in headers:
        end = buf.index(b'\0', strtab + name_off)
        out[buf[strtab + name_off:end].decode()] = align
    return out


def c_layout(path):
    """section name -> CSection for the C object; None when there is no
    such object."""
    if path is None:
        return None
    if os.path.exists(path + '.corig'):
        path = path + '.corig'
    if not os.path.exists(path):
        return None
    from bpfelf import BpfElf
    elf = BpfElf(path)
    aligns = section_aligns(path)
    out = {s.name: CSection({}, aligns.get(s.name, 0)) for s in elf.sections
           if PRIVATE_SECTION.match(s.name)}
    for sym in elf.symbols:
        if sym.type != 1 or sym.shndx >= len(elf.sections):
            continue
        sec = elf.sections[sym.shndx].name
        if sec in out:
            out[sec].variables[sym.name] = (sym.value, sym.size)
    return out


def fitting_align(prev_end, offset, natural):
    """The smallest power of two >= natural that places a global at `offset`
    when the previous one ends at `prev_end` (as LLVM lays a section out)."""
    align = natural
    while align <= 4096:
        if -(-prev_end // align) * align == offset:
            return align
        align *= 2
    return max(natural, offset & -offset) if offset else natural


def layout(ir, c=None):
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
        name, src = var_of(m.group(7), index)
        if src is None:
            continue
        sections.setdefault(m.group(3), []).append((i, src, name, int(m.group(5)), m))

    def rebuilt(m, align):
        return f'@{m.group(1)} = {m.group(2)}section "{m.group(3)}"{m.group(4)}, align {align}{m.group(6)}'

    for section, members in sections.items():
        slots = [i for i, *_ in members]
        csec = (c or {}).get(section)
        if isinstance(csec, dict):  # a bare {name: (offset, size)} is fine too
            csec = CSection(csec)
        want = csec.variables if csec else None
        known = [t for t in members if want and t[2] in want]
        rest = sorted((t for t in members if t not in known), key=lambda t: (t[1], t[0]))
        known.sort(key=lambda t: want[t[2]][0])
        ordered = []
        prev_end = 0
        for i, _src, name, natural, m in known:
            offset, size = want[name]
            # the first variable also carries the section's alignment
            align = (max(natural, csec.align) if offset == 0
                     else fitting_align(prev_end, offset, natural))
            prev_end = offset + size
            ordered.append(rebuilt(m, align))
        for _i, _src, _name, natural, m in rest:
            ordered.append(rebuilt(m, max(natural, 8)))
        for slot, text in zip(slots, ordered):
            lines[slot] = text
    return '\n'.join(lines)


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    with open(sys.argv[1]) as f:
        ir = f.read()
    out = layout(ir, c_layout(sys.argv[2] if len(sys.argv) == 3 else None))
    if out != ir:
        with open(sys.argv[1], 'w') as f:
            f.write(out)


if __name__ == '__main__':
    main()
