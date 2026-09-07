#!/usr/bin/env python3
"""Keep Rust debug signatures while lowering explicitly marked raw BPF bodies.

Rust naked functions lose their LLVM definition/debug signature. Ordinary Rust
functions with noreturn asm retain it, but acquire a synthetic return through
add_ksyms.py. For // BPF_NAKED: name declarations only, require a body consisting
solely of inline asm and a terminator, drop Rust's unused sret parameter, and
restore LLVM's naked/unreachable form. The assembly supplies the complete ABI,
including exits and R0:R2 returns; no generated instructions are discarded.
"""
import re
import sys


def lower(ir, source):
    names = re.findall(r'^// BPF_NAKED: ([A-Za-z_][A-Za-z_0-9]*)\s*$', source, re.M)
    for name in names:
        pattern = r'^define ([^\n]*@' + re.escape(name) + r'\([^\n]*)\{\n(.*?)^}'
        matches = list(re.finditer(pattern, ir, re.M | re.S))
        if len(matches) != 1:
            raise ValueError(f'{name}: expected one LLVM definition')
        match = matches[0]
        header, body = match.groups()
        instructions = [line.strip() for line in body.splitlines()
                        if line.strip() and not line.strip().endswith(':')
                        and not line.lstrip().startswith('#dbg_')]
        if len(instructions) != 2 or 'asm sideeffect' not in instructions[0] or not re.match(r'(ret |unreachable)', instructions[1]):
            raise ValueError(f'{name}: raw body must contain only asm and a terminator: {instructions}')
        # No operand may use the sret pointer. A raw function has no Rust args.
        header = re.sub(r'@' + name + r'\(ptr [^\n]*?sret\([^)]*\)[^\n]*? %\w+\)', '@' + name + '()', header)
        if not re.search(r'@' + name + r'\(\)', header):
            raise ValueError(f'{name}: raw function must have no arguments')
        header = re.sub(r'\s+#\d+', '', header)
        header = re.sub(r'\s+(section|!dbg)', r' naked \1', header, count=1)
        # Remove debug intrinsics referencing the eliminated sret argument.
        body = '\n'.join(line for line in body.splitlines() if not line.lstrip().startswith('#dbg_'))
        body = re.sub(r'^\s*(?:ret [^\n]*|unreachable[^\n]*)$', '  unreachable', body, flags=re.M)
        ir = ir[:match.start()] + 'define ' + header + '{\n' + body + '\n}' + ir[match.end():]
    return ir


if __name__ == '__main__':
    path, source = sys.argv[1:]
    with open(path) as f:
        ir = f.read()
    with open(source) as f:
        result = lower(ir, f.read())
    with open(path, 'w') as f:
        f.write(result)
