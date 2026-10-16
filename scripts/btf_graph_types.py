#!/usr/bin/env python3
"""Keep one BTF definition of each graph type the kernel looks up by name.

rust-bpf's add_ksyms.py gives every kfunc prototype parameter the kernel's
type as a fresh debug-info node: a struct it describes by name alone, as an
empty definition (not a forward declaration, which libbpf would not match
against the kernel's struct). llc emits that node as its own STRUCT, so an
object that also defines the struct itself carries two BTF structs of the
same name, the stub first when the first program calls the kfunc before
the real type is reached.

The kernel resolves a few struct names by their FIRST definition
(kernel/bpf/btf.c, alloc_obj_fields): bpf_spin_lock, bpf_list_head,
bpf_list_node, bpf_rb_root, bpf_rb_node, bpf_refcount. Its struct-meta
pass only parses a local type whose member is of those ids, so a node
type such as `struct node_data { struct bpf_list_node l; ... }` loses
its record when the stub comes first, and creating a map that holds the
list head fails with -EFAULT (btf_check_and_fixup_fields finds no meta).

For those names, when the module defines the struct in full, repoint every
use of a stub at that definition and drop the stub. Other kernel types
keep their stubs: the kernel never parses their metadata from program
BTF, and the object's own view types are partial on purpose.

Usage: btf_graph_types.py <module.ll>
"""
import re
import sys

GRAPH_TYPES = ("bpf_spin_lock", "bpf_list_head", "bpf_list_node",
               "bpf_rb_root", "bpf_rb_node", "bpf_refcount")
COMPOSITE = re.compile(r'^!(\d+) = (?:distinct )?!DICompositeType\((.*)\)$')


def dedup(ir):
    lines = ir.split('\n')
    empty = {m.group(1) for m in (re.match(r'^!(\d+) = !\{\}$', l) for l in lines) if m}
    full, stubs = {}, {}
    for i, line in enumerate(lines):
        m = COMPOSITE.match(line)
        if not m:
            continue
        body = m.group(2)
        name = re.search(r'\bname: "([^"]*)"', body)
        if not name or name.group(1) not in GRAPH_TYPES:
            continue
        if 'tag: DW_TAG_structure_type' not in body and 'tag: DW_TAG_union_type' not in body:
            continue
        elements = re.search(r'\belements: !(\d+|\{\})', body)
        size = re.search(r'\bsize: (\d+)', body)
        if (size is None or size.group(1) == '0') and 'identifier:' not in body \
                and (elements is None or elements.group(1) == '{}' or elements.group(1) in empty) \
                and 'DIFlagFwdDecl' not in body:
            stubs.setdefault(name.group(1), []).append((i, m.group(1)))
        elif size and size.group(1) != '0' and elements and elements.group(1) not in empty \
                and 'DIFlagFwdDecl' not in body:
            full.setdefault(name.group(1), (i, m.group(1)))
    drop = set()
    renames = {}
    for name, stub_list in stubs.items():
        if name not in full:
            continue
        for i, sid in stub_list:
            drop.add(i)
            renames[sid] = full[name][1]
    if not renames:
        return ir
    pattern = re.compile(r'!(' + '|'.join(sorted(renames, key=len, reverse=True)) + r')(?!\d)')
    out = []
    for i, line in enumerate(lines):
        if i in drop:
            continue
        out.append(pattern.sub(lambda m: '!' + renames[m.group(1)], line))
    return '\n'.join(out)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(sys.argv[1]) as f:
        ir = f.read()
    out = dedup(ir)
    if out != ir:
        with open(sys.argv[1], 'w') as f:
            f.write(out)


if __name__ == '__main__':
    main()
