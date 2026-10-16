"""A kfunc prototype's empty stub of a graph type the module defines in full
must not reach BTF as a second struct of that name."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from btf_graph_types import dedup

FULL = ('!33 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_list_node", '
        'scope: !2, file: !11, size: 192, align: 64, flags: DIFlagPrivate, elements: !34, '
        'templateParams: !18, identifier: "37a306aa69c31036e58b55523be74982")\n'
        '!34 = !{!35}\n'
        '!18 = !{}\n')
STUB = '!2348 = !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_list_node", file: !3, elements: !18)\n'
USE = ('!2347 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !2348, size: 64)\n'
       '!23480 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)\n')


def test_the_stub_is_dropped_and_its_uses_repointed():
    out = dedup(FULL + STUB + USE)
    assert STUB not in out
    assert 'baseType: !33, size: 64)\n!23480 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33' in out
    assert FULL in out


def test_a_stub_without_a_full_definition_stays():
    ir = STUB + USE.replace('!33', '!2348')
    assert dedup(ir) == ir


def test_other_kernel_types_keep_their_stubs():
    ir = (FULL + STUB + USE).replace('bpf_list_node', 'task_struct')
    assert dedup(ir) == ir


def test_a_forward_declaration_is_not_a_stub():
    fwd = '!2348 = !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_list_node", file: !3, flags: DIFlagFwdDecl)\n'
    ir = FULL + fwd + USE
    assert dedup(ir) == ir
