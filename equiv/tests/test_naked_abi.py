"""Raw BPF lowering must preserve signatures and reject generated code."""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from naked_abi import lower


def test_pair_return_keeps_debug_signature_and_raw_instructions():
    ir = '''define void @pair(ptr noalias sret([16 x i8]) align 16 %_0) #0 !dbg !12 {
start:
  call void asm sideeffect "r0 = 1; r2 = 2; exit;", ""()
  ret void
}
!12 = distinct !DISubprogram(name: "pair", type: !13)
!13 = !DISubroutineType(types: !14)
!14 = !{!15}
!15 = !DIBasicType(name: "u128", size: 128, encoding: DW_ATE_unsigned)
'''
    out = lower(ir, '// BPF_NAKED: pair\n')
    assert 'define void @pair() naked !dbg !12' in out
    assert 'r0 = 1; r2 = 2; exit;' in out
    assert 'sret(' not in out
    assert 'ret void' not in out
    assert 'unreachable' in out
    assert out[out.index('!12 ='):] == ir[ir.index('!12 ='):]


def test_section_and_unmarked_function_survive():
    ir = '''define i32 @entry() #0 section "tc" !dbg !1 {
start:
  call void asm sideeffect "r0 = 0; exit;", ""()
  ret i32 0
}
define i32 @normal() { ret i32 7 }
'''
    out = lower(ir, '// BPF_NAKED: entry\n')
    assert 'naked section "tc" !dbg !1' in out
    assert 'define i32 @normal() { ret i32 7 }' in out
    assert lower(ir, '') == ir


@pytest.mark.parametrize('extra', ['  store i64 1, ptr %p\n', '  %x = add i32 1, 2\n'])
def test_generated_instructions_are_never_discarded(extra):
    ir = 'define i32 @p() !dbg !1 {\n  call void asm sideeffect "exit;", ""()\n' + extra + '  ret i32 0\n}\n'
    with pytest.raises(ValueError, match='only asm'):
        lower(ir, '// BPF_NAKED: p\n')


def test_missing_definition_and_real_arguments_are_rejected():
    with pytest.raises(ValueError, match='one LLVM definition'):
        lower('', '// BPF_NAKED: p\n')
    ir = 'define i32 @p(i64 %a) !dbg !1 {\n  call void asm sideeffect "exit;", ""()\n  ret i32 0\n}\n'
    with pytest.raises(ValueError, match='no arguments'):
        lower(ir, '// BPF_NAKED: p\n')
