"""A private(NAME) section keeps C's declaration order and 8-byte alignment."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from private_sections import layout

GHEAD = '@_R5ghead = internal global [16 x i8] zeroinitializer, section ".data.A", align 8, !dbg !8\n'
GLOCK = '@_R5glock = internal global [4 x i8] zeroinitializer, section ".data.A", align 4, !dbg !21\n'
OTHER = '@zero = global i32 0, section ".bss", align 4, !dbg !30\n'
DI = ('!8 = !DIGlobalVariableExpression(var: !9, expr: !DIExpression())\n'
      '!9 = distinct !DIGlobalVariable(name: "ghead", linkageName: "_R5ghead", line: 59, isLocal: true)\n'
      '!21 = !DIGlobalVariableExpression(var: !22, expr: !DIExpression())\n'
      '!22 = distinct !DIGlobalVariable(name: "glock", linkageName: "_R5glock", line: 54, isLocal: true)\n'
      '!30 = !DIGlobalVariableExpression(var: !31, expr: !DIExpression())\n'
      '!31 = distinct !DIGlobalVariable(name: "zero", line: 10, isLocal: false)\n')


def test_statics_follow_their_source_lines_and_get_aligned_8():
    out = layout(GHEAD + GLOCK + OTHER + DI)
    assert out.startswith('@_R5glock = internal global [4 x i8] zeroinitializer, section ".data.A", align 8, !dbg !21\n'
                          '@_R5ghead = internal global [16 x i8] zeroinitializer, section ".data.A", align 8, !dbg !8\n')
    assert OTHER in out and DI in out


def test_plain_sections_are_untouched():
    ir = OTHER + OTHER.replace('zero', 'one').replace('!30', '!8').replace('!31', '!9') + DI
    assert layout(ir) == ir


def test_a_section_in_source_order_only_gains_alignment():
    ir = GLOCK + GHEAD + DI
    out = layout(ir)
    assert out.index('@_R5glock') < out.index('@_R5ghead')
    assert 'section ".data.A", align 8, !dbg !21' in out
