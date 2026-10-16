"""A private(NAME) section is laid out as the C object has it; without the
C object it keeps source order and 8-byte alignment."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from private_sections import CSection, fitting_align, layout

GHEAD = '@_R5ghead = internal global [16 x i8] zeroinitializer, section ".data.A", align 8, !dbg !8\n'
GLOCK = '@_R5glock = internal global [4 x i8] zeroinitializer, section ".data.A", align 4, !dbg !21\n'
GROOT2 = '@_R6groot2 = internal global [16 x i8] zeroinitializer, section ".data.A", align 8, !dbg !40\n'
OTHER = '@zero = global i32 0, section ".bss", align 4, !dbg !30\n'
DI = ('!8 = !DIGlobalVariableExpression(var: !9, expr: !DIExpression())\n'
      '!9 = distinct !DIGlobalVariable(name: "ghead", linkageName: "_R5ghead", line: 59, isLocal: true)\n'
      '!21 = !DIGlobalVariableExpression(var: !22, expr: !DIExpression())\n'
      '!22 = distinct !DIGlobalVariable(name: "glock", linkageName: "_R5glock", line: 54, isLocal: true)\n'
      '!30 = !DIGlobalVariableExpression(var: !31, expr: !DIExpression())\n'
      '!31 = distinct !DIGlobalVariable(name: "zero", line: 10, isLocal: false)\n'
      '!40 = !DIGlobalVariableExpression(var: !41, expr: !DIExpression())\n'
      '!41 = distinct !DIGlobalVariable(name: "groot2", linkageName: "_R6groot2", line: 60, isLocal: true)\n'
      '!50 = !DIGlobalVariableExpression(var: !51, expr: !DIExpression())\n'
      '!51 = distinct !DIGlobalVariable(name: "lock2", linkageName: "_R5lock2", line: 55, isLocal: true)\n')
LOCK2 = '@_R5lock2 = internal global [4 x i8] zeroinitializer, section ".data.A", align 4, !dbg !50\n'


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


def test_the_c_objects_layout_wins_over_source_order():
    # rbtree_fail.c: declared glock, groot, groot2; clang: groot 0, glock 16, groot2 24
    c = {'.data.A': {'ghead': (0, 16), 'glock': (16, 4), 'groot2': (24, 16)}}
    out = layout(GLOCK + GHEAD + GROOT2 + DI, c)
    assert out.index('@_R5ghead') < out.index('@_R5glock') < out.index('@_R6groot2')
    assert 'section ".data.A", align 8, !dbg !8' in out    # offset 0: natural
    assert 'section ".data.A", align 4, !dbg !21' in out   # 16 after 0+16: natural fits
    assert 'section ".data.A", align 8, !dbg !40' in out   # 24 after 16+4: 8 rounds 20 up to 24


def test_c_alignment_gaps_are_reproduced_and_plain_sections_keep_natural():
    # two aligned(8) locks: lock2 must sit at 8 although 4 would do, and the
    # first one carries the C section's alignment
    c = {'.data.A': CSection({'glock': (0, 4), 'lock2': (8, 4)}, 8)}
    out = layout(GLOCK + LOCK2 + DI, c)
    assert 'align 8, !dbg !21' in out and 'align 8, !dbg !50' in out
    # test_global_map_resize.c: plain SEC(".data.X") ints at 0 and 4
    c = {'.data.A': CSection({'lock2': (0, 4), 'glock': (4, 4)}, 4)}
    out = layout(GLOCK + LOCK2 + DI, c)
    assert out.index('@_R5lock2') < out.index('@_R5glock')
    assert 'align 4, !dbg !50' in out and 'align 4, !dbg !21' in out


def test_statics_the_c_object_lacks_follow_in_source_order():
    c = {'.data.A': {'glock': (0, 4)}}
    out = layout(GHEAD + GROOT2 + GLOCK + DI, c)
    assert out.index('@_R5glock') < out.index('@_R5ghead') < out.index('@_R6groot2')
    assert 'align 8, !dbg !8' in out and 'align 8, !dbg !40' in out


def test_a_section_unknown_to_the_c_object_keeps_the_fallback():
    out = layout(GHEAD + GLOCK + DI, {'.data.B': {'x': (0, 4)}})
    assert out.index('@_R5glock') < out.index('@_R5ghead')
    assert 'align 8, !dbg !21' in out


def test_fitting_align():
    assert fitting_align(16, 16, 4) == 4
    assert fitting_align(20, 24, 8) == 8
    assert fitting_align(4, 8, 4) == 8
    assert fitting_align(4, 4, 4) == 4
    assert fitting_align(12, 16, 4) == 8
