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


COUNTER = '@counter = local_unnamed_addr global [4 x i8] c"\\05\\00\\00\\00", align 4, !dbg !60\n'
PX = '@px = local_unnamed_addr global ptr @x, align 8, !dbg !62\n'
X = '@x = global [4 x i8] c"*\\00\\00\\00", align 4, !dbg !64\n'
SUM = '@sum = local_unnamed_addr global [8 x i8] zeroinitializer, align 8, !dbg !66\n'
DI2 = ('!60 = !DIGlobalVariableExpression(var: !61, expr: !DIExpression())\n'
       '!61 = distinct !DIGlobalVariable(name: "counter", line: 30, isLocal: false)\n'
       '!62 = !DIGlobalVariableExpression(var: !63, expr: !DIExpression())\n'
       '!63 = distinct !DIGlobalVariable(name: "px", line: 40, isLocal: false)\n'
       '!64 = !DIGlobalVariableExpression(var: !65, expr: !DIExpression())\n'
       '!65 = distinct !DIGlobalVariable(name: "x", line: 34, isLocal: false)\n'
       '!66 = !DIGlobalVariableExpression(var: !67, expr: !DIExpression())\n'
       '!67 = distinct !DIGlobalVariable(name: "sum", line: 36, isLocal: false)\n')


def test_plain_sections_are_laid_out_only_when_asked():
    ir = PX + COUNTER + X + SUM + DI2
    assert layout(ir, {'.data': {'counter': (0, 4), 'x': (8, 4), 'px': (16, 8)}}) == ir
    # data_in_arena: rustc's name order ends .data at 44 bytes, clang's
    # declaration order at 48; the statics get the section attribute
    c = {'.data': CSection({'counter': (0, 4), 'x': (8, 4), 'px': (16, 8)}, 8)}
    out = layout(ir, c, ('.data',))
    assert out.index('@counter') < out.index('@x') < out.index('@px')
    assert '@counter = local_unnamed_addr global [4 x i8] c"\\05\\00\\00\\00", section ".data", align 8, !dbg !60' in out
    assert 'section ".data", align 8, !dbg !64' in out  # 8 after 0+4
    assert 'section ".data", align 8, !dbg !62' in out
    assert SUM in out                                    # .bss was not asked for


def test_a_zero_initialized_global_is_bss():
    c = {'.bss': CSection({'sum': (0, 8)}, 8)}
    out = layout(PX + SUM + DI2, c, ('.bss',))
    assert 'zeroinitializer, section ".bss", align 8, !dbg !66' in out
    assert PX in out
