"""Load-order control moves complete definitions, preserving bodies and debug info."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from program_order import lower

BAD = 'define i32 @bad() section "raw_tp/sys_enter" !dbg !1 {\n  ret i32 -1\n}'
GOOD = 'define i32 @good() section "raw_tp/sys_enter" !dbg !2 {\n  ret i32 0\n}'
HELPER = 'define i32 @helper() {\n  ret i32 3\n}'
IR = BAD + '\n' + HELPER + '\n' + GOOD + '\n!1 = !{}\n!2 = !{}\n'


def test_load_order_changes_without_changing_code_or_debug_metadata():
    result = lower(IR, '// BPF_PROGRAM_ORDER: good bad')
    assert result == GOOD + '\n' + HELPER + '\n' + BAD + '\n!1 = !{}\n!2 = !{}\n'
    assert lower(result, '// BPF_PROGRAM_ORDER: good bad') == result


@pytest.mark.parametrize('names', ['good good', 'missing bad', 'good', 'helper2 good bad', 'invalid!'])
def test_invalid_or_incomplete_order_is_rejected(names):
    with pytest.raises(ValueError):
        lower(IR, '// BPF_PROGRAM_ORDER: ' + names)


HELPER2 = 'define i32 @helper2() {\n  ret i32 4\n}'
IR2 = BAD + '\n' + HELPER + '\n' + GOOD + '\n' + HELPER2 + '\n!1 = !{}\n!2 = !{}\n'


def test_text_subprograms_are_ordered_like_a_section():
    # a function without a section attribute is a .text subprogram: listing
    # one orders the whole of .text, so every .text function must be listed
    result = lower(IR2, '// BPF_PROGRAM_ORDER: helper2 helper')
    assert result == BAD + '\n' + HELPER2 + '\n' + GOOD + '\n' + HELPER + '\n!1 = !{}\n!2 = !{}\n'
    with pytest.raises(ValueError):
        lower(IR2, '// BPF_PROGRAM_ORDER: helper good bad')


def test_unselected_objects_are_unchanged():
    assert lower(IR, '') == IR
