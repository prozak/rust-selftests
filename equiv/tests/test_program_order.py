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


@pytest.mark.parametrize('names', ['good good', 'missing bad', 'good', 'helper good bad', 'invalid!'])
def test_invalid_or_incomplete_order_is_rejected(names):
    with pytest.raises(ValueError):
        lower(IR, '// BPF_PROGRAM_ORDER: ' + names)


def test_unselected_objects_are_unchanged():
    assert lower(IR, '') == IR
