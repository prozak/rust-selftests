"""A map whose slots name other maps must share one `.maps` section with them
and come after them."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from maps_section import unify

PLAIN = '@inner_map = constant [32 x i8] zeroinitializer, section ".maps", align 8, !dbg !47\n'
OUTER = ('@outer_arr = constant <{ [32 x i8], ptr }> <{ [32 x i8] zeroinitializer, '
         'ptr @inner_map }>, section ".maps", align 8, !dbg !86\n')
OTHER = ('@fmt = internal unnamed_addr constant [4 x i8] c"abc\\00", align 1\n'
         '@lic = constant [4 x i8] c"GPL\\00", section "license", align 1\n'
         '@tbl = constant <{ ptr }> <{ ptr @inner_map }>, section ".rodata", align 8\n')


def test_a_slot_reference_makes_every_map_writable():
    out = unify(PLAIN + OUTER + OTHER)
    assert '@inner_map = global [32 x i8] zeroinitializer, section ".maps"' in out
    assert '@outer_arr = global <{ [32 x i8], ptr }>' in out
    assert out.endswith(OTHER), "definitions outside .maps are untouched"


def test_objects_without_slot_references_are_untouched():
    ir = PLAIN + PLAIN.replace('inner_map', 'hash') + OTHER
    assert unify(ir) == ir


def test_linkage_and_address_attributes_are_kept():
    ir = ('@m = dso_local local_unnamed_addr constant [8 x i8] zeroinitializer, '
          'section ".maps", align 8\n' + OUTER)
    assert ('@m = dso_local local_unnamed_addr global [8 x i8] zeroinitializer, '
            'section ".maps"') in unify(ir)


def test_a_map_named_constant_is_not_confused_with_the_keyword():
    ir = '@constant = constant [8 x i8] zeroinitializer, section ".maps", align 8\n' + OUTER
    assert '@constant = global [8 x i8] zeroinitializer' in unify(ir)


def test_an_already_writable_map_is_left_alone():
    ir = '@m = global [8 x i8] zeroinitializer, section ".maps", align 8\n' + OUTER
    out = unify(ir)
    assert out.count(' global ') == 2 and ' constant ' not in out


def names(ir):
    return [line.split(' ')[0] for line in ir.splitlines() if 'section ".maps"' in line]


def test_an_inner_map_is_moved_ahead_of_the_map_that_names_it():
    ir = (OTHER + OUTER.replace('@inner_map }', '@sockarr }')
          + '@lic2 = constant [4 x i8] c"GPL\00", align 1\n'
          + PLAIN + PLAIN.replace('inner_map', 'sockarr'))
    out = unify(ir)
    assert names(out) == ['@sockarr', '@outer_arr', '@inner_map']
    kept = [l for l in out.splitlines() if 'section ".maps"' not in l]
    assert kept == [l for l in ir.splitlines() if 'section ".maps"' not in l]
    assert out.splitlines().index(ir.splitlines()[4]) == 4, "only .maps lines trade places"


def test_maps_already_in_a_usable_order_keep_it():
    ir = PLAIN.replace('inner_map', 'zeta') + PLAIN + OUTER + PLAIN.replace('inner_map', 'alpha')
    assert names(unify(ir)) == ['@zeta', '@inner_map', '@outer_arr', '@alpha']


def test_a_slot_naming_a_program_does_not_reorder_anything():
    ir = ('@jmp = constant <{ [24 x i8], ptr }> <{ [24 x i8] zeroinitializer, ptr @prog }>, '
          'section ".maps", align 8\n' + PLAIN)
    assert names(unify(ir)) == ['@jmp', '@inner_map']


def test_a_chain_of_references_is_ordered_innermost_first():
    a = OUTER.replace('@outer_arr', '@a').replace('@inner_map }', '@b }')
    b = OUTER.replace('@outer_arr', '@b').replace('@inner_map }', '@c }')
    c = PLAIN.replace('inner_map', 'c')
    assert names(unify(a + b + c)) == ['@c', '@b', '@a']
