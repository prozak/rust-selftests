"""scripts/affected_tests.py narrows a swap's test filter only when the narrowing is certainly complete."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import affected_tests  # noqa: E402

VERIFIER_C = """
#include "verifier_and.skel.h"
#include "verifier_and_more.skel.h"
#include "verifier_xadd.skel.h"

/* a helper taking the skeleton by name: test_verifier_and(void) { RUN(verifier_and); } */
static void run_tests_aux(const char *skel_name, skel_elf_bytes_fn f)
{
	test_loader__run_subtests(&tester, skel_name, f);
}

#define RUN(skel) run_tests_aux(#skel, skel##__elf_bytes)

void test_verifier_and(void)                  { RUN(verifier_and); }
void test_verifier_and_more(void)             { RUN(verifier_and_more); }
void test_verifier_xadd(void)
{
	if (is_jit_enabled())
		RUN(verifier_xadd);
	else
		test__skip();
}
"""

HELPER_OPENS_C = """
#include "fentry_test.skel.h"

static int fentry_test_common(struct fentry_test *fentry_skel)
{
	return fentry_test__attach(fentry_skel);
}

void test_fentry_test(void)
{
	struct fentry_test *skel = fentry_test__open_and_load();
	fentry_test_common(skel);
}

void serial_test_fentry_other(void)
{
	do_other();
}
"""


def test_verifier_file_contributes_only_the_tests_that_name_the_object():
    assert affected_tests.affected_tests("verifier_and", VERIFIER_C) == ["verifier_and"]
    assert affected_tests.affected_tests("verifier_and_more", VERIFIER_C) == ["verifier_and_more"]
    assert affected_tests.affected_tests("verifier_xadd", VERIFIER_C) == ["verifier_xadd"]


def test_a_reference_outside_every_test_body_keeps_the_whole_file():
    # fentry_test__attach in the static helper: the helper may serve any test
    assert affected_tests.affected_tests("fentry_test", HELPER_OPENS_C) == ["fentry_test", "fentry_other"]


def test_no_reference_at_all_keeps_the_whole_file():
    assert affected_tests.affected_tests("verifier_bounds", VERIFIER_C) == [
        "verifier_and", "verifier_and_more", "verifier_xadd"]


def test_a_test_calling_another_test_inherits_its_loads():
    source = """
#include "timer.skel.h"
void test_timer(void)
{
	struct timer *skel = timer__open_and_load();
	timer__destroy(skel);
}

void test_timer_stress(void)
{
	for (int i = 0; i < 10; i++)
		test_timer();
}

void test_timer_other(void)
{
	other();
}
"""
    assert affected_tests.affected_tests("timer", source) == ["timer", "timer_stress"]


def test_a_test_called_from_a_helper_keeps_the_whole_file():
    source = """
void test_timer(void) { timer__open_and_load(); }
static void run_all(void) { test_timer(); }
void test_timer_other(void) { run_all(); }
"""
    assert affected_tests.affected_tests("timer", source) == ["timer", "timer_other"]


def test_macro_defined_tests_are_not_definitions():
    source = """
#define BTF_FAIL_TEST(suffix) \\
void test_rbtree_btf_fail__##suffix(void) \\
{ rbtree_btf_fail__##suffix##__open_and_load(); }
BTF_FAIL_TEST(add_wrong_type);
void test_rbtree_success(void) { rbtree__open_and_load(); }
"""
    # the reference lies outside every registered definition: whole file
    assert affected_tests.affected_tests("rbtree_btf_fail__add_wrong_type", source) == ["rbtree_success"]
    assert affected_tests.affected_tests("rbtree", source) == ["rbtree_success"]


def test_object_file_strings_count_as_references():
    source = """
void test_a(void) { bpf_object__open_file("./test_obj.bpf.o", NULL); }
void test_b(void) { other(); }
"""
    assert affected_tests.affected_tests("test_obj", source) == ["a"]


def test_file_without_test_functions_falls_back_to_its_basename(tmp_path):
    source = tmp_path / "odd.c"
    source.write_text("static void helper(void) { use(verifier_and__open()); }\n")
    out = subprocess.run([sys.executable, str(ROOT / "scripts/affected_tests.py"), "verifier_and",
                          str(source)], check=True, capture_output=True, text=True).stdout
    assert out.split() == ["odd"]


def test_unparsable_bodies_keep_the_whole_file():
    source = "void test_a(void)\n{\n\tRUN(x);\n\nvoid test_b(void) { other(); }\n"  # unbalanced
    assert affected_tests.affected_tests("x", source) == ["a", "b"]


def test_cli_merges_files_in_order_without_duplicates(tmp_path):
    (tmp_path / "verifier.c").write_text(VERIFIER_C)
    (tmp_path / "second.c").write_text("void test_verifier_and(void) { RUN(verifier_and); }\n")
    out = subprocess.run([sys.executable, str(ROOT / "scripts/affected_tests.py"), "verifier_and",
                          str(tmp_path / "verifier.c"), str(tmp_path / "second.c")],
                         check=True, capture_output=True, text=True).stdout
    assert out.split() == ["verifier_and"]


def test_a_linked_half_is_referenced_under_its_skeleton_name():
    source = """
#include "test_usdt.skel.h"
#include "test_urandom_usdt.skel.h"
void test_usdt_basic(void) { test_usdt__open_and_load(); }
void test_usdt_multi(void) { test_usdt__open_and_load(); }
void test_urandom_usdt(void) { test_urandom_usdt__open_and_load(); }
"""
    # the half's own name appears nowhere: the whole file
    assert affected_tests.affected_tests("test_usdt_multispec", source) == [
        "usdt_basic", "usdt_multi", "urandom_usdt"]
    assert affected_tests.affected_tests(["test_usdt_multispec", "test_usdt"], source) == [
        "usdt_basic", "usdt_multi"]


def test_cli_takes_the_skeleton_names_after_commas(tmp_path):
    (tmp_path / "usdt.c").write_text(
        'void test_a(void) { test_usdt__open(); }\nvoid test_b(void) { other(); }\n')
    out = subprocess.run([sys.executable, str(ROOT / "scripts/affected_tests.py"),
                          "test_usdt_multispec,test_usdt", str(tmp_path / "usdt.c")],
                         check=True, capture_output=True, text=True).stdout
    assert out.split() == ["a"]
