#!/usr/bin/env python3
"""The prog_tests test names that load a given object: the -t filter of one
swap (scripts/swap-and-test.sh).

  scripts/affected_tests.py <object-name>[,<skeleton-name>...] <prog_tests/file.c>...

A consuming file is one whose test object includes the object's skeleton
or names its .bpf.o; swap-and-test.sh finds those. An object linked into a
multi-object skeleton of another name (test_usdt_multispec into test_usdt)
is referenced under that skeleton's name: the further names count as the
object's. The whole file used to
run, which for prog_tests/verifier.c means every verifier test (145 of
them, 3000 subtests, about 45 seconds) for a swap only test_verifier_<name>
can observe. This script narrows the set to the test functions that
reference the object, and only when that is certainly complete:

  - a test function is a top-level `void test_<name>(void)` or
    `void serial_test_<name>(void)`; its body is found by brace matching
    with strings, character literals and comments skipped;
  - a reference is the object's identifier as a whole token or followed by
    `__` (the skeleton API: `x__open_and_load`, `x__elf_bytes`,
    `RUN_TESTS(x)`), or the string "<path/>x.bpf.o"; `verifier_bounds` does
    not match `verifier_bounds_deduction`;
  - a test function that calls another test function of the file (timer.c's
    stress tests call test_timer, bpf_iter.c's test_bpf_iter runs the
    others as subtests) inherits its references, transitively;
  - when every reference in the file lies inside test bodies, those tests
    are the file's contribution; when any lies outside (a static helper
    that opens the skeleton for several tests, a file-scope table, a test
    function called from a helper) or the file has no test function, the
    file contributes every test it defines, or its basename when it
    defines none: exactly what ran before.

One name per output line, in first-seen order, without duplicates. The
script is part of the gate environment hash (scripts/qemu_gate.py
ENV_FILES): a change here re-gates every translation.
"""
import os
import re
import sys

# What the selftests Makefile registers (gen_tests_hdr: sed -n -E
# 's/^void (serial_)?test_([a-zA-Z0-9_]+)\((void)?\).*/DEFINE_TEST(\2)/p'):
# the registered name is the function name without its prefix. A test
# defined through a macro (rbtree.c's BTF_FAIL_TEST) is not a definition
# here either, so a reference inside it keeps the whole file.
TEST_DEF = re.compile(r"^void (?:serial_)?test_([a-zA-Z0-9_]+)\((?:void)?\)", re.M)


def blank_noncode(text):
    """The same text with comments, string and character literals replaced
    by spaces (newlines kept), so braces and identifiers inside them do not
    count."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(c + " " * (j - i - 2) + c if j - i >= 2 else " " * (j - i))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def test_bodies(code):
    """[(test name, start, end)] over the blanked text: each top-level test
    function definition with its brace-matched body."""
    bodies = []
    for m in TEST_DEF.finditer(code):
        open_brace = code.find("{", m.end())
        if open_brace < 0 or code[m.end():open_brace].strip():
            return None  # a prototype, or something unexpected before the body
        depth, j = 0, open_brace
        while j < len(code):
            if code[j] == "{":
                depth += 1
            elif code[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if depth:
            return None  # unbalanced: do not trust this file
        bodies.append((m.group(1), m.start(), j + 1))
    return bodies


def reference_pattern(names):
    ident = "|".join(re.escape(n) for n in names)
    return re.compile(rf"(?<![A-Za-z0-9_])(?:{ident})(?![A-Za-z0-9]|_(?!_))")


def affected_tests(names, text):
    """The test names of one prog_tests source that a swap of `names` (an
    object name, or that and the skeleton names it is linked under) can
    affect, by the rules in the module docstring."""
    if isinstance(names, str):
        names = [names]
    code = blank_noncode(text)
    every = []
    for m in TEST_DEF.finditer(code):
        if m.group(1) not in every:
            every.append(m.group(1))
    if not every:
        return []
    bodies = test_bodies(code)
    if not bodies:
        return every
    references = [m.start() for m in reference_pattern(names).finditer(code)]
    # the .bpf.o path is a string literal, blanked above: look in the source
    objects = "|".join(re.escape(n) for n in names)
    references += [m.start() for m in re.finditer(r'"[^"]*(?:' + objects + r')\.bpf\.o"', text)]
    if not references:
        return every

    def owner(position):
        for test, start, end in bodies:
            if start <= position < end:
                return test
        return None

    hit = []
    for position in references:
        test = owner(position)
        if test is None:
            return every  # a reference outside every test body
        if test not in hit:
            hit.append(test)
    # calls between test functions: the caller runs the callee's loads
    callers = {}
    for m in re.finditer(r"(?<![A-Za-z0-9_])(?:serial_)?test_([A-Za-z0-9_]+)\s*\(", code):
        callee = m.group(1)
        if callee not in every or code.startswith("void", m.start() - 5, m.start()) \
                or re.match(r"void\s+$", code[max(0, m.start() - 8):m.start()]):
            continue
        caller = owner(m.start())
        if caller is None:
            return every  # a test function called from a helper
        if caller != callee:
            callers.setdefault(callee, []).append(caller)
    queue = list(hit)
    while queue:
        for caller in callers.get(queue.pop(), []):
            if caller not in hit:
                hit.append(caller)
                queue.append(caller)
    return [t for t in every if t in hit]


def main(argv):
    if len(argv) < 3:
        sys.exit("usage: affected_tests.py <object-name>[,<skeleton-name>...] "
                 "<prog_tests/file.c>...")
    names, files = [n for n in argv[1].split(",") if n], argv[2:]
    out = []
    for path in files:
        try:
            with open(path, errors="replace") as f:
                tests = affected_tests(names, f.read())
        except OSError:
            tests = []
        for t in tests or [os.path.splitext(os.path.basename(path))[0]]:
            if t not in out:
                out.append(t)
    print("\n".join(out))


if __name__ == "__main__":
    main(sys.argv)
