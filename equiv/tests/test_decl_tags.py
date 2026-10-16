"""Hermetic tests for translint's decl-tags class: the C object's
`contains:` / `exception_callback:` / `arg:*` decl tags must sit on the same
declaration in the Rust object (rust-bpf's #[btf_tag] emits them).

No kernel, no build tree: both objects are synthesized here and read back
with the prover's own ELF reader.
"""
import os
import struct
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import translint  # noqa: E402


class Btf:
    """Accumulates BTF types; ids start at 1 in the order they are added."""

    def __init__(self):
        self.types, self.strings, self.n = b"", b"\0", 0

    def s(self, text):
        off = len(self.strings)
        self.strings += text.encode() + b"\0"
        return off

    def add(self, raw):
        self.types += raw
        self.n += 1
        return self.n

    def int(self, name):
        return self.add(struct.pack("<IIII", self.s(name), 1 << 24, 4, 32))

    def struct(self, name, members, int_id):
        raw = struct.pack("<III", self.s(name), (4 << 24) | len(members),
                          4 * len(members))
        for i, m in enumerate(members):
            raw += struct.pack("<III", self.s(m), int_id, 32 * i)
        return self.add(raw)

    def var(self, name, type_id):
        return self.add(struct.pack("<IIII", self.s(name), 14 << 24,
                                    type_id, 1))

    def func(self, name, nparams, int_id):
        proto = struct.pack("<III", 0, (13 << 24) | nparams, int_id)
        for i in range(nparams):
            proto += struct.pack("<II", self.s(f"a{i}"), int_id)
        proto_id = self.add(proto)
        return self.add(struct.pack("<III", self.s(name), (12 << 24) | 1,
                                    proto_id))

    def decl_tag(self, payload, target, comp=-1):
        return self.add(struct.pack("<IIIi", self.s(payload), 17 << 24,
                                    target, comp))

    def write(self, path):
        btf = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(self.types),
                          len(self.types), len(self.strings))
        btf += self.types + self.strings
        shstr = b"\0.BTF\0.shstrtab\0"
        shoff = 64 + len(btf) + len(shstr)
        out = bytearray(b"\x7fELF\x02\x01\x01" + b"\0" * 9)
        out += struct.pack("<HHI", 1, 247, 1)                # ET_REL, EM_BPF
        out += struct.pack("<QQQ", 0, 0, shoff)
        out += struct.pack("<IHHHHHH", 0, 64, 0, 0, 64, 3, 2)
        out += btf + shstr

        def shdr(name_off, typ, off, size, align):
            return struct.pack("<IIQQQQIIQQ", name_off, typ, 0, 0, off, size,
                               0, 0, align, 0)

        out += shdr(0, 0, 0, 0, 0)
        out += shdr(1, 1, 64, len(btf), 4)                   # .BTF
        out += shdr(6, 3, 64 + len(btf), len(shstr), 1)      # .shstrtab
        open(path, "wb").write(bytes(out))


def rbtree_object(path, *, root_tag=None, member_tag=None, cb_tag=None,
                  arg_tag=None, member_idx=1):
    """A C-shaped object: global `groot`, map value `map_value {a, head}`,
    program `prog`, global subprog `sub(a0, a1)`; each tag optional."""
    b = Btf()
    i = b.int("int")
    sv = b.struct("map_value", ["a", "head"], i)
    groot = b.var("groot", i)
    prog = b.func("prog", 1, i)
    sub = b.func("sub", 2, i)
    b.decl_tag("comment:0:test_expect_failure", prog)   # test-tags' business
    if root_tag:
        b.decl_tag(root_tag, groot)
    if member_tag:
        b.decl_tag(member_tag, sv, member_idx)
    if cb_tag:
        b.decl_tag(cb_tag, prog)
    if arg_tag:
        b.decl_tag(arg_tag, sub, 1)
    b.write(path)


ALL = dict(root_tag="contains:node_data:node",
           member_tag="contains:foo:list",
           cb_tag="exception_callback:exception_cb",
           arg_tag="arg:ctx")


@pytest.fixture
def lint_env(tmp_path, monkeypatch):
    """Point translint at a scratch C output dir and a scratch repo bld/."""
    c_dir, repo = tmp_path / "c", tmp_path / "repo"
    (repo / "bld").mkdir(parents=True)
    c_dir.mkdir()
    monkeypatch.setattr(translint, "C_OBJ_DIR", str(c_dir))
    monkeypatch.setattr(translint, "REPO", str(repo))

    def run(c_tags, rust_tags):
        rbtree_object(str(c_dir / "t.bpf.o"), **c_tags)
        rbtree_object(str(repo / "bld" / "t.bpf.o"), **rust_tags)
        return list(translint.check_decl_tags("t"))
    return run


def test_reads_every_target_kind(tmp_path):
    obj = str(tmp_path / "t.bpf.o")
    rbtree_object(obj, **ALL)
    assert translint.decl_tags(obj) == {
        ("var", "groot", None, "contains:node_data:node"),
        ("struct", "map_value", "head", "contains:foo:list"),
        ("func", "prog", None, "exception_callback:exception_cb"),
        ("func", "sub", 1, "arg:ctx"),
    }


def test_test_loader_comment_tags_are_left_to_test_tags(tmp_path):
    obj = str(tmp_path / "t.bpf.o")
    rbtree_object(obj)
    assert translint.decl_tags(obj) == set()


def test_matching_objects_are_clean(lint_env):
    assert lint_env(ALL, ALL) == []


@pytest.mark.parametrize("missing", ["root_tag", "member_tag", "cb_tag"])
def test_a_missing_load_bearing_tag_is_an_error(lint_env, missing):
    rust = {k: v for k, v in ALL.items() if k != missing}
    (level, text), = lint_env(ALL, rust)
    assert level == "ERROR" and ALL[missing] in text


def test_a_missing_arg_tag_is_a_warning(lint_env):
    rust = {k: v for k, v in ALL.items() if k != "arg_tag"}
    assert lint_env(ALL, rust) == [
        ("WARN", "C object tags func sub parameter 1 with 'arg:ctx', the "
                 "translation does not")]


def test_the_wrong_member_is_caught(lint_env):
    # the tag on `a` instead of `head`: same payload, different declaration
    msgs = lint_env(ALL, dict(ALL, member_idx=0))
    assert [lvl for lvl, _ in msgs] == ["ERROR", "ERROR"]
    assert "map_value.head" in msgs[0][1] and "map_value.a" in msgs[1][1]


def test_a_different_payload_is_caught(lint_env):
    msgs = lint_env(ALL, dict(ALL, root_tag="contains:node_data:other"))
    assert sorted(lvl for lvl, _ in msgs) == ["ERROR", "ERROR"]


def test_an_extra_rust_tag_is_an_error(lint_env):
    (level, text), = lint_env({}, dict(root_tag="contains:x:y"))
    assert level == "ERROR" and "the C object does not" in text


def test_an_unreadable_object_is_skipped(lint_env, tmp_path):
    rbtree_object(str(tmp_path / "c" / "t.bpf.o"), **ALL)
    assert list(translint.check_decl_tags("t")) == []
