#!/usr/bin/env python3
"""Emit the kernel test_loader's BTF decl tags for a Rust-built object.

tools/testing/selftests/bpf/test_loader.c decides whether each program in an
object must load, must be REJECTED, and what the verifier log has to contain
by reading BTF_KIND_DECL_TAGs hanging off the program's FUNC:

    comment:<__COUNTER__>:test_expect_failure
    comment:<__COUNTER__>:test_expect_msg=combined stack size of 3 calls is

clang derives those from bpf_misc.h's __attribute__((btf_decl_tag)) macros.
rustc emits no decl tags at all, so a tag-less Rust object makes test_loader
default to "expect successful load" (test_loader.c:parse_test_spec) and every
negative selftest silently inverts its meaning.

This pass closes that gap: the translation declares its expectations in the
source with bpf-rs-core's `test_tags!` macro (which expands to nothing), and
we append the corresponding DECL_TAGs to the built object's .BTF here.

    test_tags! {
        global_func1: __failure, __msg("combined stack size of 3 calls is");
    }

Appending is safe by construction: new type ids come after every existing id,
no existing type's bytes move, and strings are appended to the end of the
string table, so .BTF.ext's type ids and string offsets stay valid. Only the
.BTF blob's own str_off/str_len/type_len header fields change. As in
btf_rename.py, the grown blob is appended at EOF with its section header
repointed -- never llvm-objcopy --update-section.

Usage: btf_test_tags.py <obj.bpf.o> <prog.rs>
"""

import os
import re
import struct
import sys

BTF_KIND_FUNC = 12
BTF_KIND_DECL_TAG = 17

# extra bytes after struct btf_type, per kind (None => vlen-dependent)
FIXED_EXTRA = {1: 4, 2: 0, 3: 12, 4: None, 5: None, 6: None, 7: 0, 8: 0, 9: 0,
               10: 0, 11: 0, 12: 0, 13: None, 14: 4, 15: None, 16: 0,
               17: 4, 18: 0, 19: None}
PER_VLEN = {4: 12, 5: 12, 6: 8, 13: 8, 15: 12, 19: 12}

# --- bpf_misc.h attribute -> decl tag payload -------------------------------
#
# Mirrors progs/bpf_misc.h one for one. NULLARY tags take no argument; VALUED
# tags take exactly one, appended after '='. A tag this table does not know is
# a hard error: silently dropping an expectation is how a negative test turns
# into a vacuous one.

NULLARY = {
    "__failure": "test_expect_failure",
    "__success": "test_expect_success",
    "__failure_unpriv": "test_expect_failure_unpriv",
    "__success_unpriv": "test_expect_success_unpriv",
    "__auxiliary": "test_auxiliary",
    "__auxiliary_unpriv": "test_auxiliary_unpriv",
    "__load_if_JITed": "load_mode=jited",
    "__load_if_no_JITed": "load_mode=no_jited",
    "__arch_x86_64": "test_arch=X86_64",
    "__arch_arm64": "test_arch=ARM64",
    "__arch_riscv64": "test_arch=RISCV64",
    "__arch_s390x": "test_arch=s390x",
    "__arch_loongarch": "test_arch=LOONGARCH",
}

VALUED = {
    "__msg": "test_expect_msg",
    "__not_msg": "test_expect_not_msg",
    "__msg_unpriv": "test_expect_msg_unpriv",
    "__not_msg_unpriv": "test_expect_not_msg_unpriv",
    "__xlated": "test_expect_xlated",
    "__xlated_unpriv": "test_expect_xlated_unpriv",
    "__jited": "test_jited",
    "__jited_unpriv": "test_jited_unpriv",
    "__stderr": "test_expect_stderr",
    "__stderr_unpriv": "test_expect_stderr_unpriv",
    "__stdout": "test_expect_stdout",
    "__stdout_unpriv": "test_expect_stdout_unpriv",
    "__description": "test_description",
    "__log_level": "test_log_level",
    "__flag": "test_prog_flags",
    "__retval": "test_retval",
    "__retval_unpriv": "test_retval_unpriv",
    "__arch": "test_arch",
    "__caps_unpriv": "test_caps_unpriv",
    # bpf-next 2026-08: the loader skips the program, printing the reason
    "__skip": "test_skip",
}


class TagError(Exception):
    pass


# --- Source parsing ---------------------------------------------------------

def _strip_noise(src):
    """Blank out comments and string bodies so delimiter scanning is safe.

    Returns a string of the same length as `src` with comment and string-body
    characters replaced by spaces, so offsets stay usable as indexes into the
    original text.
    """
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth += 1
                    out[i] = out[i + 1] = " "
                    i += 2
                elif src.startswith("*/", i):
                    depth -= 1
                    out[i] = out[i + 1] = " "
                    i += 2
                else:
                    out[i] = " "
                    i += 1
        elif c == "r" and i + 1 < n and src[i + 1] in '#"':
            j = i + 1
            hashes = 0
            while j < n and src[j] == "#":
                hashes += 1
                j += 1
            if j < n and src[j] == '"':
                close = '"' + "#" * hashes
                k = src.find(close, j + 1)
                if k < 0:
                    raise TagError("unterminated raw string literal")
                for p in range(i, k + len(close)):
                    out[p] = " "
                i = k + len(close)
            else:
                i += 1
        elif c == '"':
            i += 1
            while i < n:
                if src[i] == "\\":
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if src[i] == '"':
                    break
                out[i] = " "
                i += 1
            if i >= n:
                raise TagError("unterminated string literal")
            i += 1
        else:
            i += 1
    return "".join(out)


def _unquote(lit):
    """Decode one Rust string literal (normal or raw) to its bytes-as-str."""
    lit = lit.strip()
    m = re.match(r'^r(#*)"', lit)
    if m:
        hashes = m.group(1)
        close = '"' + hashes
        if not lit.endswith(close):
            raise TagError(f"malformed raw string literal: {lit}")
        return lit[len(m.group(0)):-len(close)]
    if not (lit.startswith('"') and lit.endswith('"') and len(lit) >= 2):
        raise TagError(f"expected a string literal, got: {lit}")
    body, out, i = lit[1:-1], [], 0
    while i < len(body):
        if body[i] == "\\":
            i += 1
            if i >= len(body):
                raise TagError(f"trailing backslash in: {lit}")
            c = body[i]
            out.append({"n": "\n", "t": "\t", "r": "\r", "0": "\0",
                        "\\": "\\", '"': '"', "'": "'"}.get(c, c))
            i += 1
        else:
            out.append(body[i])
            i += 1
    return "".join(out)


def _split_top(text, sep, mask):
    """Split `text` on `sep` at bracket depth 0, using `mask` for delimiters."""
    parts, depth, start = [], 0, 0
    for i, c in enumerate(mask):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == sep and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return parts


def parse_source(path):
    """Read the test_tags! declaration from a .rs translation.

    Returns [(func_name, [decl tag payload, ...]), ...] in source order, or []
    when the translation declares none.
    """
    src = open(path, encoding="utf-8").read()
    mask = _strip_noise(src)
    hits = [m for m in re.finditer(r"\btest_tags\s*!", mask)]
    if not hits:
        return []
    if len(hits) > 1:
        raise TagError(f"{path}: more than one test_tags! declaration")

    i = hits[0].end()
    while i < len(mask) and mask[i].isspace():
        i += 1
    if i >= len(mask) or mask[i] not in "({[":
        raise TagError(f"{path}: test_tags! is not followed by a delimiter")
    opener, closer = mask[i], {"(": ")", "{": "}", "[": "]"}[mask[i]]
    depth, j = 0, i
    while j < len(mask):
        if mask[j] == opener:
            depth += 1
        elif mask[j] == closer:
            depth -= 1
            if depth == 0:
                break
        j += 1
    if depth:
        raise TagError(f"{path}: unterminated test_tags! body")
    body, bmask = src[i + 1:j], mask[i + 1:j]

    entries = []
    for stmt, smask in zip(_split_top(body, ";", bmask),
                           _split_top(bmask, ";", bmask)):
        if not smask.strip():
            continue
        colon = smask.find(":")
        if colon < 0:
            raise TagError(f"{path}: entry without '<func>:': {stmt.strip()}")
        func = stmt[:colon].strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", func):
            raise TagError(f"{path}: bad program name {func!r}")
        tags = []
        for tag, tmask in zip(_split_top(stmt[colon + 1:], ",", smask[colon + 1:]),
                              _split_top(smask[colon + 1:], ",", smask[colon + 1:])):
            if not tmask.strip():
                continue
            tags.append(parse_tag(tag.strip(), path))
        if not tags:
            raise TagError(f"{path}: program {func} declares no tags")
        entries.append((func, tags))
    if not entries:
        raise TagError(f"{path}: empty test_tags! declaration")
    return entries


def parse_tag(text, path):
    """One `__failure` / `__msg("...")` attribute -> its decl tag payload."""
    m = re.fullmatch(r"(__[A-Za-z0-9_]+)\s*(?:\((.*)\))?", text, re.S)
    if not m:
        raise TagError(f"{path}: unparsable tag {text!r}")
    name, arg = m.group(1), m.group(2)
    if arg is None or arg.strip() == "":
        if name not in NULLARY:
            if name in VALUED:
                raise TagError(f"{path}: {name} takes an argument")
            raise TagError(f"{path}: unknown test tag {name}")
        return NULLARY[name]
    if name not in VALUED:
        if name in NULLARY:
            raise TagError(f"{path}: {name} takes no argument")
        raise TagError(f"{path}: unknown test tag {name}")
    arg = arg.strip()
    if arg.startswith('"') or arg.startswith("r"):
        value = _unquote(arg)
    else:
        # numeric / macro-name arguments (__retval(0), __flag(BPF_F_...)) are
        # stringized by bpf_misc.h; take them through verbatim.
        if not re.fullmatch(r"[-A-Za-z0-9_|+ ]+", arg):
            raise TagError(f"{path}: unsupported argument for {name}: {arg!r}")
        value = arg.strip()
    return f"{VALUED[name]}={value}"


# --- BTF surgery ------------------------------------------------------------

def elf_find_section(buf, want):
    assert buf[:4] == b"\x7fELF" and buf[4] == 2 and buf[5] == 1, \
        "not an ELF64-LE object"
    (e_shoff,) = struct.unpack_from("<Q", buf, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 0x3A)

    def shdr(i):
        base = e_shoff + i * e_shentsize
        sh_name, = struct.unpack_from("<I", buf, base)
        sh_offset, sh_size = struct.unpack_from("<QQ", buf, base + 24)
        sh_addralign, = struct.unpack_from("<Q", buf, base + 48)
        return base, sh_name, sh_offset, sh_size, sh_addralign

    _, _, stroff, _, _ = shdr(e_shstrndx)
    for i in range(e_shnum):
        base, sh_name, sh_offset, sh_size, sh_addralign = shdr(i)
        end = buf.index(b"\0", stroff + sh_name)
        if buf[stroff + sh_name:end].decode() == want:
            return base, sh_offset, sh_size, sh_addralign
    raise KeyError(f"no section {want}")


def func_ids(data, hdr_len, type_off, type_len, str_base):
    """FUNC name -> btf type id, from an already-mapped .BTF blob."""

    def get_str(off):
        end = data.index(b"\0", str_base + off)
        return data[str_base + off:end].decode()

    out, pos, end, tid = {}, hdr_len + type_off, hdr_len + type_off + type_len, 1
    while pos < end:
        name_off, info, _sz = struct.unpack_from("<III", data, pos)
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        if kind == BTF_KIND_FUNC:
            out[get_str(name_off)] = tid
        extra = FIXED_EXTRA.get(kind)
        if extra is None:
            extra = vlen * PER_VLEN[kind]
        pos += 12 + extra
        tid += 1
    return out


def inject(path, entries):
    buf = bytearray(open(path, "rb").read())
    shdr_base, btf_off, btf_size, btf_align = elf_find_section(buf, ".BTF")
    data = bytearray(buf[btf_off:btf_off + btf_size])

    magic, _ver, _flags, hdr_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", data, 0)
    assert magic == 0xEB9F, hex(magic)
    str_base = hdr_len + str_off
    assert str_base + str_len == len(data), "string table not at end of .BTF"

    funcs = func_ids(data, hdr_len, type_off, type_len, str_base)

    new_types, new_strings, count = bytearray(), bytearray(), 0
    for func, tags in entries:
        if func not in funcs:
            raise TagError(
                f"{os.path.basename(path)}: no BTF FUNC named {func!r} "
                f"(programs in this object: {', '.join(sorted(funcs))})")
        for tag in tags:
            # "comment:<n>:" mirrors bpf_misc.h's __COUNTER__ prefix; the
            # loader sorts tags with strverscmp to recover source order.
            payload = f"comment:{count}:{tag}".encode() + b"\0"
            name_off = str_len + len(new_strings)
            new_strings.extend(payload)
            new_types.extend(struct.pack(
                "<IIIi", name_off, BTF_KIND_DECL_TAG << 24, funcs[func], -1))
            count += 1

    # types grow in place at the end of the type section; the string table
    # (which must stay last) shifts by exactly that much.
    head = data[:hdr_len + type_off + type_len]
    strings = data[str_base:str_base + str_len]
    out = bytearray(head)
    out.extend(new_types)
    out.extend(strings)
    out.extend(new_strings)
    struct.pack_into("<III", out, 12,
                     type_len + len(new_types),
                     str_off + len(new_types),
                     str_len + len(new_strings))

    align = max(btf_align, 1)
    pad = (-len(buf)) % align
    new_off = len(buf) + pad
    buf.extend(b"\0" * pad)
    buf.extend(out)
    struct.pack_into("<QQ", buf, shdr_base + 24, new_off, len(out))
    open(path, "wb").write(buf)
    return count


def declares_failure(src):
    """True when the translation asserts the verifier rejects a program in
    PRIVILEGED mode -- the mode veristat loads in. __failure_unpriv doesn't
    count: those objects load fine privileged and belong in the gate."""
    return any(t == "test_expect_failure"
               for _fn, tags in parse_source(src) for t in tags)


def main(argv):
    # --list-negative <prog.rs>...: names of translations the verifier must
    # reject, for callers that would otherwise treat rejection as a failure
    # (the veristat gate).
    if len(argv) > 1 and argv[1] == "--list-negative":
        for src in argv[2:]:
            try:
                if declares_failure(src):
                    print(os.path.basename(src)[:-3])
            except TagError as e:
                print(f"[btf_test_tags] ERROR: {e}", file=sys.stderr)
                return 1
        return 0
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    obj, src = argv[1], argv[2]
    try:
        entries = parse_source(src)
        if not entries:
            return 0
        n = inject(obj, entries)
    except TagError as e:
        print(f"[btf_test_tags] ERROR: {e}", file=sys.stderr)
        return 1
    progs = ", ".join(f for f, _ in entries)
    print(f"[btf_test_tags] {os.path.basename(obj)}: {n} decl tag(s) on {progs}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
