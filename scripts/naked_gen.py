#!/usr/bin/env python3
"""Generate the Rust translation of a selftest written as naked BPF asm.

Most tools/testing/selftests/bpf/progs/verifier_*.c programs are `__naked`
functions whose body is one `asm volatile` block of hand-written BPF
assembly, with bpf_misc.h's __imm / __imm_addr / __imm_const / __imm_insn /
__imm_ptr operands and test_loader decl tags. There is nothing to translate
but the operands, so this generator carries the asm verbatim:

  - the C file is preprocessed with the selftests' own clang flags, so the
    #if-selected variants and the macro-built operands are the ones the
    oracle object was built from;
  - every "i" operand is resolved by compiling a probe (an `#include` of
    the C file plus one `.8byte %[op]` per operand) with the same flags and
    reading the values and relocations back: a helper id becomes the
    literal `call 1`, a map, function or kfunc address `{name}` with
    `sym name`, a constant or an encoded instruction its decimal value;
  - `%=` labels get the function name as their suffix; "r" operands
    (__imm_ptr) become `in(reg)` inputs; a `call`/`goto` to a function
    named in the asm text becomes a `sym` operand, which is what keeps a
    `__used` static subprogram alive through internalize/globaldce;
  - maps, globals, kfunc externs and the license come from the C object's
    BTF and ELF, the test_loader tags from its decl tags, verbatim, so the
    test_tags! declaration mirrors the oracle exactly;
  - each function is emitted as `// BPF_NAKED:` raw asm (scripts/naked_abi.py).

scripts/translint.py's naked-verbatim check then compares the built
object's instruction stream against the C object's, relocation by
relocation (scripts/naked_verbatim.py).

A function with a C body is hand work: with --with-c-bodies the generated
file include!s progs/hand/<name>.rs, which the generator writes once (a
stub and the C text per such function) and never overwrites. A function
that only references kfuncs (`__kfunc_btf_root`, `kfunc_root`: a BTF
prototype for each kfunc the asm calls) is generated whatever its name.

What the generator refuses (reported as "unsupported", per file in
--survey): a kfunc variable (`extern const int x __ksym`), a `.percpu`
section, a map member it does not know, a struct the Rust layout could not
reproduce, a function header it cannot parse (`typeof`).

Usage:
  scripts/naked_gen.py <name>...          write progs/<name>.rs
  scripts/naked_gen.py --with-c-bodies <name>...   ... and progs/hand/<name>.rs
  scripts/naked_gen.py --stdout <name>    print instead of writing
  scripts/naked_gen.py --survey [name...] what can be generated, per file
                                          (default: every verifier_*.c)
"""
import argparse
import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "equiv"))
sys.path.insert(0, HERE)
import paths  # noqa: E402
from bpfelf import BpfElf  # noqa: E402
import btf_test_tags  # noqa: E402

C_PROGS = os.path.join(paths.SELFTESTS_SRC, "progs")
C_OBJS = paths.SELFTESTS_OUTPUT
CLANG = os.path.join(paths.LLVM_PREFIX, "bin", "clang")

STT_SECTION = 3

RUST_KEYWORDS = {
    "as", "break", "const", "continue", "crate", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
    "move", "mut", "pub", "ref", "return", "self", "Self", "static", "struct",
    "super", "trait", "true", "type", "unsafe", "use", "where", "while",
    "async", "await", "dyn", "abstract", "become", "box", "do", "final",
    "macro", "override", "priv", "typeof", "unsized", "virtual", "yield",
    "try", "gen",
}


class Unsupported(Exception):
    pass


def ident(name):
    return "r#" + name if name in RUST_KEYWORDS else name


def rust_fn(name):
    """The Rust name of a C function: a keyword (`self`) gets a trailing
    underscore and keeps its symbol through #[export_name]."""
    return name + "_" if name in RUST_KEYWORDS else name


def fn_attrs(name):
    return f'#[export_name = "{name}"]' if name in RUST_KEYWORDS else "#[no_mangle]"


# --- clang: the selftests' own flags ---------------------------------------

_SYS_INC = None


def sys_includes():
    """Makefile's get_sys_includes: clang's own system include dirs, as
    -idirafter, so <stdint.h> and friends resolve the way they do for the
    oracle object."""
    global _SYS_INC
    if _SYS_INC is None:
        p = subprocess.run([CLANG, "-v", "-E", "-"], input="",
                           capture_output=True, text=True)
        out, on = [], False
        for line in p.stderr.splitlines():
            if "<...> search starts here:" in line:
                on = True
                continue
            if "End of search list." in line:
                break
            if on and line.startswith(" /"):
                out += ["-idirafter", line.strip()]
        _SYS_INC = out
    return _SYS_INC


def bpf_cflags():
    """BPF_CFLAGS + BPF_SYS_INCLUDES + BPF_DEFINES + BPF_CC_FLAGS of the
    selftests build (Makefile.buildvars, Makefile.skel; x86-64, the default
    test_progs flavor), minus -Werror."""
    out, src = C_OBJS, paths.SELFTESTS_SRC
    tools = os.path.join(paths.KERNEL_SRC, "tools")
    return (["-g", "-Wall", "-D__TARGET_ARCH_x86", "-mlittle-endian",
             "-I" + os.path.join(out, "tools", "include"), "-I" + src,
             "-I" + os.path.join(tools, "include", "uapi"),
             "-I" + os.path.join(tools, "include"),
             "-I" + os.path.join(src, "libarena", "include"),
             "-I" + os.path.abspath(os.path.join(out, "..", "usr", "include")),
             "-std=gnu11", "-fno-strict-aliasing", "-Wno-microsoft-anon-tag",
             "-fms-extensions", "-Wno-compare-distinct-pointer-types",
             "-Wno-initializer-overrides"]
            + sys_includes()
            + ["-DENABLE_ATOMICS_TESTS", "-O2", "--target=bpfel", "-mcpu=v3"])


def clang(args, what):
    p = subprocess.run([CLANG] + bpf_cflags() + args, capture_output=True,
                       text=True)
    if p.returncode:
        err = [ln for ln in p.stderr.splitlines() if "error:" in ln]
        raise Unsupported(f"{what}: " + (err[0] if err else p.stderr.strip()[-200:]))
    return p.stdout


def preprocess(cpath):
    """The main file's own text after preprocessing (headers dropped by the
    line markers), so #if-selected variants and macro-built operands are
    what the oracle object was built from."""
    out, keep = [], False
    for line in clang(["-E", cpath], "preprocess").split("\n"):
        m = re.match(r'# \d+ "([^"]*)"', line)
        if m:
            keep = os.path.abspath(m.group(1)) == os.path.abspath(cpath)
            continue
        if keep and not line.startswith("#"):    # SEC()'s _Pragma lines
            out.append(line)
    return "\n".join(out)


def preprocess_files(cpath):
    """{file: its preprocessed text} for the main file and the selftests'
    own headers (those under tools/testing/selftests/bpf, vmlinux.h
    excepted): a header can define a function the C object carries
    (bpf_sockopt_helpers.h's get_set_sk_priority)."""
    sdir = os.path.dirname(os.path.dirname(os.path.abspath(cpath)))
    out, cur = {}, None
    for line in clang(["-E", cpath], "preprocess").split("\n"):
        m = re.match(r'# \d+ "([^"]*)"', line)
        if m:
            f = os.path.abspath(m.group(1))
            cur = f if f == os.path.abspath(cpath) or \
                (f.startswith(sdir + os.sep) and os.path.basename(f) != "vmlinux.h") else None
            continue
        if cur and not line.startswith("#"):
            out.setdefault(cur, []).append(line)
    return {f: "\n".join(ls) for f, ls in out.items()}


# --- C parsing (preprocessed text) -----------------------------------------

def split_top(text, sep):
    """Split at `sep` outside parentheses, brackets, braces and strings."""
    parts, depth, start, i, n = [], 0, 0, 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            q = c
            i += 1
            while i < n and text[i] != q:
                if text[i] == "\\":
                    i += 1
                i += 1
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == sep and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return parts


def strip_attrs(head):
    """Remove every __attribute__((...)) from a declaration head; return
    (rest, [attribute, ...]) with each attribute's text as written."""
    attrs, out, i = [], [], 0
    while True:
        m = re.compile(r"__attribute(?:__)?\s*\(").search(head, i)
        if not m:
            out.append(head[i:])
            break
        j = m.start()
        out.append(head[i:j])
        k = m.end() - 1
        depth, m = 0, k
        while m < len(head):
            c = head[m]
            if c == '"':                      # a tag's message may hold parens
                m += 1
                while m < len(head) and head[m] != '"':
                    if head[m] == "\\":
                        m += 1
                    m += 1
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            m += 1
        inner = head[k + 1:m].strip()
        if inner.startswith("(") and inner.endswith(")"):
            inner = inner[1:-1]
        attrs += [a.strip() for a in split_top(inner, ",") if a.strip()]
        i = m + 1
    return "".join(out), attrs


def is_func_header(head):
    rest, _ = strip_attrs(head)
    rest = rest.strip()
    return rest.endswith(")") and "=" not in rest.split("(")[0]


def split_items(text):
    """Top-level items of preprocessed C: (head, body) with body None for a
    declaration and the text between the braces for a function."""
    items, start, depth, body_start, i, n = [], 0, 0, None, 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            q = c
            i += 1
            while i < n and text[i] != q:
                if text[i] == "\\":
                    i += 1
                i += 1
        elif c == "{":
            if depth == 0:
                body_start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and is_func_header(text[start:body_start]):
                items.append((text[start:body_start], text[body_start + 1:i]))
                start, body_start = i + 1, None
        elif c == ";" and depth == 0:
            items.append((text[start:i], None))
            start, body_start = i + 1, None
        i += 1
    return items


class Func:
    def __init__(self, name, static, section, rtype, params, naked, body):
        self.name, self.static, self.section = name, static, section
        self.rtype, self.params, self.naked, self.body = rtype, params, naked, body
        self.stmts, self.operands, self.rust_params = [], [], []   # filled by resolve
        self.asm_index, self.clobbers, self.root, self.c_text = 0, [], None, ""
        self.header = None      # the included header defining it, if any


def parse_function(head, body):
    rest, attrs = strip_attrs(head)
    section = None
    for a in attrs:
        m = re.fullmatch(r"section\s*\((.*)\)", a, re.S)
        if m:
            section = c_string(m.group(1))   # SEC("?fentry.s/" SYS_PREFIX "x")
    rest = re.sub(r"\s+", " ", rest).strip()
    rest = re.sub(r"\b(?:inline|__inline|__inline__)\b", "", rest).strip()
    if not rest.endswith(")"):
        raise Unsupported(f"unparsable function header {rest!r}")
    depth, i = 0, len(rest) - 1
    while i >= 0:
        if rest[i] == ")":
            depth += 1
        elif rest[i] == "(":
            depth -= 1
            if depth == 0:
                break
        i -= 1
    params, head = rest[i + 1:-1].strip(), rest[:i].rstrip()
    m = re.fullmatch(r"(static )?(.*?)\s*\b([A-Za-z_]\w*)", head, re.S)
    if not m:
        raise Unsupported(f"unparsable function header {rest!r}")
    if params == "void":
        params = ""
    return Func(m.group(3), bool(m.group(1)), section, m.group(2).strip(),
                params, "naked" in attrs, body)


def c_function_text(raw, name):
    """The definition of function `name` in the raw C source (from the
    blank line before its head to its closing brace), for a comment."""
    m = re.search(r"\b" + re.escape(name) + r"\s*\([^;{)]*\)\s*(?:__attribute__\(\(.*?\)\)\s*)*\{", raw, re.S)
    if not m:    # BPF_PROG(name, args...) and friends
        m = re.search(r"\bBPF_\w+\(\s*" + re.escape(name) + r"\b[^{]*\{", raw, re.S)
    if not m:
        return f"(definition of {name} not found in the source)"
    start = raw.rfind("\n\n", 0, m.start())
    start = 0 if start < 0 else start + 2
    depth, i = 0, m.end() - 1
    while i < len(raw):
        if raw[i] == "{":
            depth += 1
        elif raw[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return raw[start:i + 1]


def c_string(text):
    """Decode the concatenated C string literals that make up `text`."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if c != '"':
            raise Unsupported(f"asm template is not a string literal: {text[i:i + 20]!r}")
        i += 1
        while i < n and text[i] != '"':
            if text[i] == "\\":
                i += 1
                e = text[i]
                if e in "01234567":
                    j = i
                    while j < n and j < i + 3 and text[j] in "01234567":
                        j += 1
                    out.append(chr(int(text[i:j], 8)))
                    i = j
                    continue
                if e == "x":
                    j = i + 1
                    while j < n and text[j] in "0123456789abcdefABCDEF":
                        j += 1
                    out.append(chr(int(text[i + 1:j], 16)))
                    i = j
                    continue
                out.append({"n": "\n", "t": "\t", "r": "\r", "a": "\a",
                            "b": "\b", "f": "\f", "v": "\v"}.get(e, e))
                i += 1
            else:
                out.append(text[i])
                i += 1
        i += 1
    return "".join(out)


def parse_asm(f):
    """(template, [(operand name, constraint, expr), ...]) of a naked
    function's single asm statement."""
    s = f.body.strip()
    m = re.fullmatch(r"(?:__asm__|asm)\s*(?:volatile|__volatile__|__volatile)?"
                     r"\s*\((.*)\)\s*;?", s, re.S)
    if not m:
        raise Unsupported(f"{f.name}: body is not a single asm statement")
    parts = split_top(m.group(1), ":")
    if len(parts) > 4:
        raise Unsupported(f"{f.name}: asm statement with {len(parts) - 1} colons")
    if len(parts) > 3:
        f.clobbers = [c_string(c) for c in split_top(parts[3], ",") if c.strip()]
    if len(parts) > 1 and parts[1].strip():
        raise Unsupported(f"{f.name}: asm output operands")
    ops = []
    if len(parts) > 2:
        for item in split_top(parts[2], ","):
            item = item.strip()
            if not item:
                continue
            mm = re.fullmatch(r'\[(\w+)\]\s*"([^"]*)"\s*\((.*)\)', item, re.S)
            if not mm:
                raise Unsupported(f"{f.name}: operand {item[:40]!r}")
            ops.append((mm.group(1), mm.group(2), mm.group(3).strip()))
    return c_string(parts[0]), ops


# --- "i" operands: what clang makes of them ----------------------------------

def probe_operands(cpath, entries):
    """entries: [(func, operand name, C expression)] -> [('imm', int) |
    ('sym', symbol name)], by compiling an `#include` of the C file plus
    one `.8byte %[op]` per operand with the selftests' flags and reading
    the values and relocations back."""
    if not entries:
        return []
    src = [f'#include "{cpath}"',
           '__attribute__((section("rsgen"), used)) void __rsgen_probe(void)', "{"]
    for base in range(0, len(entries), 16):
        chunk = entries[base:base + 16]
        tmpl = " ".join(f".8byte %[o{base + i}];" for i in range(len(chunk)))
        ins = ", ".join(f'[o{base + i}]"i"({expr})'
                        for i, (_f, _n, expr) in enumerate(chunk))
        src.append(f'\tasm volatile("{tmpl}" : : {ins});')
    src.append("}")
    with tempfile.TemporaryDirectory() as tmp:
        c = os.path.join(tmp, "probe.c")
        o = os.path.join(tmp, "probe.o")
        with open(c, "w") as fh:
            fh.write("\n".join(src) + "\n")
        clang(["-c", c, "-o", o], "operand probe")
        elf = BpfElf(o)
    sec = elf.section_by_name("rsgen")
    # the slots, then the `exit` clang appends to the probe function
    if sec is None or sec.size != 8 * len(entries) + 8:
        raise Unsupported("operand probe: unexpected rsgen section")
    rels = elf.relocs.get(sec.idx, {})
    out = []
    for i in range(len(entries)):
        off = 8 * i
        raw = struct.unpack_from("<q", sec.data, off)[0]
        if off in rels:
            sym = rels[off].sym
            if sym.type == STT_SECTION:
                sym = elf.named_symbol_at(sym.shndx, raw)
            if sym is None or not sym.name:
                raise Unsupported(f"{entries[i][0]}: operand {entries[i][1]} "
                                  f"relocates against an unnamed symbol")
            out.append(("sym", sym.name))
        else:
            out.append(("imm", raw))
    return out


# --- BTF -----------------------------------------------------------------

K_INT, K_PTR, K_ARRAY, K_STRUCT, K_UNION, K_ENUM, K_FWD, K_TYPEDEF = range(1, 9)
K_VOLATILE, K_CONST, K_RESTRICT, K_FUNC, K_FUNC_PROTO, K_VAR, K_DATASEC = range(9, 16)
K_FLOAT, K_DECL_TAG, K_TYPE_TAG, K_ENUM64 = 16, 17, 18, 19
MODIFIERS = (K_TYPEDEF, K_VOLATILE, K_CONST, K_RESTRICT, K_TYPE_TAG)


class BtfType:
    __slots__ = ("kind", "name", "size", "vlen", "kflag", "extra")

    def __init__(self, kind, name, size, vlen, kflag, extra):
        self.kind, self.name, self.size = kind, name, size
        self.vlen, self.kflag, self.extra = vlen, kflag, extra


class Btf:
    def __init__(self, data):
        (magic, _ver, _flags, hdr_len, type_off, type_len,
         str_off, str_len) = struct.unpack_from("<HBBIIIII", data, 0)
        assert magic == 0xEB9F
        sb = hdr_len + str_off
        self.strs = data[sb:sb + str_len]
        self.types = {0: BtfType(0, "void", 0, 0, 0, None)}
        pos, end, tid = hdr_len + type_off, hdr_len + type_off + type_len, 1
        while pos < end:
            name_off, info, size = struct.unpack_from("<III", data, pos)
            pos += 12
            kind, vlen, kflag = (info >> 24) & 0x1F, info & 0xFFFF, info >> 31
            extra = None
            if kind == K_INT:
                extra = struct.unpack_from("<I", data, pos)[0]
                pos += 4
            elif kind == K_ARRAY:
                extra = struct.unpack_from("<III", data, pos)
                pos += 12
            elif kind in (K_STRUCT, K_UNION):
                extra = []
                for _ in range(vlen):
                    n, t, off = struct.unpack_from("<III", data, pos)
                    extra.append((self.s(n), t, off))
                    pos += 12
            elif kind == K_ENUM:
                extra = []
                for _ in range(vlen):
                    n, v = struct.unpack_from("<Ii", data, pos)
                    extra.append((self.s(n), v))
                    pos += 8
            elif kind == K_FUNC_PROTO:
                extra = []
                for _ in range(vlen):
                    n, t = struct.unpack_from("<II", data, pos)
                    extra.append((self.s(n), t))
                    pos += 8
            elif kind == K_VAR:
                extra = struct.unpack_from("<I", data, pos)[0]
                pos += 4
            elif kind == K_DATASEC:
                extra = []
                for _ in range(vlen):
                    extra.append(struct.unpack_from("<III", data, pos))
                    pos += 12
            elif kind == K_DECL_TAG:
                extra = struct.unpack_from("<i", data, pos)[0]
                pos += 4
            elif kind == K_ENUM64:
                extra = []
                for _ in range(vlen):
                    n, lo, hi = struct.unpack_from("<III", data, pos)
                    extra.append((self.s(n), lo | (hi << 32)))
                    pos += 12
            self.types[tid] = BtfType(kind, self.s(name_off), size, vlen, kflag, extra)
            tid += 1

    def s(self, off):
        end = self.strs.index(b"\0", off)
        return self.strs[off:end].decode()

    def strip(self, tid):
        t = self.types[tid]
        while t.kind in MODIFIERS:
            tid = t.size
            t = self.types[tid]
        return tid

    def datasec(self, name):
        for t in self.types.values():
            if t.kind == K_DATASEC and t.name == name:
                return t
        return None

    def datasecs(self):
        return [t for t in self.types.values() if t.kind == K_DATASEC]


class RustTypes:
    """BTF type -> Rust type text; the struct/union definitions it needed,
    in dependency order, in `defs`."""

    def __init__(self, btf):
        self.btf = btf
        self.defs, self.done, self.failed, self.packed = [], set(), {}, set()
        self.opaque = set()

    def rust(self, tid):
        btf = self.btf
        tid = btf.strip(tid)
        t = btf.types[tid]
        if t.kind == K_INT:
            enc = t.extra
            flags, offset, bits = (enc >> 24) & 0xF, (enc >> 16) & 0xFF, enc & 0xFF
            if offset or bits != t.size * 8:
                raise Unsupported(f"bitfield int {t.name!r}")
            if flags & 4:
                return "bool"
            return ("i" if flags & 1 else "u") + str(t.size * 8)
        if t.kind == K_FLOAT:
            return {4: "f32", 8: "f64"}.get(t.size) or self.fail(t)
        if t.kind == K_PTR:
            p = btf.types[btf.strip(t.size)]
            if p.kind in (K_STRUCT, K_UNION) and p.name:
                try:
                    return "*mut " + self.rust(t.size)
                except Unsupported:
                    # a kernel struct the Rust cannot spell: an opaque stand-in
                    # of the same name (a kptr is classified by that name)
                    if p.name not in self.opaque:
                        self.opaque.add(p.name)
                        kw = "union" if p.kind == K_UNION else "struct"
                        # a #[btf] (CO-RE) view, as lru_bug.rs / bpf_iter_tcp4.rs
                        # declare theirs: a plain struct only pointed at
                        # reaches BTF as a FWD, which a kptr may not be
                        self.defs.append("/// An opaque stand-in for the kernel's: only pointed at.\n"
                                         "#[allow(non_camel_case_types)]\n#[btf]\n"
                                         f"{kw} {p.name} {{}}")
                    return "*mut " + p.name
            if p.kind in (K_INT, K_ARRAY, K_FLOAT):
                return "*mut " + self.rust(t.size)
            if p.kind == K_FUNC_PROTO:
                return self.fn_pointer(btf.strip(t.size))
            return "*mut c_void"
        if t.kind == K_ARRAY:
            elem, _idx, n = t.extra
            return f"[{self.rust(elem)}; {n}]"
        if t.kind in (K_STRUCT, K_UNION):
            if not t.name:
                # an anonymous type (a map's `struct { ... }` value): named
                # here, Rust having no anonymous types; map value type
                # names are not load-bearing for libbpf
                t.name = f"__anon_type{tid}"
            self.collect(tid)
            return t.name
        if t.kind in (K_ENUM, K_ENUM64):
            return ("i" if t.kflag else "u") + str(t.size * 8)
        return self.fail(t)

    def fail(self, t):
        raise Unsupported(f"BTF kind {t.kind} ({t.name!r}) as a value type")

    def fn_pointer(self, proto_tid):
        """`extern "C" fn(...) -> R` for a FUNC_PROTO: Sync (a raw pointer is
        not, and a .rodata table of function pointers is a `static`), and
        the C's BTF shape (a pointer to a function prototype)."""
        btf = self.btf
        t = btf.types[proto_tid]

        def one(tid):
            pt = btf.types[btf.strip(tid)]
            if pt.kind == K_PTR:
                return "*mut c_void"
            return self.rust(tid)
        params = ", ".join(one(p) for _n, p in t.extra)
        ret = "" if btf.strip(t.size) == 0 else " -> " + one(t.size)
        return f'extern "C" fn({params}){ret}'

    def local_like(self, tid, depth=0):
        """Whether a struct looks like one the C file defines (a callback
        context, a value type) rather than a kernel type pulled in from
        vmlinux.h: few members, of scalar, pointer or small nested types."""
        btf = self.btf
        t = btf.types[btf.strip(tid)]
        if t.kind not in (K_STRUCT, K_UNION) or len(t.extra) > 8 or depth > 2:
            return False
        for _name, mtid, _off in t.extra:
            m = btf.types[btf.strip(mtid)]
            if m.kind == K_ARRAY:
                m = btf.types[btf.strip(m.extra[0])]
            if m.kind in (K_STRUCT, K_UNION) and not self.local_like(mtid, depth + 1):
                return False
        return True

    def size_align(self, tid):
        """Natural (repr(C)) size and alignment of the Rust rendering."""
        btf = self.btf
        t = btf.types[btf.strip(tid)]
        if t.kind in (K_INT, K_FLOAT, K_ENUM, K_ENUM64):
            return t.size, t.size
        if t.kind == K_PTR:
            return 8, 8
        if t.kind == K_ARRAY:
            elem, _idx, n = t.extra
            s, a = self.size_align(elem)
            return s * n, a
        if t.kind in (K_STRUCT, K_UNION):
            size, align = 0, 1
            for _name, mtid, off in t.extra:
                s, a = self.size_align(mtid)
                if off % 8:
                    raise Unsupported(f"struct {t.name}: bitfield member")
                if t.kind == K_STRUCT and (off // 8) % a:
                    self.packed.add(btf.strip(tid))      # repr(C, packed)
                    a = 1
                align = max(align, a)
                if t.kind == K_UNION:
                    size = max(size, s)
                else:
                    size = off // 8 + s
            if btf.strip(tid) in self.packed:
                align = 1
            return (size + align - 1) // align * align, align
        return self.fail(t)

    def collect(self, tid):
        if tid in self.done:
            if tid in self.failed:
                raise Unsupported(self.failed[tid])
            return
        self.done.add(tid)
        try:
            self._collect(tid)
        except Unsupported as e:
            self.failed[tid] = str(e)
            raise

    def _collect(self, tid):
        t = self.btf.types[tid]
        if t.kflag:
            raise Unsupported(f"struct {t.name}: bitfield members")
        fields = []
        for i, (name, mtid, off) in enumerate(t.extra):
            if not name:
                # an anonymous struct/union member: named here (Rust has
                # no anonymous members), its type after the enclosing one
                inner = self.btf.types[self.btf.strip(mtid)]
                if inner.kind not in (K_STRUCT, K_UNION) or inner.name:
                    raise Unsupported(f"struct {t.name}: anonymous member of kind {inner.kind}")
                inner.name = f"{t.name}__anon{i}"
                name = f"__anon{i}"
            fields.append(f"    {ident(name)}: {self.rust(mtid)},")
        size, _align = self.size_align(tid)
        if size != t.size and tid in self.packed:
            size = sum(0 for _ in ()) or t.size   # packed: the C size is the layout
        if size != t.size:
            raise Unsupported(f"struct {t.name}: C size {t.size}, natural Rust "
                              f"layout {size} (explicit alignment or padding)")
        kw = "union" if t.kind == K_UNION else "struct"
        repr_ = "#[repr(C, packed)]" if tid in self.packed else "#[repr(C)]"
        # plain data, Copy: a union's members must be
        self.defs.append("#[allow(non_camel_case_types, non_snake_case)]\n" + repr_ + "\n#[derive(Clone, Copy)]\n"
                         + f"{kw} {t.name} {{\n" + "\n".join(fields) + "\n}")

    def literal(self, tid, data, rels=None, base=0):
        """A Rust literal of type `tid` holding the bytes `data`; `rels`
        maps an offset (from `base`) to the symbol a pointer there names."""
        btf = self.btf
        rels = rels or {}
        t = btf.types[btf.strip(tid)]
        if t.kind == K_INT:
            flags = (t.extra >> 24) & 0xF
            v = int.from_bytes(data[:t.size], "little", signed=bool(flags & 1))
            if flags & 4:
                return "true" if v else "false"
            return str(v)
        if t.kind in (K_ENUM, K_ENUM64):
            return str(int.from_bytes(data[:t.size], "little", signed=bool(t.kflag)))
        if t.kind == K_PTR:
            if base in rels:
                return rels[base]
            if any(data[:8]):
                raise Unsupported("non-null pointer initializer without a relocation")
            return "core::ptr::null_mut()"
        if t.kind == K_ARRAY:
            elem, _idx, n = t.extra
            es = self.size_align(elem)[0]
            items = [self.literal(elem, data[i * es:(i + 1) * es], rels, base + i * es) for i in range(n)]
            if n > 4 and len(set(items)) == 1:
                return f"[{items[0]}; {n}]"
            return "[" + ", ".join(items) + "]"
        if t.kind == K_STRUCT:
            fields = [f"{ident(name)}: {self.literal(mtid, data[off // 8:], rels, base + off // 8)}"
                      for name, mtid, off in t.extra]
            return f"{t.name} {{ " + ", ".join(fields) + " }"
        raise Unsupported(f"initializer of BTF kind {t.kind}")


# --- the C object: maps, globals, kfuncs, tags, license ----------------------

class CObject:
    def __init__(self, path):
        self.elf = BpfElf(path)
        sec = self.elf.section_by_name(".BTF")
        if sec is None:
            raise Unsupported("C object has no .BTF")
        self.btf = Btf(sec.data)
        self.types = RustTypes(self.btf)

    def hidden_symbols(self):
        """Names of the ELF symbols with STV_HIDDEN visibility (the C's
        __hidden), which equiv/bpfelf.py's Symbol does not carry."""
        symtab, strtab = self.elf.section_by_name(".symtab"), self.elf.section_by_name(".strtab")
        out = set()
        if symtab is None or strtab is None:
            return out
        for i in range(symtab.size // 24):
            name_off, _info, other, _shndx, _value, _size = struct.unpack_from("<IBBHQQ", symtab.data, i * 24)
            if other & 3 == 2:
                end = strtab.data.index(b"\0", name_off)
                out.add(strtab.data[name_off:end].decode())
        return out

    def functions(self):
        """Defined FUNC symbol name -> section name."""
        out = {}
        for s in self.elf.symbols:
            if s.type == 2 and s.shndx not in (0, 0xFFF1) and s.shndx < len(self.elf.sections):
                out[s.name] = self.elf.sections[s.shndx].name
        return out

    def arg_tags(self):
        """Function name -> [(parameter index, tag)] of the C object's
        parameter decl tags (bpf_misc.h's __arg_nonnull, __arg_untrusted, ...)."""
        btf, out = self.btf, {}
        for t in btf.types.values():
            if t.kind != K_DECL_TAG or t.name.startswith("comment:") or t.extra < 0:
                continue
            target = btf.types[t.size]
            if target.kind == K_FUNC:
                out.setdefault(target.name, []).append((t.extra, t.name))
        return out

    def type_tags(self):
        """[(struct name, member, tag)] for every struct/union member whose
        pointer type carries a BTF type tag (`__kptr`, `__uptr`, ...),
        [(function, "<index>" or "ret", tag)] for a defined function's
        parameter or return type that does (`u32 __arena *f(u32 __arena *p)`),
        and [(variable, "", tag)] for a global whose own type does
        (`struct bin_data __kptr *ptr;`)."""
        btf, out = self.btf, []

        def tag_of(tid):
            while True:
                m = btf.types[tid]
                if m.kind == K_TYPE_TAG:
                    return m.name
                if m.kind in (K_PTR,) + MODIFIERS and m.kind != K_TYPE_TAG:
                    tid = m.size
                    continue
                return None
        defined = self.functions()
        for t in btf.types.values():
            if t.kind in (K_STRUCT, K_UNION) and t.name:
                for mname, mtid, _off in t.extra:
                    tag = tag_of(mtid) if mtid else None
                    if tag:
                        out.append((t.name, mname, tag))
            elif t.kind == K_VAR and t.name:
                tag = tag_of(t.size) if t.size else None
                if tag:
                    out.append((t.name, "", tag))
            elif t.kind == K_FUNC and t.name in defined:
                proto = btf.types[t.size]
                for i, (_pname, ptid) in enumerate(proto.extra):
                    tag = tag_of(ptid) if ptid else None
                    if tag:
                        out.append((t.name, str(i), tag))
                tag = tag_of(proto.size) if proto.size else None
                if tag:
                    out.append((t.name, "ret", tag))
        return out

    def test_tags(self):
        """Program name -> [decl tag payload, ...] in test_loader order."""
        btf, out = self.btf, {}
        for t in btf.types.values():
            if t.kind != K_DECL_TAG or not t.name.startswith("comment:"):
                continue
            target = btf.types[t.size]
            if target.kind != K_FUNC:
                continue
            _c, counter, payload = t.name.split(":", 2)
            out.setdefault(target.name, []).append((int(counter), payload))
        return {fn: [p for _c, p in sorted(tl)] for fn, tl in out.items()}

    def ksyms(self):
        """[(kind, name, type id)] of the .ksyms DATASEC."""
        ds = self.btf.datasec(".ksyms")
        if ds is None:
            return []
        out = []
        for tid, _off, _size in ds.extra:
            t = self.btf.types[tid]
            out.append((t.kind, t.name, tid))
        return out

    def var_extent(self, section, name):
        """(offset, size) of a global variable within its ELF section: the
        BTF DATASEC entries of an object carry offset 0 (libbpf fills them
        in from the symbol table at load time)."""
        sec = self.elf.section_by_name(section)
        if sec is None:
            raise Unsupported(f"no section {section} for variable {name}")
        for s in self.elf.symbols:
            if s.name == name and s.type == 1 and s.shndx == sec.idx:
                return s.value, s.size
        raise Unsupported(f"variable {name} has no symbol in {section}")

    def license(self):
        sec = self.elf.section_by_name("license")
        if sec is None:
            return None, None
        sym = next((s for s in self.elf.symbols if s.type == 1 and s.shndx == sec.idx), None)
        text = sec.data.split(b"\0")[0].decode()
        return (sym.name if sym else "_license"), text


# --- generation --------------------------------------------------------------

def rust_str(s):
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ord(ch) < 32 or ord(ch) == 127:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


NULLARY_REV = {v: k for k, v in btf_test_tags.NULLARY.items()}
VALUED_REV = {v: k for k, v in btf_test_tags.VALUED.items()}


def tag_macro(payload, name):
    if payload in NULLARY_REV:
        return NULLARY_REV[payload]
    key, sep, val = payload.partition("=")
    if sep and key in VALUED_REV:
        # the verifier names a function's source file from the line info
        # ("<func> @ <file>:<line>"): for this object that is the .rs
        val = val.replace(f" @ {name}.c", f" @ {name}.rs")
        return f"{VALUED_REV[key]}({rust_str(val)})"
    raise Unsupported(f"test tag {payload!r} has no bpf_misc.h macro in btf_test_tags.py")


C_RETURN_TYPES = {
    "void": "", "int": "i32", "unsigned int": "u32", "unsigned": "u32",
    "long": "i64", "unsigned long": "u64", "long long": "i64",
    "unsigned long long": "u64", "__u64": "u64", "__s64": "i64",
    "__u32": "u32", "__s32": "i32", "__u16": "u16", "__s16": "i16",
    "__u8": "u8", "__s8": "i8", "char": "i8", "unsigned char": "u8",
    "short": "i16", "unsigned short": "u16", "bool": "bool", "_Bool": "bool",
    "void *": "*mut c_void", "void*": "*mut c_void",
}


class Generator:
    def __init__(self, name, with_c_bodies=False):
        self.name = name
        self.with_c_bodies = with_c_bodies
        self.cpath = os.path.join(C_PROGS, name + ".c")
        opath = os.path.join(C_OBJS, name + ".bpf.o")
        if os.path.exists(opath + ".corig"):
            opath = opath + ".corig"
        if not os.path.exists(self.cpath):
            raise Unsupported("no C source")
        if not os.path.exists(opath):
            raise Unsupported("no C object")
        self.obj = CObject(opath)
        self.errors = []
        self.funcs = []
        self.n_asm = 0              # asm statements using %= seen, in source order
        self.map_names, self.global_names, self.extern_names = [], [], []
        self.ksym_vars = []
        self.needs_cvoid = False
        self.hand = None
        self.stats = {}

    def count(self, key, n=1):
        self.stats[key] = self.stats.get(key, 0) + n

    # -- C source
    def parse(self):
        text = preprocess(self.cpath)
        with open(self.cpath) as fh:
            self.raw = fh.read()
        items = split_items(text)
        # BPF_PROG(name, ...) puts SEC() on a declaration of `name`, ahead
        # of the definition the macro writes without it
        declared = {}
        for head, body in items:
            if body is None and "section" in head and is_func_header(head):
                try:
                    d = parse_function(head, "")
                except Unsupported:
                    continue
                if d.section:
                    declared[d.name] = d
        for head, body in items:
            if body is None:
                continue
            f = parse_function(head, body)
            d = declared.get(f.name)
            if d is not None:
                if f.section is None:
                    f.section = d.section
                if "typeof(" in f.rtype and d.rtype in C_RETURN_TYPES:
                    f.rtype = d.rtype      # `int BPF_PROG(name, ...)`
            if f.naked:
                # AsmPrinter::PrintSpecial bumps its counter once per asm
                # statement that expands a `%=` (${:uid}), from 0
                if "%=" in body:
                    f.asm_index = self.n_asm
                    self.n_asm += 1
                self.funcs.append(f)
            elif self.root_statements(f):
                self.n_asm += body.count("%=")
                self.funcs.append(f)
            elif self.with_c_bodies:
                if f.name not in self.obj.functions():
                    self.count("inlined")       # inlined away by clang
                    continue
                self.n_asm += body.count("%=")
                f.c_text = c_function_text(self.raw, f.name)
                self.funcs.append(f)
            else:
                self.errors.append(f"C body: {f.name}")
        if self.with_c_bodies:
            # a function the C object carries from an included header
            missing = set(self.obj.functions()) - {f.name for f in self.funcs}
            for path, htext in preprocess_files(self.cpath).items() if missing else []:
                if os.path.abspath(path) == os.path.abspath(self.cpath):
                    continue
                for head, body in split_items(htext):
                    if body is None or not is_func_header(head):
                        continue
                    try:
                        f = parse_function(head, body)
                    except Unsupported:
                        continue
                    if f.name not in missing or f.naked:
                        continue
                    with open(path) as fh:
                        f.c_text = c_function_text(fh.read(), f.name)
                    f.header = os.path.basename(path)
                    self.funcs.insert(0, f)      # included ahead of the source's own
                    missing.discard(f.name)
        if not any(f.naked for f in self.funcs) and not self.with_c_bodies:
            self.errors.append("no naked function")

    def resolve(self):
        entries, per_func = [], {}
        for f in self.funcs:
            if f.root:
                continue
            if not f.naked:
                try:
                    f.rust_params = self.btf_params(f) or self.params(f)
                except Unsupported:
                    f.rust_params = [f"_todo: () /* {f.params} */"]
                if f.rtype not in C_RETURN_TYPES:
                    f.rtype = f"void /* {f.rtype} */"
                self.count("hand")
                continue
            try:
                template, ops = parse_asm(f)
            except Unsupported as e:
                self.errors.append(str(e))
                continue
            try:
                f.rust_params = self.params(f)
            except Unsupported as e:
                self.errors.append(str(e))
                continue
            if f.rtype not in C_RETURN_TYPES:
                self.errors.append(f"{f.name}: return type {f.rtype!r}")
                continue
            per_func[f.name] = (template, ops)
            for opname, constraint, expr in ops:
                if constraint == "i":
                    entries.append((f.name, opname, expr))
                elif constraint != "r":
                    self.errors.append(f"{f.name}: operand constraint {constraint!r}")
        if self.errors:
            return
        values = probe_operands(self.cpath, entries)
        resolved = {(fn, op): v for (fn, op, _e), v in zip(entries, values)}
        funcs = {f.name for f in self.funcs}
        for f in self.funcs:
            if not f.naked:
                continue
            template, ops = per_func[f.name]
            bindings, kinds = {}, {}
            for opname, constraint, expr in ops:
                if constraint == "i":
                    kind, value = resolved[(f.name, opname)]
                    if kind == "imm":
                        kinds[opname] = ("imm", str(value))
                        self.count("imm")
                    else:
                        # an operand named like a Rust keyword (`self`) is
                        # renamed with the function it names
                        key = rust_fn(opname)
                        kinds[opname] = ("sym", "{" + key + "}")
                        bindings[key] = f"sym {rust_fn(value) if value in funcs else value}"
                        self.count("sym")
                else:
                    m = re.fullmatch(r"&\s*([A-Za-z_]\w*)", expr)
                    if not m:
                        self.errors.append(f"{f.name}: register operand {expr!r}")
                        continue
                    target = m.group(1)
                    key = rust_fn(opname)
                    kinds[opname] = ("reg", "{" + key + "}")
                    if target in funcs:
                        bindings[key] = f"in(reg) {rust_fn(target)} as usize"
                    else:
                        bindings[key] = f"in(reg) core::ptr::addr_of!({target})"
                    self.count("reg")
            try:
                stmts = self.statements(f, template, kinds)
            except Unsupported as e:
                self.errors.append(str(e))
                continue
            # a function named in the asm text (`call subprog;`, `goto
            # subprog;`) is referenced through a sym operand, which is what
            # keeps a `__used` static alive through internalize/globaldce
            for i, s in enumerate(stmts):
                m = re.fullmatch(r"(call|goto|gotol|callx) ([A-Za-z_]\w*);", s) \
                    or re.fullmatch(r"(r\d = )([A-Za-z_]\w*) ll;", s) \
                    or re.fullmatch(r"(\.quad|\.8byte) ([A-Za-z_]\w*);", s)     # a table entry
                if m and m.group(2) in funcs:
                    target = rust_fn(m.group(2))
                    if target not in bindings:
                        bindings[target] = f"sym {target}"
                    sep = "" if m.group(1).endswith(" = ") else " "
                    tail = " ll;" if s.endswith(" ll;") else ";"
                    stmts[i] = f"{m.group(1)}{sep}{{{target}}}{tail}"
                    self.count("text-sym")
            f.stmts = stmts
            # C tolerates an operand the template never uses; asm! does not
            used = {m for st in stmts for m in re.findall(r"\{(\w+)\}", st)}
            f.operands = [(k, v) for k, v in bindings.items() if k in used]
            self.count("programs" if f.section else "subprogs")

    def btf_params(self, f):
        """A hand function's parameters as the C object's BTF prototype has
        them: exact types, a named struct collected into the file; a
        parameter the Rust cannot render becomes `*mut c_void`."""
        btf, types = self.obj.btf, self.obj.types
        func = next((t for t in btf.types.values() if t.kind == K_FUNC and t.name == f.name), None)
        if func is None:
            return None
        proto = btf.types[func.size]
        out = []
        for i, (pname, ptid) in enumerate(proto.extra):
            try:
                pt = btf.types[btf.strip(ptid)]
                pointee = btf.types[btf.strip(pt.size)] if pt.kind == K_PTR else None
                if f.static and pointee is not None and pointee.kind in (K_STRUCT, K_UNION) \
                        and btf.strip(pt.size) not in types.done \
                        and not types.local_like(btf.strip(pt.size)):
                    # a static function's BTF is not checked by the verifier:
                    # spare the file a kernel struct's whole definition
                    rtype = "*mut c_void"
                else:
                    rtype = types.rust(ptid)
            except Unsupported:
                rtype = "*mut c_void"
            if "c_void" in rtype:
                self.needs_cvoid = True
            out.append(f"_{pname or f'a{i}'}: {rtype}")
        return out

    def params(self, f):
        """A naked function's parameters, which its asm cannot name, as
        unused Rust parameters of the C types (a pointer as `*mut c_void`),
        so the BTF prototype keeps the C's parameter count."""
        out = []
        for p in split_top(f.params, ","):
            p = strip_attrs(p)[0]
            p = re.sub(r"\s+", " ", p).strip()
            if not p:
                continue
            m = re.fullmatch(r"(.*?)\s*\b([A-Za-z_]\w*)", p)
            if not m:
                raise Unsupported(f"{f.name}: parameter {p!r}")
            ctype, pname = m.group(1).strip(), m.group(2)
            if ctype.endswith("*"):
                rtype = "*mut c_void"
                self.needs_cvoid = True
            elif ctype in C_RETURN_TYPES and C_RETURN_TYPES[ctype]:
                rtype = C_RETURN_TYPES[ctype]
            else:
                raise Unsupported(f"{f.name}: parameter type {ctype!r}")
            out.append(f"_{pname}: {rtype}")
        return out

    def statements(self, f, template, kinds):
        t = re.sub(r"/\*.*?\*/", " ", template, flags=re.S)
        if "{" in t or "}" in t or "$" in t:
            raise Unsupported(f"{f.name}: brace or dollar in asm text")
        # `%=` is LLVM's per-module inline asm counter (${:uid}), bumped
        # per asm statement that uses it, in emission order: with the
        # functions kept in source order (BPF_PROGRAM_ORDER) the number is
        # clang's, so even an asm-defined symbol (a jump table) keeps its
        # C name
        t = t.replace("%%", "\x01").replace("%=", str(f.asm_index))

        def sub(m):
            if m.group(1) not in kinds:
                raise Unsupported(f"{f.name}: %[{m.group(1)}] is not an operand")
            return kinds[m.group(1)][1]
        t = re.sub(r"%\[(\w+)\]", sub, t)
        if "%" in t:
            raise Unsupported(f"{f.name}: unhandled % in asm text")
        t = t.replace("\x01", "%")
        out = []
        for piece in t.split(";"):
            piece = re.sub(r"\s+", " ", piece).strip()
            while True:
                m = re.match(r"([A-Za-z_]\w*|\d+):\s*(.*)$", piece)   # a label, numeric too
                if not m:
                    break
                out.append(m.group(1) + ":")
                piece = m.group(2)
            if piece:
                out.append(piece + ";")
        return out

    # -- maps / globals / externs from the C object
    def maps(self):
        btf, types, out = self.obj.btf, self.obj.types, []
        ds = btf.datasec(".maps")
        if ds is None:
            return out
        sec = self.obj.elf.section_by_name(".maps")
        rels = self.obj.elf.relocs.get(sec.idx, {}) if sec else {}
        for vtid, _voff, _vsize in ds.extra:
            var = btf.types[vtid]
            voff, vsize = self.obj.var_extent(".maps", var.name)
            slots = {off: r for off, r in rels.items() if voff <= off < voff + vsize}
            st = btf.types[btf.strip(var.size)]
            members, plain = [], True
            for mname, mtid, moff in st.extra:
                mt = btf.types[mtid]
                if mname == "values":
                    plain = False
                    if mt.kind != K_ARRAY or mt.extra[2] != 0:
                        raise Unsupported(f"map {var.name}: values is not a zero-length array")
                    et = btf.types[btf.strip(mt.extra[0])]
                    if et.kind != K_PTR:
                        raise Unsupported(f"map {var.name}: values element is not a pointer")
                    pt = btf.types[btf.strip(et.size)]
                    if pt.kind == K_FUNC_PROTO and slots:
                        # `.values = { [i] = (void *)&prog }`: the C object's
                        # storage holds one pointer per slot up to the last
                        # initialized one, relocated against the programs;
                        # scripts/btf_map_slots.py turns the Rust array
                        # back into libbpf's zero-length BTF array
                        n = (vsize - moff // 8) // 8
                        init = ["core::ptr::null()"] * n
                        for off, r in slots.items():
                            i = (off - voff - moff // 8) // 8
                            target = r.sym
                            if target.type == STT_SECTION:
                                imm = struct.unpack_from("<q", sec.data, off)[0]
                                target = self.obj.elf.named_symbol_at(target.shndx, imm)
                            if target is None or not target.name or i < 0 or i >= n:
                                raise Unsupported(f"map {var.name}: slot relocation")
                            init[i] = f"{rust_fn(target.name)} as {self.fn_type(target.name)} as *const c_void"
                            self.count("slots")
                        self.needs_cvoid = True
                        members.append((mname, f"[*const c_void; {n}]", "[" + ", ".join(init) + "]"))
                    elif pt.kind == K_STRUCT and slots:
                        # `.values = { &inner_map }`: the element type is
                        # the inner map's own definition (access_map_in_map.rs)
                        n = (vsize - moff // 8) // 8
                        init, inner = ["core::ptr::null()"] * n, None
                        for off, r in slots.items():
                            i = (off - voff - moff // 8) // 8
                            target = r.sym
                            if target.type == STT_SECTION:
                                imm = struct.unpack_from("<q", sec.data, off)[0]
                                target = self.obj.elf.named_symbol_at(target.shndx, imm)
                            if target is None or not target.name or i < 0 or i >= n:
                                raise Unsupported(f"map {var.name}: slot relocation")
                            if inner is None:
                                inner = target.name
                            elif inner != target.name:
                                raise Unsupported(f"map {var.name}: slots of different maps")
                            init[i] = f"&{target.name}"
                            self.count("slots")
                        if self.map_shape(pt) != self.map_shape(self.map_struct(inner)):
                            raise Unsupported(f"map {var.name}: inner definition differs from {inner}'s")
                        members.append((mname, f"[*const {inner}; {n}]", "[" + ", ".join(init) + "]"))
                    elif slots:
                        raise Unsupported(f"map {var.name}: statically initialized slots")
                    elif pt.kind == K_FUNC_PROTO:
                        members.append((mname, f"[{self.fn_proto(et.size)}; 0]", "[]"))
                    elif pt.kind == K_STRUCT:
                        inner = self.inner_def(var.name, et.size)
                        members.append((mname, f"[*const {inner}; 0]", "[]"))
                    else:
                        raise Unsupported(f"map {var.name}: values element kind {pt.kind}")
                    continue
                if mt.kind in (K_ENUM, K_ENUM64) and mt.vlen == 1:
                    # `__ulong(map_extra, v)`: an enum whose one enumerator is v
                    ename = f"{var.name}__{mname}"
                    value = mt.extra[0][1]
                    if mt.kind == K_ENUM and mt.kflag:
                        value = value - (1 << 32) if value >= 1 << 31 else value
                    self.obj.types.defs.append(
                        "#[allow(non_camel_case_types)]\n#[repr(u64)]\n"
                        f"enum {ename} {{\n    __unique_value = {value:#x},\n}}")
                    members.append((mname, ename, f"{ename}::__unique_value"))
                    plain = False
                    continue
                if mt.kind != K_PTR:
                    raise Unsupported(f"map {var.name}: member {mname} of BTF kind {mt.kind}")
                pointee = btf.types[btf.strip(mt.size)]
                if mname in ("key", "value"):
                    members.append((mname, f"*const {types.rust(mt.size)}", "core::ptr::null()"))
                elif pointee.kind == K_ARRAY and btf.types[btf.strip(pointee.extra[0])].kind == K_INT:
                    members.append((mname, f"*const [i32; {pointee.extra[2]}]", "core::ptr::null()"))
                else:
                    raise Unsupported(f"map {var.name}: member {mname} is not __uint/__type encoded")
            self.map_names.append(var.name)
            self.count("maps")
            if plain:
                body = "\n".join(f"        {ident(m)}: {ty}," for m, ty, _i in members)
                out.append(f"bpf_map! {{\n    {var.name} {{\n{body}\n    }}\n}}")
            else:
                decl = "\n".join(f"    {ident(m)}: {ty}," for m, ty, _i in members)
                init = "\n".join(f"    {ident(m)}: {i}," for m, _ty, i in members)
                out.append("#[allow(non_camel_case_types)]\n#[repr(C)]\n"
                           f"struct {var.name} {{\n{decl}\n}}\n"
                           f"unsafe impl Sync for {var.name} {{}}\n\n"
                           f'#[link_section = ".maps"]\n#[no_mangle]\n'
                           f"static {var.name}: {var.name} = {var.name} {{\n{init}\n}};")
        return out

    def map_struct(self, name):
        """The definition struct of the .maps variable `name`."""
        btf = self.obj.btf
        for vtid, _off, _size in btf.datasec(".maps").extra:
            var = btf.types[vtid]
            if var.name == name:
                return btf.types[btf.strip(var.size)]
        raise Unsupported(f"no map {name}")

    def map_shape(self, st):
        """(member name, pointee kind, array length) of a definition
        struct's __uint/__type members, the shape libbpf compares."""
        btf, out = self.obj.btf, []
        for mname, mtid, _off in st.extra:
            mt = btf.types[mtid]
            if mt.kind != K_PTR:
                continue
            pointee = btf.types[btf.strip(mt.size)]
            n = pointee.extra[2] if pointee.kind == K_ARRAY and mname not in ("key", "value") else None
            size = btf.types[btf.strip(mt.size)].size if mname in ("key", "value") else None
            out.append((mname, n, size))
        return out

    def fn_type(self, name):
        """The Rust fn type of one of the file's functions, for a cast."""
        f = next((f for f in self.funcs if f.name == name), None)
        if f is None:
            raise Unsupported(f"map slot names {name}, not a function of the source")
        ret = C_RETURN_TYPES[f.rtype]
        params = ", ".join(p.split(": ", 1)[1] for p in f.rust_params)
        return f'extern "C" fn({params})' + (f" -> {ret}" if ret else "")

    def inner_def(self, outer, ptr_tid):
        """The Rust struct for a map-in-map's inner definition."""
        btf, types = self.obj.btf, self.obj.types
        st = btf.types[btf.strip(ptr_tid)]
        name = f"{outer}__inner"
        fields = []
        for mname, mtid, _off in st.extra:
            mt = btf.types[mtid]
            if mt.kind != K_PTR:
                raise Unsupported(f"map {outer}: inner member {mname} of BTF kind {mt.kind}")
            pointee = btf.types[btf.strip(mt.size)]
            if mname in ("key", "value"):
                fields.append(f"    {ident(mname)}: *const {types.rust(mt.size)},")
            elif pointee.kind == K_ARRAY:
                fields.append(f"    {ident(mname)}: *const [i32; {pointee.extra[2]}],")
            else:
                raise Unsupported(f"map {outer}: inner member {mname}")
        self.obj.types.defs.append("#[allow(non_camel_case_types)]\n#[repr(C)]\n"
                                   f"struct {name} {{\n" + "\n".join(fields) + "\n}")
        return name

    def fn_proto(self, proto_tid):
        btf, types = self.obj.btf, self.obj.types
        t = btf.types[btf.strip(proto_tid)]
        params = ", ".join(self.param_type(p) for _n, p in t.extra)
        ret = "" if btf.strip(t.size) == 0 else " -> " + types.rust(t.size)
        return f'extern "C" fn({params}){ret}'

    def param_type(self, tid):
        btf, types = self.obj.btf, self.obj.types
        t = btf.types[btf.strip(tid)]
        if t.kind == K_PTR:
            self.needs_cvoid = True
            return "*mut c_void"
        return types.rust(tid)

    def struct_ops(self, ds):
        """A struct_ops map: the C's `SEC(".struct_ops") struct T v = {
        .op = (void *)prog, ... }`. libbpf relocates each set member (which
        must be a pointer to a function prototype in BTF) to its program and
        leaves the unset ones NULL; the kernel takes the value's type from
        its own BTF and only compares member kinds, so a set member carries
        the program's Rust fn type and an unset one is a null `*const c_void`
        (a raw pointer: not Sync, hence `static mut`)."""
        btf, types, elf, out = self.obj.btf, self.obj.types, self.obj.elf, []
        sec = elf.section_by_name(ds.name)
        for vtid, _voff, _vsize in ds.extra:
            var = btf.types[vtid]
            voff, vsize = self.obj.var_extent(ds.name, var.name)
            st = btf.types[btf.strip(var.size)]
            if st.kind != K_STRUCT or not st.name:
                raise Unsupported(f"{ds.name} {var.name}: not a named struct")
            data = sec.data[voff:voff + vsize] if sec and sec.data else b""
            data = data + b"\0" * (vsize - len(data))
            rels = {}
            for off, r in elf.relocs.get(sec.idx, {}).items() if sec else []:
                if voff <= off < voff + vsize:
                    target = r.sym
                    if target.type == STT_SECTION:
                        imm = struct.unpack_from("<q", sec.data, off)[0]
                        target = elf.named_symbol_at(target.shndx, imm)
                    if target is None or target.type != 2:
                        raise Unsupported(f"{var.name}: relocation against a non-function")
                    rels[off - voff] = target.name
            fields, inits = [], []
            for mname, mtid, moff in st.extra:
                mt, b = btf.types[btf.strip(mtid)], moff // 8
                if mt.kind == K_PTR and b in rels:
                    fields.append(f"    {ident(mname)}: {self.fn_type(rels[b])},")
                    inits.append(f"{ident(mname)}: {rust_fn(rels[b])}")
                elif mt.kind == K_PTR:
                    if any(data[b:b + 8]):
                        raise Unsupported(f"{var.name}.{mname}: non-null pointer without a relocation")
                    fields.append(f"    {ident(mname)}: *const c_void,")
                    inits.append(f"{ident(mname)}: core::ptr::null()")
                    self.needs_cvoid = True
                else:
                    fields.append(f"    {ident(mname)}: {types.rust(mtid)},")
                    inits.append(f"{ident(mname)}: {types.literal(mtid, data[b:])}")
            types.defs.append("/// The C's struct_ops map value: the kernel's struct of this name.\n"
                              "#[allow(non_camel_case_types, non_snake_case)]\n#[repr(C)]\n"
                              f"struct {st.name} {{\n" + "\n".join(fields) + "\n}")
            out.append(f'#[link_section = "{ds.name}"]\n#[no_mangle]\n#[allow(non_upper_case_globals)]\n'
                       f"static mut {var.name}: {st.name} = {st.name} {{ " + ", ".join(inits) + " };")
            self.global_names.append(var.name)
            self.count("globals")
        return out

    def globals(self):
        btf, types, elf, out = self.obj.btf, self.obj.types, self.obj.elf, []
        for ds in btf.datasecs():
            if ds.name in (".maps", ".ksyms", ".kconfig", "license") or ds.name.startswith(".arena"):
                continue
            if ds.name.startswith(".struct_ops"):
                out += self.struct_ops(ds)
                continue
            if not re.match(r"^\.(data|bss|rodata|percpu|addr_space\.\d+)(\.|$)", ds.name):
                raise Unsupported(f"DATASEC {ds.name}")
            sec = elf.section_by_name(ds.name)
            for vtid, _voff, _vsize in ds.extra:
                var = btf.types[vtid]
                voff, vsize = self.obj.var_extent(ds.name, var.name)
                data = sec.data[voff:voff + vsize] if sec and sec.data else b""
                data = data + b"\0" * (vsize - len(data))
                ty = types.rust(var.size)
                rels = {}
                for off, r in elf.relocs.get(sec.idx, {}).items() if sec else []:
                    if voff <= off < voff + vsize:
                        target = r.sym
                        if target.type == STT_SECTION:
                            imm = struct.unpack_from("<q", sec.data, off)[0]
                            target = elf.named_symbol_at(target.shndx, imm)
                        if target is None or not target.name:
                            raise Unsupported(f"{var.name}: relocation against an unnamed symbol")
                        if target.type == 2:    # a function's address
                            rels[off - voff] = rust_fn(target.name)
                        else:
                            rels[off - voff] = f"core::ptr::addr_of!({target.name}) as *mut c_void"
                            self.needs_cvoid = True
                lit = types.literal(var.size, data, rels)
                attrs = []
                zero = not any(data)
                # rustc puts a read-only static with relocations (a table of
                # function pointers) in .data.rel.ro: name the C's section
                if ds.name not in (".data", ".bss", ".rodata") or (ds.name == ".data" and zero) \
                        or (ds.name == ".rodata" and rels):
                    attrs.append(f'#[link_section = "{ds.name}"]')
                attrs.append("#[no_mangle]")
                attrs.append("#[allow(non_upper_case_globals)]")    # the C's name
                mut = "" if ds.name.startswith(".rodata") else "mut "
                rname = var.name
                if not re.fullmatch(r"[A-Za-z_]\w*", var.name):
                    # a C function-local static (`fn.___fmt`): exported under
                    # its symbol name, spelled with underscores in Rust
                    rname = re.sub(r"\W", "_", var.name)
                    attrs = [a for a in attrs if a != "#[no_mangle]"] + [f'#[export_name = "{var.name}"]']
                if not mut and ("*mut " in ty or "*const " in ty):
                    # raw pointers are not Sync: a `static mut`, kept read-only
                    # by the explicit section
                    mut = "mut "
                    if not any(a.startswith("#[link_section") for a in attrs):
                        attrs.insert(0, f'#[link_section = "{ds.name}"]')
                out.append("\n".join(attrs) + f"\nstatic {mut}{rname}: {ty} = {lit};")
                if var.name in self.obj.hidden_symbols():
                    # the C's __hidden (STV_HIDDEN): libbpf then leaves the
                    # section's map unmapped (a global holding a spin lock
                    # cannot be mmapped); rustc has no visibility attribute,
                    # the assembler directive sets it on the symbol
                    out[-1] += f'\ncore::arch::global_asm!(".hidden {var.name}");'
                    self.needs_asm = True
                self.global_names.append(var.name)
                self.count("globals")
        return out

    def externs(self):
        btf, types, out = self.obj.btf, self.obj.types, []
        for kind, name, tid in self.obj.ksyms():
            if kind == K_VAR:
                # `extern const int x __ksym`: scripts/ksym_vars.py mirrors
                # the C object's declaration for a `// BTF_KSYM:` extern
                self.ksym_vars.append((name, types.rust(btf.types[tid].size)))
                self.count("ksym-vars")
                continue
            if kind != K_FUNC:
                raise Unsupported(f"ksym {name} of BTF kind {kind}")
            proto = btf.types[btf.types[tid].size]
            params = ", ".join(f"{ident(n) if n else f'a{i}'}: {self.param_type(p)}"
                               for i, (n, p) in enumerate(proto.extra))
            ret = "" if btf.strip(proto.size) == 0 else " -> " + self.param_type(proto.size)
            out.append(f"    fn {name}({params}){ret};")
            self.extern_names.append((name, proto))
            self.count("kfuncs")
        return out

    def root_statements(self, f):
        """The statements of a C function that only references kfuncs
        (`__kfunc_btf_root`, `kfunc_root`: a BTF prototype for each kfunc
        the asm calls, since llc emits one only for a real call or address
        load), as [("call", name, [args]) | ("ref", [names])], or None when
        the body is anything else."""
        kfuncs = {name for kind, name, _tid in self.obj.ksyms() if kind == K_FUNC}
        out = []
        for stmt in split_top(f.body, ";"):
            stmt = stmt.strip()
            if not stmt:
                continue
            m = re.fullmatch(r'(?:__asm__|asm)\s*(?:volatile|__volatile__)?\s*\(\s*""\s*:\s*:(.*)\)', stmt, re.S)
            if m:
                refs = []
                for item in split_top(m.group(1), ","):
                    mm = re.fullmatch(r'\s*"r"\s*\(\s*&\s*([A-Za-z_]\w*)\s*\)\s*', item)
                    if not mm or mm.group(1) not in kfuncs:
                        return None
                    refs.append(mm.group(1))
                out.append(("ref", refs))
                continue
            m = re.fullmatch(r"([A-Za-z_]\w*)\s*\((.*)\)", stmt, re.S)
            if not m or m.group(1) not in kfuncs:
                return None
            args = [re.sub(r"\s+", "", a) for a in split_top(m.group(2), ",")]
            if any(not re.fullmatch(r"\(*(?:\(void\*\))?0x?[0-9a-fA-F]*\)*", a) for a in args):
                return None
            out.append(("call", m.group(1), args))
        if not out or f.params or f.rtype != "void":
            return None
        f.root = out
        return True

    def kfunc_root(self, f):
        """Rust for a kfunc-reference function (root_statements)."""
        btf = self.obj.btf
        protos = dict(self.extern_names)
        calls = []
        for stmt in f.root:
            if stmt[0] == "ref":
                refs = [f"in(reg) {name} as usize" for name in stmt[1]]
                # asm! insists every operand appears in the template; a
                # comment is enough, the loads happen before the asm
                tmpl = "/* " + " ".join("{%d}" % i for i in range(len(refs))) + " */"
                calls.append(f'        core::arch::asm!("{tmpl}", ' + ", ".join(refs)
                             + ", options(nostack, preserves_flags));")
                self.count("root-refs", len(refs))
                continue
            _k, name, cargs = stmt
            args = []
            for arg, (_n, ptid) in zip(cargs, protos[name].extra):
                if btf.types[btf.strip(ptid)].kind == K_PTR:
                    args.append("core::ptr::null_mut()")
                else:
                    args.append(re.sub(r"[()]", "", arg))
            calls.append(f"        {name}({', '.join(args)});")
            self.count("root-calls")
        attrs = "#[no_mangle]\n" + ("" if f.section else "#[inline(never)]\n")
        return (f"// {f.name}: the C's reference to each kfunc the asm calls, for its\n"
                f"// BTF prototype (llc emits one only for a real call or address load).\n"
                + attrs + f'extern "C" fn {f.name}() {{\n    unsafe {{\n'
                + "\n".join(calls) + "\n    }\n}")

    # -- the file
    def generate(self):
        self.parse()
        if not self.errors:
            self.resolve()
        if self.errors:
            raise Unsupported("; ".join(self.errors))
        c_funcs = self.obj.functions()
        for f in self.funcs:
            if f.name not in c_funcs:
                raise Unsupported(f"{f.name}: not a function of the C object")
        ours = {f.name for f in self.funcs}
        missing = sorted(set(c_funcs) - ours)
        if missing:
            raise Unsupported(f"C object functions not in the source: {', '.join(missing)}")

        maps = self.maps()
        globs = self.globals()
        externs = self.externs()
        tags = self.obj.test_tags()
        known = set(self.map_names) | set(self.global_names) | {n for n, _p in self.extern_names} \
            | {n for n, _t in self.ksym_vars} | ours | {rust_fn(n) for n in ours}
        for f in self.funcs:
            for _op, binding in f.operands:
                target = re.sub(r"^(sym |in\(reg\) core::ptr::addr_of!\(|in\(reg\) )", "", binding)
                target = re.sub(r"[) ].*$", "", target)
                if target not in known:
                    raise Unsupported(f"{f.name}: operand refers to unknown symbol {target}")
        lic_sym, lic = self.obj.license()
        self.hand = self.hand_file()
        hand_text = self.hand[1] if self.hand else ""

        out = ["// SPDX-License-Identifier: GPL-2.0", "#![no_std]", "#![no_main]"]
        if any(f.naked for f in self.funcs) or "asm!" in hand_text:
            out += ["#![feature(asm_experimental_arch)]", "#![allow(named_asm_labels)]"]
        if any("as usize" in b for f in self.funcs for _o, b in f.operands) \
                or any(s[0] == "ref" for f in self.funcs if f.root for s in f.root) \
                or "as usize" in hand_text:
            out.append("#![allow(function_casts_as_integer)]")
        if "#[linkage" in hand_text:
            out.append("#![feature(linkage)]")
        out.append("")
        hand = [f.name for f in self.funcs if not f.naked and not f.root]
        out.append(f"// Translation of tools/testing/selftests/bpf/progs/{self.name}.c, GENERATED")
        if hand:
            out += ["// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the",
                    f"// function(s) with C bodies, translated by hand in progs/hand/{self.name}.rs",
                    "// (include!d below): " + ", ".join(hand) + ".",
                    "// Every other function in the C"]
        else:
            out.append("// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C")
        out += ["// source is `__naked` hand-written BPF asm, carried here verbatim as",
                "// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands",
                "// resolved the way clang resolves them (helper ids and constants as",
                "// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels",
                "// suffixed with the function's name, and the test_loader decl tags",
                "// mirrored verbatim from the C object. Regenerate with",
                f"// `scripts/naked_gen.py {self.name}` rather than editing by hand;",
                "// scripts/translint.py's naked-verbatim check compares the built object",
                "// with the C object instruction by instruction.", ""]
        uses = ["bpf_object"] if lic_sym == "_license" else []
        if any(m.startswith("bpf_map!") for m in maps):
            uses.append("bpf_map")
        if tags:
            uses.append("test_tags")
        if self.obj.arg_tags():
            uses.append("arg_tags")
        tag_owners = {re.search(r"^(?:struct|union|enum) (\w+)", d, re.M).group(1) for d in self.obj.types.defs}
        tag_owners |= set(re.findall(r"^(?:pub )?(?:struct|union) (\w+)", hand_text or "", re.M))
        if any((st in self.global_names if m == "" else
                st in tag_owners or (m == "ret" or m.isdigit()) and st in ours)
               for st, m, _t in self.obj.type_tags()):
            uses.append("btf_type_tags")
        # rustc emits functions sorted by name; keep the C's source order
        # in every section, .text included (scripts/program_order.py), so
        # even a pc-relative call to a subprogram encodes the same
        programs = [f.name for f in self.funcs]
        if len(programs) > 1:
            out.append("// BPF_PROGRAM_ORDER: " + " ".join(programs))
            out.append("")
        for name, _ty in self.ksym_vars:
            out.append(f"// BTF_KSYM: {name}")
        if self.ksym_vars:
            out.append("")
        if any(re.search(r"\b(?:__anon_type\d+|\w+__anon\d+)\b", d) for d in self.obj.types.defs):
            out += ["// the C's anonymous types, named here; scripts/btf_anon.py clears",
                    "// the names in the object's BTF", "// BTF_ANON", ""]
        # a `*mut c_void` parameter or member is the C's `void *`: BTF must
        # say void too (the kernel checks a global subprogram's `void *ctx
        # __arg_ctx`, say), where rustc's debug info names the c_void enum
        if any("c_void" in p for f in self.funcs if not f.naked for p in f.rust_params) \
                or re.search(r'extern "C" fn \w+\([^)]*\*(?:mut|const) c_void\b', hand_text or "") \
                or re.search(r"^\s+\w+: \*(?:mut|const) c_void,$", hand_text or "", re.M) \
                or any("c_void" in d for d in self.obj.types.defs) \
                or any("c_void" in m for m in maps) or any("c_void" in g for g in globs):
            out += ["// a `*mut c_void` is the C's `void *` in BTF (scripts/btf_rename.py)",
                    "// BTF_C_VOID: c_void", ""]
        # the Makefile reads marker lines from progs/<name>.rs only: carry
        # the hand file's over
        markers = re.findall(r"^// (?:(?:BTF_TYPE_ID|BTF_KSYM|BTF_WEAK_KFUNC|BTF_C_CHAR|RUSTC_OPT_LEVEL|BPF_NAKED): .*"
                             r"|translint: allow\(.*\))$", hand_text, re.M)
        markers = list(dict.fromkeys(markers))
        if markers:
            out += ["// (from the hand file)"] + markers + [""]
        if uses:
            out.append("use bpf_rs_core::{" + ", ".join(sorted(uses)) + "};")
        if hand and not (self.needs_cvoid or any("c_void" in m for m in maps)
                         or any("c_void" in d for d in self.obj.types.defs)):
            out.append("#[allow(unused_imports)]")   # for the hand file's sake
        if any("#[btf]" in d for d in self.obj.types.defs):
            out.append("use btf_macros::btf;")
        if self.needs_cvoid or hand or any("c_void" in d for d in self.obj.types.defs) \
                or any("c_void" in m for m in maps) or any("c_void" in g for g in globs):
            out.append("use core::ffi::c_void;")
        out.append("")

        # `// GEN_TAGS: name:` + `//     tag,` lines in the hand file replace
        # the C object's tags for one program (the hand file also carries the
        # `// translint: allow(test-tags:name)` that goes with it): the C
        # object was built for one BPF CPU version, and a test whose messages
        # count instructions carries `#if __BPF_CPU_VERSION__` branches
        overrides = {m.group(1): [ln[len("//     "):] for ln in m.group(2).splitlines()]
                     for m in re.finditer(r"^// GEN_TAGS: (\w+):\n((?://     .*\n)+)", hand_text, re.M)}
        if tags:
            out.append("test_tags! {")
            for f in self.funcs:
                if f.name in tags:
                    payloads = tags.pop(f.name)
                    if f.name in overrides:
                        out.append(f"    {f.name}:")      # GEN_TAGS, from the hand file
                        out += ["        " + ln for ln in overrides[f.name]]
                        continue
                    macros = [tag_macro(p, self.name) for p in payloads]
                    out.append(f"    {f.name}:")
                    out.append("        " + ",\n        ".join(macros) + ";")
            if tags:
                raise Unsupported(f"tags on functions not in the source: {', '.join(tags)}")
            out.append("}")
            out.append("")
        if self.obj.types.defs:
            out += ["// Map key/value types, shaped like the C object's BTF (the kernel",
                    "// checks some of them member by member, so no explicit padding).",
                    "// translint: allow(padding)"]
        # `__kptr` and friends on struct members, on the prototypes of this
        # file's functions and on its globals: btf_type_tags!
        # (scripts/btf_type_tags.py), for the types this file defines
        defined = {re.search(r"^(?:struct|union|enum) (\w+)", d, re.M).group(1) for d in self.obj.types.defs}
        defined |= set(re.findall(r"^(?:pub )?(?:struct|union) (\w+)", hand_text or "", re.M))
        type_tags = [(st, m, tag) for st, m, tag in self.obj.type_tags()
                     if (st in self.global_names if m == "" else
                         st in defined or (m == "ret" or m.isdigit()) and st in ours)]
        if type_tags:
            out.append("btf_type_tags! {")
            for st, m, tag in type_tags:
                out.append(f"    {st}.{m}: {tag};" if m else f"    {st}: {tag};")
            out.append("}")
            out.append("")
        arg_tags = self.obj.arg_tags()
        if arg_tags:
            out.append("arg_tags! {")
            for fn, tags in arg_tags.items():
                if fn not in ours:
                    raise Unsupported(f"parameter tags on {fn}, not a function of the source")
                out.append(f"    {fn}: " + ", ".join(f'{i}: {rust_str(tag)}' for i, tag in sorted(tags)) + ";")
            out.append("}")
            out.append("")
        # `// GEN_SKIP_TYPE: name` in the hand file: the hand file defines
        # that type itself (a CO-RE view of a kernel struct, say)
        skip = set(re.findall(r"^// GEN_SKIP_TYPE: (\w+)$", hand_text, re.M))
        defs = [d for d in self.obj.types.defs
                if re.search(r"^(?:struct|union|enum) (\w+)", d, re.M).group(1) not in skip]
        if skip:
            # a type reached only through a skipped one (the kernel structs
            # behind a CO-RE view's pointer) goes with it
            anchor = "\n".join([hand_text or ""] + maps + globs + externs
                                + [p for f in self.funcs for p in f.rust_params])
            while True:
                names = {re.search(r"^(?:struct|union|enum) (\w+)", d, re.M).group(1) for d in defs}
                text = anchor + "\n".join(defs)
                keep = []
                for d in defs:
                    n = re.search(r"^(?:struct|union|enum) (\w+)", d, re.M).group(1)
                    rest = text.replace(d, "")
                    if re.search(r"\b" + re.escape(n) + r"\b", rest):
                        keep.append(d)
                if len(keep) == len(defs):
                    break
                defs = keep
        for d in defs:
            out.append(d)
            out.append("")
        for m in maps:
            out.append(m)
            out.append("")
        for g in globs:
            out.append(g)
            out.append("")
        if externs or self.ksym_vars:
            out.append('extern "C" {')
            for name, ty in self.ksym_vars:
                out.append(f"    static {name}: {ty};")
            out += externs
            out.append("}")
            out.append("")
        for f in self.funcs:
            if f.naked or f.root:
                out.append(self.emit_function(f))
                out.append("")
        if self.hand:
            out.append(f'include!("hand/{self.name}.rs");')
            out.append("")
        if lic_sym == "_license":
            out.append(f'bpf_object!("{lic}");')
        elif lic_sym is None:
            out += ["// The C source declares no license.", "#[panic_handler]",
                    "fn panic(_: &core::panic::PanicInfo) -> ! {", "    loop {}", "}"]
        else:
            out += ["// The C source names its license global `" + lic_sym + "`; the symbol",
                    "// name must match for the keep-list, so bpf_object! is written out.",
                    '#[link_section = "license"]', "#[no_mangle]",
                    f"static {lic_sym}: [u8; {len(lic) + 1}] = *b\"{lic}\\0\";", "",
                    "#[panic_handler]", "fn panic(_: &core::panic::PanicInfo) -> ! {",
                    "    loop {}", "}"]
        return "\n".join(out) + "\n"

    def hand_file(self):
        """progs/hand/<name>.rs: the hand-translated C bodies, written with
        stubs when absent and never overwritten."""
        hand = [f for f in self.funcs if not f.naked and not f.root]
        if not hand:
            return None
        path = os.path.join(REPO, "progs", "hand", self.name + ".rs")
        if os.path.exists(path):
            with open(path) as fh:
                text = fh.read()
            missing = [f.name for f in hand if not re.search(r"\bfn " + rust_fn(f.name) + r"\b", text)]
            if missing:
                raise Unsupported(f"{os.path.relpath(path, REPO)} lacks {', '.join(missing)}")
            return path, text, False
        out = [f"// SPDX-License-Identifier: GPL-2.0",
               f"// The C bodies of tools/testing/selftests/bpf/progs/{self.name}.c, translated",
               f"// by hand; include!d by the generated progs/{self.name}.rs (scripts/naked_gen.py",
               "// --with-c-bodies writes this file once, with stubs, and never overwrites it).", ""]
        for f in hand:
            out.append(self.emit_hand(f))
            out.append("")
        text = "\n".join(out)
        return path, text, True

    def emit_hand(self, f):
        """A function with a C body: the C, and a stub to replace by hand."""
        ret = C_RETURN_TYPES.get(f.rtype, "")
        if "c_void" in ret:
            self.needs_cvoid = True
        where = f" (from {f.header})" if f.header else ""
        lines = [f"// HAND: {f.name} -- translate the C below{where} (see the file comment)"]
        lines += [("//   " + ln.replace("\t", "    ")).rstrip() for ln in f.c_text.splitlines()]
        if f.section:
            lines.append(f'#[link_section = "{f.section}"]')
        lines.append(fn_attrs(f.name))
        if not f.section:
            lines.append("#[inline(never)]")
        params = ", ".join(f.rust_params)
        lines.append(f'extern "C" fn {rust_fn(f.name)}({params}){" -> " + ret if ret else ""} {{')
        lines.append("    todo!()")
        lines.append("}")
        return "\n".join(lines)

    def emit_function(self, f):
        if f.root:
            return self.kfunc_root(f)
        if not f.naked:
            return self.emit_hand(f)
        lines = []
        if f.section:
            lines.append(f'#[link_section = "{f.section}"]')
        lines.append(fn_attrs(f.name))
        lines.append("#[inline(never)]")
        lines.append(f"// BPF_NAKED: {f.name}")
        ret = C_RETURN_TYPES[f.rtype]
        if "c_void" in ret:
            self.needs_cvoid = True
        params = ", ".join(f.rust_params)
        lines.append(f'extern "C" fn {rust_fn(f.name)}({params}){" -> " + ret if ret else ""} {{')
        if ret:
            lines.append(f"    let ret: {ret};")
        lines.append("    unsafe {")
        lines.append("        core::arch::asm!(")
        for s in f.stmts:
            lines.append(f"            {rust_str(s)},")
        for op, binding in f.operands:
            lines.append(f"            {op} = {binding},")
        # Not options(noreturn): the optimizer would infer `noreturn` for the
        # function and delete a Rust caller's code after `call` (a subprogram
        # returning a value to a hand-translated program). The function
        # returns what the asm left in r0 instead, an output the optimizer
        # cannot fold, and scripts/naked_abi.py turns the `ret` into
        # `unreachable`. With a register input, the C's clobber list decides
        # which register the input gets (clang's choice is the oracle).
        if ret:
            lines.append('            out("r0") ret,')
        if any(b.startswith("in(reg)") for _o, b in f.operands):
            for c in f.clobbers:
                if re.fullmatch(r"r[0-9]", c) and not (ret and c == "r0"):
                    lines.append(f'            out("{c}") _,')
        lines.append("            options(nostack)")
        lines += ["        );", "    }"]
        if ret:
            lines.append("    ret")
        lines.append("}")
        return "\n".join(lines)


def survey(names):
    rows, ok = [], 0
    for name in names:
        try:
            g = Generator(name)
            g.generate()
            ok += 1
            st = ", ".join(f"{k} {v}" for k, v in sorted(g.stats.items()))
            rows.append((name, "ok", st))
        except Unsupported as e:
            rows.append((name, "unsupported", str(e)))
    width = max(len(r[0]) for r in rows) if rows else 0
    for name, verdict, detail in rows:
        print(f"{name:<{width}}  {verdict:<11}  {detail}")
    print(f"\n{ok} of {len(rows)} generatable")
    reasons = {}
    for _n, verdict, detail in rows:
        if verdict != "ok":
            for part in detail.split("; "):
                key = re.sub(r"^[A-Za-z_0-9]+: ", "", part)
                key = re.sub(r"\b(map|struct) \w+:", r"\1 <x>:", key)
                reasons[key] = reasons.get(key, 0) + 1
    for key, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print(f"  {n:4d}  {key}")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("names", nargs="*")
    ap.add_argument("--survey", action="store_true")
    ap.add_argument("--stdout", action="store_true")
    ap.add_argument("--with-c-bodies", action="store_true",
                    help="emit a function with a C body as a stub to translate by hand")
    args = ap.parse_args(argv[1:])
    names = args.names
    if args.survey:
        if not names:
            names = sorted(f[:-2] for f in os.listdir(C_PROGS)
                           if f.startswith("verifier_") and f.endswith(".c"))
        return survey(names)
    if not names:
        ap.error("a selftest name is required")
    rc = 0
    for name in names:
        try:
            gen = Generator(name, args.with_c_bodies)
            text = gen.generate()
        except Unsupported as e:
            print(f"[naked_gen] {name}: unsupported: {e}", file=sys.stderr)
            rc = 1
            continue
        if args.stdout:
            sys.stdout.write(text)
            continue
        path = os.path.join(REPO, "progs", name + ".rs")
        with open(path, "w") as fh:
            fh.write(text)
        print(f"[naked_gen] wrote {os.path.relpath(path, REPO)}")
        if gen.hand and gen.hand[2]:
            os.makedirs(os.path.dirname(gen.hand[0]), exist_ok=True)
            with open(gen.hand[0], "w") as fh:
                fh.write(gen.hand[1])
            print(f"[naked_gen] wrote {os.path.relpath(gen.hand[0], REPO)}: translate its C bodies")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
