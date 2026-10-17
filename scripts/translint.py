#!/usr/bin/env python3
"""Translation linter: mechanical checks for the divergence classes the Z3
equivalence prover has caught in real translations (equiv/README.md's
"true findings"). Advisory WARN/NOTE lines plus hard ERRORs; exit 1 iff
any ERROR.

Classes checked (suppress per file with `// translint: allow(<class>)`):

  program-set    [ERROR] the compiled objects must define the same set of
                 programs (GLOBAL FUNC symbols outside .text, i.e. every
                 SEC()'d entry point). A program the C object has and the
                 translation lacks is missing from the skeleton, so the
                 prog_test does not even compile; an extra one changes what
                 the loader loads. Global subprograms in .text are not
                 compared (the translation may inline them).
  test-tags      [ERROR] the C object's test_loader decl tags (__failure /
                 __msg / ...) must be mirrored by a test_tags! declaration,
                 which scripts/btf_test_tags.py appends to the built object.
                 A message may relax ONLY register/stack-slot/insn-index
                 tokens, via the matcher's own {{regex}} brackets, and name
                 the translation's source file where the C names its own
                 ("<func> @ verifier_cfg.rs"); anything else diverging from
                 the C tag is an error.
  decl-tags      [ERROR] the C object's other BTF decl tags must be on the
                 same declaration in the Rust object: `contains:` (the
                 node type of a bpf_rb_root / bpf_list_head) and
                 `exception_callback:` change what the kernel accepts, so a
                 missing one is an ERROR; `arg:*` and free-form tags are a
                 WARN. Rust emits them with rust-bpf's #[btf_tag].
  naked-verbatim [ERROR] a `// BPF_NAKED:` function (raw asm carried over
                 from a `__naked` C program, scripts/naked_abi.py) must
                 compile to the C object's instruction stream in the C
                 object's section: the same bytes, with relocations
                 against the same symbols (scripts/naked_verbatim.py).
  private-layout [ERROR] a C `private(X)` section (`.data.X` / `.bss.X`,
                 __hidden statics) must hold the same variables at the same
                 offsets in the Rust object. The verifier names a lock by
                 its offset ("bpf_spin_lock at off=32 must be held") and
                 the proof compares the offsets the programs use.
                 scripts/private_sections.py copies the C object's layout
                 (clang's first-use order, not the declaration order), so
                 a difference means a static is missing, has another size
                 or alignment, or the C object changed.
  printk-count   [ERROR] C and Rust must have the same number of trace-log
                 call sites (bpf_printk / log_err / bpf_trace_printk):
                 dropped logging was 62 real INEQUIV sites.
  bool-global    [ERROR] `static mut x: bool` — clang compiles `if (_Bool)`
                 as `jne 0` at some sites and `jne 1` at others, even
                 within one file. Store u8 and mirror each site's compare
                 (disassemble the C object to pick it).
  big-hex        [WARN]  hex literal that doesn't fit in i32: in C it types
                 as UNSIGNED int and arithmetic wraps at 32 bits before
                 widening (0xabcd1234 + cnt class). Mirror with u32
                 wrapping ops.
  padding        [WARN]  #[repr(C)] struct with implicit padding: C's `= {}`
                 zeroes padding, a Rust literal doesn't — make padding an
                 explicit `_pad: [u8; N]` field if the struct reaches a map
                 or trace observable.
  ptr-scaling    [NOTE]  C source does pointer arithmetic with sizeof or
                 `ptr += n`: remember C scales by the ELEMENT size
                 (`tuple + sizeof *tuple` = +1296 bytes, `sk += 1` = +80).
  narrow-cast    [NOTE]  helper-returned pointer cast to a width — check it
                 matches the C pointee type (a u32 store through C's
                 __u64* left residue in a map value).
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "equiv"))
import paths  # noqa: E402

# The C side is the QEMU flavor: the kernel worktree pinned by kernel-commit
# and the objects built from it.
C_PROGS = os.path.join(paths.SELFTESTS_SRC, "progs")
C_OBJ_DIR = paths.SELFTESTS_OUTPUT

sys.path.insert(0, os.path.join(REPO, "scripts"))
from bpfelf import BpfElf, SHF_EXECINSTR
import btf_test_tags
import naked_verbatim

SIZES = {"u8": 1, "i8": 1, "u16": 2, "i16": 2, "u32": 4, "i32": 4,
         "u64": 8, "i64": 8, "usize": 8, "isize": 8, "bool": 1, "f32": 4,
         "f64": 8}


def field_size_align(ty):
    ty = ty.strip()
    m = re.fullmatch(r"\[([a-z0-9]+);\s*(\d+)\]", ty)
    if m and m.group(1) in SIZES:
        s = SIZES[m.group(1)]
        return s * int(m.group(2)), s
    if ty in SIZES:
        return SIZES[ty], SIZES[ty]
    if ty.startswith(("*const", "*mut")):
        return 8, 8
    return None, None


def check_padding(src):
    """Yield (struct name, offset, pad bytes) for repr(C) structs with
    implicit padding between sized fields."""
    for m in re.finditer(
            r"#\[repr\(C(?:,\s*packed)?\)\]\s*(?:pub\s+)?struct\s+(\w+)\s*\{([^}]*)\}",
            src, re.DOTALL):
        if "packed" in m.group(0).split("]")[0]:
            continue
        name, body = m.group(1), m.group(2)
        off, maxal, unknown = 0, 1, False
        pads = []
        for fm in re.finditer(r"(?:pub\s+)?(\w+)\s*:\s*([^,\n]+),?", body):
            fname, ty = fm.group(1), fm.group(2)
            size, al = field_size_align(ty)
            if size is None:
                unknown = True
                break
            if off % al:
                if not fname.startswith("_pad"):
                    pads.append((name, off, al - off % al, fname))
                off += al - off % al
            off += size
            maxal = max(maxal, al)
        if not unknown and off % maxal:
            pads.append((name, off, maxal - off % maxal, "<tail>"))
        for p in pads:
            yield p


def count_trace_printk(obj_path):
    """Count bpf_trace_printk (helper 6) / trace_vprintk (177) call sites in
    a compiled .bpf.o — exact, unlike source counting which includes
    #ifdef'd-out debug prints."""
    if not os.path.exists(obj_path):
        return None
    try:
        elf = BpfElf(obj_path)
    except Exception:
        return None
    n = 0
    for s in elf.sections:
        if not (s.flags & SHF_EXECINSTR) or not s.data:
            continue
        d = s.data
        for i in range(len(d) // 8):
            if d[i * 8] == 0x85 and d[i * 8 + 1] == 0:  # call helper
                imm = int.from_bytes(d[i * 8 + 4:i * 8 + 8], "little",
                                     signed=True)
                if imm in (6, 177):
                    n += 1
    return n


def c_test_tags(obj_path):
    """Program name -> [decl tag payload, ...] from a compiled object's BTF,
    in the loader's own order. None when the object can't be read."""
    if not os.path.exists(obj_path):
        return None
    try:
        elf = BpfElf(obj_path)
        types = elf.btf_types()
    except Exception:
        return None
    funcs = {tid: t[1] for tid, t in types.items() if t[0] == 12}
    out = {}
    for _tid, (kind, tname, target, _vlen, _extra) in types.items():
        if kind == 17 and target in funcs and tname.startswith("comment:"):
            out.setdefault(funcs[target], []).append(tname)
    for fn in out:
        # test_loader sorts with strverscmp, which compares the __COUNTER__
        # run numerically; sorting by the parsed counter is the same order.
        out[fn] = [re.sub(r"^comment:\d+:", "", t) for t in
                   sorted(out[fn], key=lambda s: int(s.split(":")[1]))]
    return out


# Tokens of a verifier log line that depend on register allocation and stack
# layout, i.e. the only things a translation may relax with the matcher's own
# {{regex}} brackets. Everything else in the message is the assertion.
CODEGEN_TOKENS = [
    (re.compile(r"\{\{[^}]*\}\}"), "<X>"),   # an explicit relaxation
    (re.compile(r"\bR\d+\b"), "<X>"),        # R1, R2, ...
    (re.compile(r"\bfp-\d+\b"), "<X>"),      # stack slots
    (re.compile(r"\boff=-?\d+\b"), "<X>"),
    (re.compile(r"\binsn \d+\b"), "insn <X>"),
    # "<func> @ <file>.c": the source file of the line info is the .rs
    (re.compile(r" @ (\w+)\.(?:c|rs)\b"), r" @ \1.<src>"),
    (re.compile(r"processed \d+ insns"), "processed <X> insns"),
]


def normalize_msg(s):
    for pat, repl in CODEGEN_TOKENS:
        s = pat.sub(repl, s)
    return s


def program_names(elf):
    """Names of the SEC()'d programs in a parsed object: GLOBAL FUNC symbols
    defined outside .text (where global subprograms live)."""
    text_idx = next((s.idx for s in elf.sections if s.name == ".text"), -1)
    return {s.name for s in elf.symbols
            if s.type == 2 and s.bind == 1 and s.shndx not in (0, text_idx)
            and s.shndx < len(elf.sections)}


def program_set(obj_path):
    """program_names() of a compiled object; None when it can't be read."""
    if not os.path.exists(obj_path):
        return None
    try:
        return program_names(BpfElf(obj_path))
    except Exception:
        return None


def check_program_set(name):
    c_obj = os.path.join(C_OBJ_DIR, f"{name}.bpf.o")
    if os.path.exists(c_obj + ".corig"):
        c_obj = c_obj + ".corig"
    want = program_set(c_obj)
    got = program_set(os.path.join(REPO, "bld", f"{name}.bpf.o"))
    if want is None or got is None:
        return
    missing, extra = sorted(want - got), sorted(got - want)
    if missing:
        yield ("ERROR", f"C object defines program(s) the translation "
                        f"lacks: {', '.join(missing)}")
    if extra:
        yield ("ERROR", f"translation defines program(s) the C object "
                        f"does not: {', '.join(extra)}")


def check_test_tags(name, rs_raw):
    """The C object's decl tags are the ground truth for what the loader must
    assert. Yield (level, text) for any divergence."""
    obj = os.path.join(C_OBJ_DIR, f"{name}.bpf.o")
    if os.path.exists(obj + ".corig"):
        obj = obj + ".corig"           # pristine C, even mid-swap
    c_tags = c_test_tags(obj)
    if c_tags is None:
        return
    try:
        declared = dict(btf_test_tags.parse_source(
            os.path.join(REPO, "progs", f"{name}.rs")))
    except btf_test_tags.TagError as e:
        yield "ERROR", f"test_tags! does not parse: {e}"
        return

    if c_tags and not declared:
        kinds = sorted({t.split("=")[0] for tl in c_tags.values() for t in tl})
        # A dropped __failure INVERTS the test: the loader defaults to
        # expect-success (test_loader.c:parse_test_spec), so a translation the
        # verifier rejects for exactly the right reason is reported as a pass.
        # Dropping only positive tags (__retval, __xlated, __auxiliary, ...)
        # doesn't invert anything, it just tests the translation more weakly
        # than the C object is tested.
        inverts = any(k.startswith("test_expect_failure") for k in kinds)
        yield ("ERROR" if inverts else "WARN",
               f"the C object carries test_loader decl tags ({', '.join(kinds)}) "
               f"but this translation declares no test_tags! — "
               + ("without them the loader defaults to expect-success and the "
                  "test inverts" if inverts else
                  "those assertions are not being made against the translation"))
        return
    if declared and not c_tags:
        yield ("ERROR",
               "test_tags! is declared but the C object carries none")
        return

    for fn in sorted(set(c_tags) | set(declared)):
        want, got = c_tags.get(fn, []), declared.get(fn, [])
        if not want:
            yield "ERROR", f"{fn}: declares tags the C object does not have"
            continue
        if not got:
            yield "ERROR", f"{fn}: C object tags this program, translation does not"
            continue
        if len(want) != len(got):
            yield ("ERROR",
                   f"{fn}: {len(got)} tag(s) declared, C object has {len(want)}")
            continue
        for w, g in zip(want, got):
            if w == g:
                continue
            if normalize_msg(w) == normalize_msg(g):
                yield ("NOTE",
                       f"{fn}: relaxed {w!r} -> {g!r} (codegen-dependent "
                       f"tokens only)")
                continue
            yield ("ERROR",
                   f"{fn}: declared tag {g!r} diverges from the C object's "
                   f"{w!r} beyond register/offset relaxation")


# Decl tags the kernel acts on: without them it rejects the object, or (an
# exception callback) runs a different program. The rest only weaken a test.
LOAD_BEARING_TAGS = ("contains:", "exception_callback:")


def plain_var_name(name):
    """A private Rust static keeps its v0-mangled symbol name in BTF
    (`_RNvCs..._16linked_list_peek5ghead` for C's `__hidden` `ghead`);
    the kernel finds graph roots by the tag on the variable, never by its
    name, so compare by the trailing identifier."""
    if not name.startswith("_R"):
        return name
    for m in re.finditer(r"\d+", name):
        n = int(m.group())
        if m.end() + n == len(name):
            ident = name[m.end():]
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", ident):
                return ident
    return name


def decl_tags(obj_path):
    """The non-test_loader decl tags of a compiled object, as a set of
    (target kind, target name, component, payload). The component is the
    member name for a struct/union member, the parameter index for a function
    parameter, else None. None when the object can't be read."""
    if not os.path.exists(obj_path):
        return None
    try:
        types = BpfElf(obj_path).btf_types()
    except Exception:
        return None
    kinds = {4: "struct", 5: "union", 8: "typedef", 12: "func", 14: "var"}
    out = set()
    for kind, payload, target, _vlen, comp in types.values():
        if kind != 17 or payload.startswith("comment:"):
            continue
        tkind, tname, _t, _v, members = types[target]
        what = kinds.get(tkind, f"kind{tkind}")
        if tkind == 14:
            tname = plain_var_name(tname)
        if comp < 0:
            comp = None
        elif tkind in (4, 5):
            comp = members[comp][0]
        out.add((what, tname, comp, payload))
    return out


def check_decl_tags(name):
    c_obj = os.path.join(C_OBJ_DIR, f"{name}.bpf.o")
    if os.path.exists(c_obj + ".corig"):
        c_obj = c_obj + ".corig"
    want = decl_tags(c_obj)
    got = decl_tags(os.path.join(REPO, "bld", f"{name}.bpf.o"))
    if want is None or got is None:
        return

    def where(t):
        what, tname, comp, _payload = t
        if comp is None:
            return f"{what} {tname}"
        if what == "func":
            return f"func {tname} parameter {comp}"
        return f"{what} {tname}.{comp}"

    missing, extra = want - got, got - want
    # An anonymous C struct/union (bpf_obj_new(struct { ... }) in a
    # negative test) has a NAMED Rust stand-in (scripts/type_id.py's
    # `(anonymous)`): a tag on the anonymous C type is matched by the same
    # tag on the same member of a Rust type the C object does not have.
    c_names = {t[1] for t in want}
    for t in sorted(missing, key=str):
        if t[0] not in ("struct", "union") or t[1]:
            continue
        for u in sorted(extra, key=str):
            if (u[0], u[2], u[3]) == (t[0], t[2], t[3]) and u[1] not in c_names:
                missing.discard(t)
                extra.discard(u)
                break
    for t in sorted(missing, key=str):
        level = "ERROR" if t[3].startswith(LOAD_BEARING_TAGS) else "WARN"
        yield (level, f"C object tags {where(t)} with {t[3]!r}, the "
                      f"translation does not")
    for t in sorted(extra, key=str):
        yield ("ERROR", f"translation tags {where(t)} with {t[3]!r}, the "
                        f"C object does not")


PRIVATE_SECTION = re.compile(r"^\.(data|bss)\.[A-Za-z_][A-Za-z0-9_]*$")


def private_layout(obj_path):
    """Section name -> [(plain variable name, offset, size)] by offset for
    every `.data.X` / `.bss.X` section of a compiled object. None when the
    object can't be read."""
    if not os.path.exists(obj_path):
        return None
    try:
        elf = BpfElf(obj_path)
    except Exception:
        return None
    out = {}
    for sec in elf.sections:
        if PRIVATE_SECTION.match(sec.name):
            out[sec.name] = []
    for sym in elf.symbols:
        if sym.type != 1 or sym.shndx >= len(elf.sections):
            continue
        sec = elf.sections[sym.shndx]
        if sec.name not in out:
            continue
        # rustc may suffix a static's symbol (`...3ref.0`)
        name = plain_var_name(re.sub(r"\.\d+$", "", sym.name))
        out[sec.name].append((name, sym.value, sym.size))
    return {k: sorted(v, key=lambda t: t[1]) for k, v in out.items()}


def check_private_layout(name):
    c_obj = os.path.join(C_OBJ_DIR, f"{name}.bpf.o")
    if os.path.exists(c_obj + ".corig"):
        c_obj = c_obj + ".corig"
    want = private_layout(c_obj)
    got = private_layout(os.path.join(REPO, "bld", f"{name}.bpf.o"))
    if want is None or got is None:
        return

    def show(layout):
        return ", ".join(f"{n}@{off}+{sz}" for n, off, sz in layout) or "(empty)"

    for sec in sorted(set(want) | set(got)):
        if sec not in got:
            yield ("ERROR", f"C object has section {sec} ({show(want[sec])}), "
                            f"the translation does not")
        elif sec not in want:
            yield ("ERROR", f"translation has section {sec} ({show(got[sec])}), "
                            f"the C object does not")
        elif want[sec] != got[sec]:
            yield ("ERROR", f"{sec} layout differs: C {show(want[sec])}; "
                            f"Rust {show(got[sec])} (a static missing, of "
                            f"another size, or more aligned than C's)")


def check_naked_verbatim(name, rs_raw):
    names = re.findall(r"^// BPF_NAKED: ([A-Za-z_][A-Za-z_0-9]*)\s*$", rs_raw, re.M)
    if not names:
        return
    c_obj = os.path.join(C_OBJ_DIR, f"{name}.bpf.o")
    if os.path.exists(c_obj + ".corig"):
        c_obj = c_obj + ".corig"
    r_obj = os.path.join(REPO, "bld", f"{name}.bpf.o")
    if not os.path.exists(c_obj) or not os.path.exists(r_obj):
        return
    try:
        c_elf, r_elf = BpfElf(c_obj), BpfElf(r_obj)
    except Exception:
        return
    for fn in names:
        for d in naked_verbatim.compare(c_elf, r_elf, fn):
            yield "ERROR", d


def lint(name):
    rs_path = os.path.join(REPO, "progs", f"{name}.rs")
    c_path = os.path.join(C_PROGS, f"{name}.c")
    rs_raw = open(rs_path).read()
    allowed = set(re.findall(r"//\s*translint:\s*allow\((\S+)\)", rs_raw))
    # blank out comments (preserving newlines so line numbers stay valid)
    # so a `==` or field name in prose can't count as a code use
    rs = re.sub(r"//[^\n]*", "", rs_raw)
    rs = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)),
                rs, flags=re.DOTALL)
    c = open(c_path).read() if os.path.exists(c_path) else None
    msgs = []

    def emit(level, cls, text):
        if cls not in allowed:
            msgs.append((level, cls, text))

    for level, text in check_program_set(name):
        emit(level, "program-set", text)
    for level, text in check_test_tags(name, rs_raw):
        emit(level, "test-tags", text)
    for level, text in check_decl_tags(name):
        emit(level, "decl-tags", text)
    for level, text in check_private_layout(name):
        emit(level, "private-layout", text)
    for level, text in check_naked_verbatim(name, rs_raw):
        emit(level, "naked-verbatim", text)

    # bool-global: only an error when the BPF side BRANCHES on it (reads);
    # write-only status flags (data.skip = true) store 1 identically in
    # both languages and are benign
    for m in re.finditer(r"static\s+mut\s+(\w+)\s*:\s*bool", rs):
        nm = m.group(1)
        reads = re.search(
            rf"(?:if[^;{{\n]*|!\s*|==[^;\n]*|!=[^;\n]*)\b{nm}\b"
            rf"|\b{nm}\b\s*(?:==|!=|\}})", rs)
        writes_only = re.search(rf"\b{nm}\b\s*=\s*(?:true|false)", rs)
        if reads:
            emit("ERROR", "bool-global",
                 f"`static mut {nm}: bool` is branched on — use u8 and "
                 f"mirror the C object's byte compare (jne 0 vs jne 1 "
                 f"varies per site)")
        elif writes_only:
            emit("NOTE", "bool-global",
                 f"`static mut {nm}: bool` is write-only (benign)")

    # big-hex (skip u32/u64-suffixed or _u32-typed const lines; flag bare)
    for m in re.finditer(r"0x[89a-fA-F][0-9a-fA-F]{7}\b(?!_?u)", rs):
        line = rs[:m.start()].count("\n") + 1
        ctx = rs.splitlines()[line - 1].strip()
        if re.search(r":\s*u(32|64)\b|as u(32|64)\b|wrapping_", ctx):
            continue
        if rs[rs.rfind("\n", 0, m.start()) + 1:m.start()].count('"') % 2:
            continue                      # inside a string: raw asm text
        emit("WARN", "big-hex",
             f"line {line}: literal {m.group(0)} doesn't fit i32 — C types "
             f"it UNSIGNED int; arithmetic wraps at 32 bits ({ctx[:60]})")

    # padding
    for sname, off, n, before in check_padding(rs):
        emit("WARN", "padding",
             f"struct {sname}: {n} implicit padding byte(s) at offset {off} "
             f"(before {before}) — C's `= {{}}` zeroes padding, a Rust "
             f"literal doesn't; add explicit `_pad: [u8; {n}]`")

    # narrow-cast
    for m in re.finditer(r"as \*mut u(8|16|32)\b", rs):
        line = rs[:m.start()].count("\n") + 1
        emit("NOTE", "narrow-cast",
             f"line {line}: pointer cast to *mut u{m.group(1)} — confirm "
             f"the C pointee width matches (u32 store via __u64* class)")

    if c is not None:
        # printk-count from the COMPILED objects (exact; source counting
        # would include #ifdef DEBUG prints absent from the build). A
        # dropped trace_printk diverges the trace observable.
        c_obj = os.path.join(C_OBJ_DIR, f"{name}.bpf.o")
        r_obj = os.path.join(REPO, "bld", f"{name}.bpf.o")
        nc, nr = count_trace_printk(c_obj), count_trace_printk(r_obj)
        if nc is not None and nr is not None and nc != nr:
            level = "ERROR" if nr < nc else "NOTE"
            emit(level, "printk-count",
                 f"compiled C object has {nc} bpf_trace_printk call(s), "
                 f"Rust has {nr} — {'dropped' if nr < nc else 'extra'} "
                 f"logging changes the trace observable")
        # ptr-scaling
        hits = [ln + 1 for ln, line in enumerate(c.splitlines())
                if re.search(r"\+\s*sizeof\b|\bsizeof\s*\*|\w+\s*\+=\s*1\s*;",
                             line)]
        if hits:
            emit("NOTE", "ptr-scaling",
                 f"C lines {hits[:8]} do sizeof/increment arithmetic — if "
                 f"on a pointer, C scales by the element size")
    return msgs


def main():
    names = sys.argv[1:]
    if not names:
        names = sorted(f[:-3] for f in os.listdir(os.path.join(REPO, "progs"))
                       if f.endswith(".rs"))
    n_err = n_warn = 0
    for name in names:
        msgs = lint(name)
        errs = [m for m in msgs if m[0] == "ERROR"]
        warns = [m for m in msgs if m[0] == "WARN"]
        n_err += len(errs)
        n_warn += len(warns)
        if msgs:
            print(f"== {name}")
            for level, cls, text in msgs:
                print(f"  {level:5s} [{cls}] {text}")
    print(f"\n{n_err} error(s), {n_warn} warning(s) across {len(names)} "
          f"translation(s)")
    return 1 if n_err else 0


if __name__ == "__main__":
    sys.exit(main())
