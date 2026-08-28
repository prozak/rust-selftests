#!/usr/bin/env python3
"""Translation linter: mechanical checks for the divergence classes the Z3
equivalence prover has caught in real translations (equiv/README.md's
"true findings"). Advisory WARN/NOTE lines plus hard ERRORs; exit 1 iff
any ERROR.

Classes checked (suppress per file with `// translint: allow(<class>)`):

  test-tags      [ERROR] the C object's test_loader decl tags (__failure /
                 __msg / ...) must be mirrored by a test_tags! declaration,
                 which scripts/btf_test_tags.py appends to the built object.
                 A message may relax ONLY register/stack-slot/insn-index
                 tokens, via the matcher's own {{regex}} brackets; anything
                 else diverging from the C tag is an error.
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
C_PROGS = os.path.join(REPO, "..", "uml-harness", ".build", "bpf-next",
                       "tools", "testing", "selftests", "bpf", "progs")
C_OBJ_DIR = os.path.join(REPO, "..", "uml-harness", ".build",
                         "selftests-output-qemu")

sys.path.insert(0, os.path.join(REPO, "equiv"))
sys.path.insert(0, os.path.join(REPO, "scripts"))
from bpfelf import BpfElf, SHF_EXECINSTR
import btf_test_tags

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
    (re.compile(r"processed \d+ insns"), "processed <X> insns"),
]


def normalize_msg(s):
    for pat, repl in CODEGEN_TOKENS:
        s = pat.sub(repl, s)
    return s


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

    for level, text in check_test_tags(name, rs_raw):
        emit(level, "test-tags", text)

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
