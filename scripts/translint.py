#!/usr/bin/env python3
"""Translation linter: mechanical checks for the divergence classes the Z3
equivalence prover has caught in real translations (equiv/README.md's
"true findings"). Advisory WARN/NOTE lines plus hard ERRORs; exit 1 iff
any ERROR.

Classes checked (suppress per file with `// translint: allow(<class>)`):

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
from bpfelf import BpfElf, SHF_EXECINSTR

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
