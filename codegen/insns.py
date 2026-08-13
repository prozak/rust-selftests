"""BPF instruction decoding and codegen metrics.

This is a CODEGEN study, not a semantics one: what does rustc emit where
clang emits something else, and which of those differences are worth
fixing in the rust-bpf pipeline. The unit of comparison is a program whose
two builds the equivalence checker has already PROVED equivalent, so any
difference counted here is the compiler's doing and not the translation's.
"""
import struct

# BPF_CLASS(op) = op & 7
LD, LDX, ST, STX, ALU, JMP, JMP32, ALU64 = range(8)
# BPF_OP(op) for ALU/ALU64 = op & 0xf0
OP_END = 0xD0
# BPF_OP(op) for JMP = op & 0xf0
JMP_CALL, JMP_EXIT, JMP_JA = 0x80, 0x90, 0x00
# BPF_MODE(op) = op & 0xE0
MODE_IMM, MODE_ABS, MODE_IND, MODE_MEM, MODE_ATOMIC = 0x00, 0x20, 0x40, 0x60, 0xC0
# BPF_SIZE(op) = op & 0x18
SIZE_NAME = {0x00: "4B", 0x08: "2B", 0x10: "1B", 0x18: "8B"}
R10 = 10


def decode(data, off=0, n=None):
    """[(op, dst, src, off, imm)] over `n` instruction slots at byte `off`."""
    n = n if n is not None else (len(data) - off) // 8
    out = []
    for i in range(n):
        op, regs, o, imm = struct.unpack_from("<BBhi", data, off + i * 8)
        out.append((op, regs & 0xF, regs >> 4, o, imm))
    return out


def classify(ins, prev_is_hi=False):
    """A short label for what KIND of work an instruction is.

    Deliberately coarse: the point is to say WHERE the extra instructions
    went (stack traffic? branches? sub-register moves?), which is what
    names a compiler problem. Finer detail is for reading the diff by hand.
    """
    op, dst, src, _off, _imm = ins
    if prev_is_hi:
        return "ld_imm64"          # second slot of a 16-byte load
    cls = op & 7
    if cls == LD:
        if op == 0x18:
            return "ld_imm64"
        return "ld_abs_ind"
    if cls in (LDX, ST, STX):
        if cls == STX and (op & 0xE0) == MODE_ATOMIC:
            return "atomic"
        # r10-relative traffic is the frame: spills, fills and locals
        onstack = (src == R10) if cls == LDX else (dst == R10)
        kind = "ldx" if cls == LDX else "stx"
        return f"{kind}_stack" if onstack else f"{kind}_mem"
    if cls in (JMP, JMP32):
        o = op & 0xF0
        if o == JMP_CALL:
            return {0: "call_helper", 1: "call_bpf2bpf", 2: "call_kfunc"}.get(src, "call")
        if o == JMP_EXIT:
            return "exit"
        if o == JMP_JA:
            return "goto"
        return "branch"
    if cls in (ALU, ALU64):
        if (op & 0xF0) == OP_END:
            return "endian"
        return "alu64" if cls == ALU64 else "alu32"
    return "other"


class FuncStats:
    """Per-function codegen metrics."""

    def __init__(self, name, insns):
        self.name = name
        self.insns = insns
        self.n = len(insns)
        self.hist = {}
        self.widths = {}       # memory-access width: how WIDE the loads and
        self.stack_bytes = 0   # stores are, which is what byte-wise copy
        skip = False           # workarounds show up in
        for i, ins in enumerate(insns):
            k = classify(ins, prev_is_hi=skip)
            self.hist[k] = self.hist.get(k, 0) + 1
            skip = (not skip) and ins[0] == 0x18
            op, dst, src, off, _ = ins
            cls = op & 7
            if cls in (LDX, ST, STX) and (op & 0xE0) != MODE_ATOMIC:
                w = SIZE_NAME.get(op & 0x18, "?")
                d = "ldx" if cls == LDX else "st"
                self.widths[f"{d}_{w}"] = self.widths.get(f"{d}_{w}", 0) + 1
            if off < 0 and ((cls == LDX and src == R10)
                            or (cls in (ST, STX) and dst == R10)):
                self.stack_bytes = max(self.stack_bytes, -off)

    def get(self, k):
        return self.hist.get(k, 0)

    @property
    def calls(self):
        return sum(self.hist.get(k, 0) for k in
                   ("call_helper", "call_bpf2bpf", "call_kfunc", "call"))


def func_spans(elf):
    """{(section, func): (section object, byte offset, byte size)} for every
    named function, INCLUDING .text subprograms (which entry programs call
    into — a fair size comparison has to follow them)."""
    from bpfelf import STT_FUNC
    out = {}
    for s in elf.symbols:
        if s.type != STT_FUNC or not s.name or s.size == 0:
            continue
        sec = elf.sections[s.shndx]
        if not sec.size or not (sec.flags & 0x4):   # SHF_EXECINSTR
            continue
        out[(sec.name, s.name)] = (sec, s.value, s.size)
    return out


def call_target(elf, sec, pc, ins):
    """(section name, insn index) for a src=1 call, or None if unresolvable."""
    rel = elf.relocs.get(sec.idx, {}).get((pc) * 8 + sec_base(sec))
    imm = ins[4]
    if rel is None:
        return sec.name, pc + 1 + imm
    sym = rel.sym
    if sym.shndx == 0 or sym.shndx >= len(elf.sections):
        return None
    return elf.sections[sym.shndx].name, sym.value // 8 + imm + 1


def sec_base(_sec):
    # relocation offsets are section-relative, and so are our pcs
    return 0


def whole_program(elf, sec, entry_off, size, depth=8):
    """Every instruction reachable from an entry program, following bpf2bpf
    calls into .text. Without this, a translation that leaves a helper
    out-of-line looks SMALLER than one that inlines it."""
    spans = func_spans(elf)
    bysec = {}
    for (sname, fname), (s, off, sz) in spans.items():
        bysec.setdefault(sname, []).append((off // 8, sz // 8, fname))
    seen, todo, total, funcs = set(), [(sec.name, entry_off // 8, size // 8)], [], []
    while todo and depth >= 0:
        sname, start, n = todo.pop()
        if (sname, start) in seen:
            continue
        seen.add((sname, start))
        s = elf.section_by_name(sname)
        if s is None:
            continue
        ins = decode(s.data, start * 8, n)
        total.extend(ins)
        funcs.append((sname, start, n))
        for i, x in enumerate(ins):
            if (x[0] & 7) in (JMP, JMP32) and (x[0] & 0xF0) == JMP_CALL and x[2] == 1:
                t = call_target(elf, s, start + i, x)
                if not t:
                    continue
                tsec, tpc = t
                for (foff, fn, _name) in bysec.get(tsec, []):
                    if foff == tpc:
                        todo.append((tsec, tpc, fn))
                        break
    return total, funcs
