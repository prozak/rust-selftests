"""Synthetic BPF objects for hermetic testing and documentation.

Builds tiny in-memory "ELF" objects that the real `Executor` and
`check_program` accept, so the prover's behaviour can be exercised without
a kernel, a build tree, or any checked-in binary artifacts. Used by
equiv/tests/ (CI) and by the semantics doc generator.

    from testkit import asm, FakeElf, compare
    a = asm.prog(asm.mov64_imm(0, 1), asm.exit_())
    b = asm.prog(asm.mov64_imm(0, 2), asm.exit_())
    compare(a, b)            # -> ("INEQUIV", "ret: C=1 rust=2")
"""
import os
import struct
import sys
from collections import namedtuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import z3

import check as _check
from bpfelf import Section, Symbol, SHF_ALLOC, SHF_EXECINSTR, STT_FUNC

SEC_NAME = "socket"
FUNC_NAME = "prog"


# ---------------------------------------------------------------- assembler

class _Asm:
    """Minimal BPF instruction builder: every helper returns 8 bytes."""

    @staticmethod
    def raw(op, dst=0, src=0, off=0, imm=0):
        return struct.pack("<BBhi", op, (src << 4) | dst, off, imm)

    # ALU64 / ALU32
    def mov64_imm(self, dst, imm):
        return self.raw(0xB7, dst, imm=imm)

    def mov64_reg(self, dst, src):
        return self.raw(0xBF, dst, src)

    def mov32_imm(self, dst, imm):
        return self.raw(0xB4, dst, imm=imm)

    def add64_imm(self, dst, imm):
        return self.raw(0x07, dst, imm=imm)

    def add64_reg(self, dst, src):
        return self.raw(0x0F, dst, src)

    def and64_imm(self, dst, imm):
        return self.raw(0x57, dst, imm=imm)

    def lsh64_imm(self, dst, imm):
        return self.raw(0x67, dst, imm=imm)

    # memory: size in bytes -> opcode nibble
    _SZ = {8: 0x18, 4: 0x00, 2: 0x08, 1: 0x10}

    def ldx(self, size, dst, src, off):
        return self.raw(0x61 | self._SZ[size], dst, src, off)

    def stx(self, size, dst, src, off):
        return self.raw(0x63 | self._SZ[size], dst, src, off)

    def st_imm(self, size, dst, off, imm):
        return self.raw(0x62 | self._SZ[size], dst, off=off, imm=imm)

    # jumps (off is in instructions, relative to the NEXT insn)
    def jeq_imm(self, dst, imm, off):
        return self.raw(0x15, dst, off=off, imm=imm)

    def jne_imm(self, dst, imm, off):
        return self.raw(0x55, dst, off=off, imm=imm)

    def jgt_imm(self, dst, imm, off):
        return self.raw(0x25, dst, off=off, imm=imm)

    def ja(self, off):
        return self.raw(0x05, off=off)

    def call(self, helper_id):
        return self.raw(0x85, imm=helper_id)

    def exit_(self):
        return self.raw(0x95)

    def ld_imm64(self, dst, value):
        lo = value & 0xFFFFFFFF
        hi = (value >> 32) & 0xFFFFFFFF
        return (self.raw(0x18, dst, imm=lo - (1 << 32) if lo >> 31 else lo)
                + self.raw(0x00, imm=hi - (1 << 32) if hi >> 31 else hi))

    @staticmethod
    def prog(*insns):
        return b"".join(insns)


asm = _Asm()


# ------------------------------------------------------------------ fake ELF

class FakeElf:
    """The slice of BpfElf the Executor and check_program actually touch."""

    def __init__(self, code, path="synthetic.bpf.o", globals_=None,
                 rodata=None, maps=None, relocs=None, ret_bits=None):
        self.path = path
        self.core_applied, self.core_poison = True, {}
        self._map_defs = maps or {}
        self._ret_bits = ret_bits
        self.sections, self.symbols = [], []
        self.relocs = {}

        def add_section(name, data, flags, stype=1):
            idx = len(self.sections)
            self.sections.append(Section(idx, name, stype, flags, 0,
                                         len(data), 0, 0, 0, data))
            return idx

        add_section("", b"", 0)                       # index 0 = SHN_UNDEF
        code_idx = add_section(SEC_NAME, code, SHF_ALLOC | SHF_EXECINSTR)
        self.symbols.append(Symbol(0, FUNC_NAME, 0, len(code), 1, STT_FUNC,
                                   code_idx))
        if globals_:
            for gname, gbytes in globals_.items():
                gidx = add_section(".bss." + gname, gbytes, SHF_ALLOC)
                self.symbols.append(Symbol(len(self.symbols), gname, 0,
                                           len(gbytes), 1, 1, gidx))
        if rodata:
            add_section(".rodata", rodata, SHF_ALLOC)
        if relocs:
            self.relocs[code_idx] = relocs

    def section_by_name(self, name):
        return next((s for s in self.sections if s.name == name), None)

    def exec_sections(self):
        return [s for s in self.sections
                if s.flags & SHF_EXECINSTR and s.size > 0]

    def named_symbol_at(self, shndx, offset):
        best = None
        for sym in self.symbols:
            if sym.shndx != shndx or not sym.name:
                continue
            if sym.value <= offset and (sym.size == 0
                                        or offset < sym.value + sym.size):
                if best is None or sym.value > best.value:
                    best = sym
        return best

    def map_defs(self):
        return self._map_defs

    def core_relo_sections(self):
        return set()

    def kconfig_externs(self):
        return set()

    def func_ret_bits(self, _name):
        return self._ret_bits


# -------------------------------------------------------------- comparison

def compare(code_a, code_b, timeout_ms=20_000, **kw):
    """Prove two synthetic programs equivalent. Returns (verdict, detail)."""
    elf_a = FakeElf(code_a, path="a.bpf.o", **kw)
    elf_b = FakeElf(code_b, path="b.bpf.o", **kw)
    shared, _ = _check.global_regions({"A": elf_a, "B": elf_b})
    for name, arr in (("ctx", "ctx"), ("kmem", "kmem"),
                      ("trace", "trace_init"), ("skbdata", "skbdata"),
                      ("sysret", "sysret")):
        shared[name] = z3.Array(arr, z3.BitVecSort(64), z3.BitVecSort(8))
    sec_a = elf_a.section_by_name(SEC_NAME)
    sec_b = elf_b.section_by_name(SEC_NAME)
    return _check.check_program(FUNC_NAME, FUNC_NAME,
                                {"A": (elf_a, sec_a, 0),
                                 "B": (elf_b, sec_b, 0)},
                                shared, timeout_ms)
