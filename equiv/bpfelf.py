"""Minimal ELF64 little-endian reader for BPF relocatable objects.

Standalone (no pyelftools): sections, symbols, and REL relocations —
everything the symbolic equivalence executor needs.
"""
import struct
from collections import namedtuple

Section = namedtuple("Section", "idx name type flags offset size link info entsize data")
Symbol = namedtuple("Symbol", "idx name value size bind type shndx")
Reloc = namedtuple("Reloc", "offset sym type")

SHT_SYMTAB = 2
SHT_NOBITS = 8
SHT_REL = 9
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3


class BpfElf:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            buf = f.read()
        if buf[:4] != b"\x7fELF" or buf[4] != 2 or buf[5] != 1:
            raise ValueError(f"{path}: not a 64-bit LE ELF")
        e_shoff = struct.unpack_from("<Q", buf, 0x28)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 0x3A)

        raw = []
        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            (name_off, s_type, flags, _addr, offset, size,
             link, info, _align, entsize) = struct.unpack_from("<IIQQQQIIQQ", buf, base)
            raw.append((name_off, s_type, flags, offset, size, link, info, entsize))

        shstr_off = raw[e_shstrndx][3]

        def cstr(base, off):
            end = buf.index(b"\x00", base + off)
            return buf[base + off:end].decode()

        self.sections = []
        for i, (name_off, s_type, flags, offset, size, link, info, entsize) in enumerate(raw):
            data = b"" if s_type == SHT_NOBITS else buf[offset:offset + size]
            self.sections.append(Section(i, cstr(shstr_off, name_off), s_type, flags,
                                         offset, size, link, info, entsize, data))

        self.symbols = []
        symtab = next((s for s in self.sections if s.type == SHT_SYMTAB), None)
        if symtab is not None:
            strtab_off = self.sections[symtab.link].offset
            n = symtab.size // 24
            for i in range(n):
                name_off, info, _other, shndx, value, size = struct.unpack_from(
                    "<IBBHQQ", buf, symtab.offset + i * 24)
                self.symbols.append(Symbol(i, cstr(strtab_off, name_off), value, size,
                                           info >> 4, info & 0xF, shndx))

        # section index -> {insn/byte offset -> Reloc}
        self.relocs = {}
        for s in self.sections:
            if s.type != SHT_REL:
                continue
            table = {}
            for i in range(s.size // 16):
                offset, info = struct.unpack_from("<QQ", buf, s.offset + i * 16)
                table[offset] = Reloc(offset, self.symbols[info >> 32], info & 0xFFFFFFFF)
            self.relocs[s.info] = table

    def section_by_name(self, name):
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def exec_sections(self):
        """Program-carrying sections (non-empty, executable)."""
        return [s for s in self.sections
                if s.flags & SHF_EXECINSTR and s.size > 0]

    def core_relo_sections(self):
        """Section names that carry CO-RE relocations (from .BTF.ext)."""
        ext = self.section_by_name(".BTF.ext")
        btf = self.section_by_name(".BTF")
        if ext is None or btf is None or len(ext.data) < 32:
            return set()
        d = ext.data
        magic, = struct.unpack_from("<H", d, 0)
        if magic != 0xEB9F:
            return set()
        hdr_len, = struct.unpack_from("<I", d, 4)
        if hdr_len < 32:
            return set()  # header predates core_relo
        core_off, core_len = struct.unpack_from("<II", d, 24)
        if core_len == 0:
            return set()
        # BTF string table
        b = btf.data
        btf_hdr_len, = struct.unpack_from("<I", b, 4)
        str_off, str_len = struct.unpack_from("<II", b, 16)
        strings = b[btf_hdr_len + str_off:btf_hdr_len + str_off + str_len]

        out = set()
        pos = hdr_len + core_off
        end = pos + core_len
        rec_size, = struct.unpack_from("<I", d, pos)
        pos += 4
        while pos < end:
            name_off, num = struct.unpack_from("<II", d, pos)
            pos += 8 + num * rec_size
            send = strings.index(b"\x00", name_off)
            out.add(strings[name_off:send].decode())
        return out

    def named_symbol_at(self, shndx, offset):
        """Best named OBJECT/FUNC symbol in section shndx containing offset."""
        best = None
        for sym in self.symbols:
            if sym.shndx != shndx or not sym.name or sym.type == STT_SECTION:
                continue
            if sym.value <= offset and (sym.size == 0 or offset < sym.value + sym.size):
                if best is None or sym.value > best.value:
                    best = sym
        return best
