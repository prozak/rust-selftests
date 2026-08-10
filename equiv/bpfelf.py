"""Minimal ELF64 little-endian reader for BPF relocatable objects.

Standalone (no pyelftools): sections, symbols, and REL relocations —
everything the symbolic equivalence executor needs.
"""
import re
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


def normalize_name(name):
    """Map Rust v0-mangled static names to their source identifier, so the
    same logical global gets the same region in both objects
    (_RNvCs..._13modify_return8sequence.0 -> sequence)."""
    base = name.split(".", 1)[0]
    if not base.startswith("_R"):
        return name
    m = re.match(r".*(\d+)([A-Za-z_][A-Za-z0-9_]*)$", base)
    if m and int(m.group(1)) == len(m.group(2)):
        return m.group(2)
    return name


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

    # BTF kind ids
    _BTF_EXTRA = {1: 4, 3: 12, 14: 4, 17: 4}          # INT, ARRAY, VAR, DECL_TAG
    _BTF_PER_VLEN = {4: 12, 5: 12, 6: 8, 13: 8, 15: 12, 19: 12}
    _BTF_MODIFIERS = {8, 9, 10, 11, 18}               # TYPEDEF..CONST..TYPE_TAG

    def btf_types(self):
        """id -> (kind, name, type/size, vlen, extra). Lazy, id 0 = void.

        extra: ARRAY -> (elem_type, nelems); STRUCT/UNION -> [(member name,
        member type id)]; DATASEC -> [var type id]; else None."""
        if hasattr(self, "_btf"):
            return self._btf
        self._btf = {0: (0, "", 0, 0, None)}
        sec = self.section_by_name(".BTF")
        if sec is None:
            return self._btf
        b = sec.data
        hdr_len, = struct.unpack_from("<I", b, 4)
        type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", b, 8)
        strings = b[hdr_len + str_off:hdr_len + str_off + str_len]

        def sname(off):
            if off and off < len(strings):
                return strings[off:strings.index(b"\x00", off)].decode()
            return ""

        pos, end, tid = hdr_len + type_off, hdr_len + type_off + type_len, 1
        while pos + 12 <= end:
            name_off, info, size_or_type = struct.unpack_from("<III", b, pos)
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            extra = None
            if kind == 3:    # ARRAY: (type, index_type, nelems)
                et, _it, ne = struct.unpack_from("<III", b, pos + 12)
                extra = (et, ne)
            elif kind in (4, 5):  # STRUCT/UNION members
                extra = [(sname(struct.unpack_from("<III", b, pos + 12 + 12 * i)[0]),
                          struct.unpack_from("<III", b, pos + 12 + 12 * i)[1])
                         for i in range(vlen)]
            elif kind == 15:  # DATASEC: (var type, offset, size)
                extra = [struct.unpack_from("<III", b, pos + 12 + 12 * i)[0]
                         for i in range(vlen)]
            self._btf[tid] = (kind, sname(name_off), size_or_type, vlen, extra)
            pos += 12 + self._BTF_EXTRA.get(kind, 0) + self._BTF_PER_VLEN.get(kind, 0) * vlen
            tid += 1
        return self._btf

    def btf_type_size(self, tid):
        """Byte size of a BTF type, or None if not sizeable."""
        types = self.btf_types()
        for _ in range(32):
            t = types.get(tid)
            if t is None:
                return None
            kind, _name, size_or_type, _vlen, extra = t
            if kind in self._BTF_MODIFIERS:
                tid = size_or_type
                continue
            if kind in (1, 4, 5, 6, 16, 19):  # INT/STRUCT/UNION/ENUM/FLOAT/ENUM64
                return size_or_type
            if kind == 2:                     # PTR
                return 8
            if kind == 3:                     # ARRAY
                es = self.btf_type_size(extra[0])
                return None if es is None else es * extra[1]
            return None
        return None

    def map_defs(self):
        """map name -> {'key_size', 'value_size', 'map_type'} from the .maps
        DATASEC BTF (libbpf-style defs: __type members are pointers to the
        real type, __uint members encode the value as a pointee-array length).
        Values are None when the def doesn't carry them."""
        if hasattr(self, "_map_defs"):
            return self._map_defs
        types = self.btf_types()
        self._map_defs = {}
        for kind, name, _st, _vlen, extra in types.values():
            if kind != 15 or name != ".maps":
                continue
            for var_id in extra:
                var = types.get(var_id)
                if var is None or var[0] != 14:  # VAR
                    continue
                mname = normalize_name(var[1])
                tid = var[2]
                for _ in range(32):  # unwrap modifiers to the def struct
                    t = types.get(tid)
                    if t is None or t[0] not in self._BTF_MODIFIERS:
                        break
                    tid = t[2]
                st = types.get(tid)
                if st is None or st[0] not in (4, 5):
                    continue
                d = {"key_size": None, "value_size": None, "map_type": None}
                for memb_name, memb_tid in st[4]:
                    mt = types.get(memb_tid)
                    if mt is None or mt[0] != 2:  # members are pointers
                        continue
                    pointee = types.get(mt[2])
                    if memb_name in ("key", "value"):
                        d[memb_name + "_size"] = self.btf_type_size(mt[2])
                    elif pointee is not None and pointee[0] == 3:  # __uint array
                        n = pointee[4][1]
                        if memb_name == "key_size":
                            d["key_size"] = n
                        elif memb_name == "value_size":
                            d["value_size"] = n
                        elif memb_name == "type":
                            d["map_type"] = n
                self._map_defs[mname] = d
        return self._map_defs

    def func_ret_bits(self, func_name):
        """Return width in bits of a BTF FUNC's return type: 0 = void,
        None = unknown/no BTF."""
        types = self.btf_types()
        proto = None
        for kind, name, typ, _vlen, _extra in types.values():
            if kind == 12 and name == func_name:  # FUNC
                proto = types.get(typ)
                break
        if proto is None or proto[0] != 13:  # FUNC_PROTO
            return None
        rt = proto[2]
        for _ in range(32):  # unwrap modifiers/typedefs
            if rt == 0:
                return 0
            t = types.get(rt)
            if t is None:
                return None
            kind, _name, typ_or_size, _vlen, _extra = t
            if kind in self._BTF_MODIFIERS:
                rt = typ_or_size
                continue
            if kind in (1, 6, 16, 19):  # INT, ENUM, FLOAT, ENUM64
                return typ_or_size * 8
            if kind == 2:               # PTR
                return 64
            return None
        return None

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
