"""CO-RE relocation application against a target (vmlinux) BTF.

Mirrors libbpf's relo_core.c algorithm: parse each `.BTF.ext` core_relo
record, build the local access spec, find name-compatible candidate types in
the target BTF, match the spec member-by-member (recursing through anonymous
members), compute the per-kind target value, and patch the instruction the
way libbpf would (off for LDX/ST/STX, imm for ALU/ALU64, imm64 for LD_IMM64).

Divergences from libbpf are all in the *failure* direction, never silent:
  - an unresolvable relocation poisons the instruction exactly like libbpf
    (call 0xbad2310), and the poison set is reported so the symbolic executor
    can BAIL if such an instruction is ever reachable;
  - candidates that disagree on the relocated value poison instead of
    erroring the whole object;
  - TYPE_ID_LOCAL is patched faithfully but also reported as poison-for-
    equivalence: the value is the object's own BTF id, incomparable between
    the C and Rust objects by construction.
"""
import struct

# BTF kinds
K_INT, K_PTR, K_ARRAY, K_STRUCT, K_UNION, K_ENUM = 1, 2, 3, 4, 5, 6
K_FWD, K_TYPEDEF, K_VOLATILE, K_CONST, K_RESTRICT = 7, 8, 9, 10, 11
K_FUNC, K_FUNC_PROTO, K_VAR, K_DATASEC, K_FLOAT = 12, 13, 14, 15, 16
K_DECL_TAG, K_TYPE_TAG, K_ENUM64 = 17, 18, 19
MODIFIERS = {K_TYPEDEF, K_VOLATILE, K_CONST, K_RESTRICT, K_TYPE_TAG}
COMPOSITE = {K_STRUCT, K_UNION}

# bpf_core_relo_kind
R_FIELD_BYTE_OFFSET, R_FIELD_BYTE_SIZE, R_FIELD_EXISTS = 0, 1, 2
R_FIELD_SIGNED, R_FIELD_LSHIFT_U64, R_FIELD_RSHIFT_U64 = 3, 4, 5
R_TYPE_ID_LOCAL, R_TYPE_ID_TARGET, R_TYPE_EXISTS, R_TYPE_SIZE = 6, 7, 8, 9
R_ENUMVAL_EXISTS, R_ENUMVAL_VALUE, R_TYPE_MATCHES = 10, 11, 12
FIELD_RELOS = {R_FIELD_BYTE_OFFSET, R_FIELD_BYTE_SIZE, R_FIELD_EXISTS,
               R_FIELD_SIGNED, R_FIELD_LSHIFT_U64, R_FIELD_RSHIFT_U64}
TYPE_RELOS = {R_TYPE_ID_LOCAL, R_TYPE_ID_TARGET, R_TYPE_EXISTS, R_TYPE_SIZE,
              R_TYPE_MATCHES}
ENUM_RELOS = {R_ENUMVAL_EXISTS, R_ENUMVAL_VALUE}
KIND_NAMES = {0: "byte_off", 1: "byte_sz", 2: "field_exists", 3: "signed",
              4: "lshift_u64", 5: "rshift_u64", 6: "local_type_id",
              7: "target_type_id", 8: "type_exists", 9: "type_size",
              10: "enumval_exists", 11: "enumval_value", 12: "type_matches"}

POISON_CALL_IMM = 0xBAD2310  # libbpf's "invalid func" marker


class BtfMember:
    __slots__ = ("name", "type", "bit_offset", "bitfield_size")

    def __init__(self, name, typ, bit_offset, bitfield_size):
        self.name, self.type = name, typ
        self.bit_offset, self.bitfield_size = bit_offset, bitfield_size


class BtfType:
    __slots__ = ("id", "kind", "name", "size", "type", "vlen", "kflag",
                 "members", "enums", "array", "int_bits", "int_signed",
                 "fwd_union", "proto")

    def __init__(self, tid, kind, name, kflag, vlen):
        self.id, self.kind, self.name, self.kflag, self.vlen = \
            tid, kind, name, kflag, vlen
        self.size = self.type = 0
        self.members = None   # [BtfMember] for STRUCT/UNION
        self.enums = None     # [(name, value)] for ENUM/ENUM64
        self.array = None     # (elem_type, nelems)
        self.int_bits = self.int_signed = 0
        self.fwd_union = False
        self.proto = None     # (ret_type, [param types]) for FUNC_PROTO


class Btf:
    """Full-fidelity BTF parser over raw .BTF bytes.

    base: another Btf for split BTF (kernel modules) — type ids continue
    after the base's and string offsets >= base string size index into this
    BTF's own string table."""

    def __init__(self, data, base=None):
        magic, = struct.unpack_from("<H", data, 0)
        if magic != 0xEB9F:
            raise ValueError("bad BTF magic")
        hdr_len, = struct.unpack_from("<I", data, 4)
        type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", data, 8)
        self.strings = data[hdr_len + str_off:hdr_len + str_off + str_len]
        self._base_strings = base.strings if base is not None else b""
        if base is not None:
            self.types = dict(base.types)
            tid0 = max(self.types) + 1
        else:
            self.types = {0: BtfType(0, 0, "", 0, 0)}
            tid0 = 1
        self.start_id = tid0  # first id owned by this (split) BTF
        self._by_name = None

        pos, end, tid = hdr_len + type_off, hdr_len + type_off + type_len, tid0
        while pos + 12 <= end:
            name_off, info, size_or_type = struct.unpack_from("<III", data, pos)
            kind = (info >> 24) & 0x1F
            t = BtfType(tid, kind, self._str(name_off), (info >> 31) & 1,
                        info & 0xFFFF)
            pos += 12
            if kind in (K_STRUCT, K_UNION, K_ENUM, K_ENUM64, K_INT, K_FLOAT,
                        K_DATASEC):
                t.size = size_or_type
            else:
                t.type = size_or_type
            if kind == K_INT:
                enc, = struct.unpack_from("<I", data, pos)
                t.int_bits = enc & 0xFF
                t.int_signed = bool(enc & 0x01000000)
                pos += 4
            elif kind == K_ARRAY:
                et, _it, ne = struct.unpack_from("<III", data, pos)
                t.array = (et, ne)
                pos += 12
            elif kind in COMPOSITE:
                t.members = []
                for _ in range(t.vlen):
                    n_off, m_typ, m_off = struct.unpack_from("<III", data, pos)
                    if t.kflag:
                        bfsz, boff = m_off >> 24, m_off & 0xFFFFFF
                    else:
                        bfsz, boff = 0, m_off
                    t.members.append(BtfMember(self._str(n_off), m_typ, boff, bfsz))
                    pos += 12
            elif kind == K_ENUM:
                t.enums = []
                for _ in range(t.vlen):
                    n_off, val = struct.unpack_from("<Ii", data, pos)
                    t.enums.append((self._str(n_off), val))
                    pos += 8
            elif kind == K_ENUM64:
                t.enums = []
                for _ in range(t.vlen):
                    n_off, lo, hi = struct.unpack_from("<III", data, pos)
                    v = (hi << 32) | lo
                    if t.kflag and v & (1 << 63):  # signed
                        v -= 1 << 64
                    t.enums.append((self._str(n_off), v))
                    pos += 12
            elif kind == K_FUNC_PROTO:
                params = []
                for _ in range(t.vlen):
                    _pn, p_typ = struct.unpack_from("<II", data, pos)
                    params.append(p_typ)
                    pos += 8
                t.proto = (t.type, params)
            elif kind == K_VAR:
                pos += 4
            elif kind == K_DECL_TAG:
                pos += 4
            elif kind == K_DATASEC:
                pos += 12 * t.vlen
            elif kind == K_FWD:
                t.fwd_union = bool(t.kflag)
            self.types[tid] = t
            tid += 1

    def _str(self, off):
        if not off:
            return ""
        base_len = len(self._base_strings)
        if off < base_len:
            buf = self._base_strings
        else:
            buf, off = self.strings, off - base_len
        if off >= len(buf):
            return ""
        end = buf.find(b"\x00", off)
        return buf[off:end].decode() if end >= 0 else ""

    def resolve(self, tid):
        """Skip modifiers/typedefs; returns BtfType (void for unknown)."""
        for _ in range(64):
            t = self.types.get(tid)
            if t is None:
                return self.types[0]
            if t.kind not in MODIFIERS:
                return t
            tid = t.type
        return self.types[0]

    def type_size(self, tid):
        """Byte size, following mods/typedefs; None if unsizeable."""
        t = self.resolve(tid)
        if t.kind in (K_INT, K_STRUCT, K_UNION, K_ENUM, K_ENUM64, K_FLOAT,
                      K_DATASEC):
            return t.size
        if t.kind == K_PTR:
            return 8
        if t.kind == K_ARRAY:
            es = self.type_size(t.array[0])
            return None if es is None else es * t.array[1]
        return None

    def by_name(self, essential):
        """All type ids whose essential name (before '___') matches."""
        if self._by_name is None:
            self._by_name = {}
            for t in self.types.values():
                if t.name:
                    self._by_name.setdefault(essential_name(t.name), []).append(t.id)
        return self._by_name.get(essential, [])


def essential_name(name):
    i = name.find("___")
    return name[:i] if i >= 0 else name


class Accessor:
    __slots__ = ("idx", "name", "type_id")

    def __init__(self, idx, name, type_id):
        self.idx, self.name, self.type_id = idx, name, type_id


class Spec:
    __slots__ = ("btf", "root_id", "accessors", "bit_offset")

    def __init__(self, btf, root_id):
        self.btf, self.root_id = btf, root_id
        self.accessors, self.bit_offset = [], 0


class CoreError(Exception):
    pass


def parse_spec(btf, type_id, access_str, kind):
    """libbpf bpf_core_parse_spec."""
    spec = Spec(btf, type_id)
    idxs = [int(x) for x in access_str.split(":")]
    t = btf.resolve(type_id)

    if kind in TYPE_RELOS:
        if idxs != [0]:
            raise CoreError(f"type relo with access '{access_str}'")
        return spec
    if kind in ENUM_RELOS:
        if len(idxs) != 1:
            raise CoreError(f"enumval relo with access '{access_str}'")
        if t.kind not in (K_ENUM, K_ENUM64) or idxs[0] >= len(t.enums):
            raise CoreError("enumval relo on non-enum/oob")
        spec.accessors.append(Accessor(idxs[0], t.enums[idxs[0]][0], t.id))
        return spec

    # field relos: first index is array-of-root deref
    sz = btf.type_size(type_id)
    if sz is None:
        raise CoreError("root type unsizeable")
    spec.bit_offset = idxs[0] * sz * 8
    spec.accessors.append(Accessor(idxs[0], None, type_id))
    t = btf.resolve(type_id)
    for idx in idxs[1:]:
        if t.kind in COMPOSITE:
            if idx >= len(t.members):
                raise CoreError("member index oob")
            m = t.members[idx]
            spec.bit_offset += m.bit_offset
            spec.accessors.append(Accessor(idx, m.name or None, m.type))
            t = btf.resolve(m.type)
        elif t.kind == K_ARRAY:
            elem, n = t.array
            if n and idx >= n:
                raise CoreError("array index oob (local)")
            es = btf.type_size(elem)
            if es is None:
                raise CoreError("array elem unsizeable")
            spec.bit_offset += idx * es * 8
            spec.accessors.append(Accessor(idx, None, elem))
            t = btf.resolve(elem)
        else:
            raise CoreError(f"access through kind {t.kind}")
    return spec


def fields_are_compat(lbtf, lid, tbtf, tid):
    """libbpf bpf_core_fields_are_compat (leaf type check)."""
    for _ in range(32):
        lt, tt = lbtf.resolve(lid), tbtf.resolve(tid)
        if lt.kind in COMPOSITE and tt.kind in COMPOSITE:
            return True  # libbpf: any two composites are fine at field leaf
        if lt.kind != tt.kind:
            # ENUM vs ENUM64 are mutually compatible
            if {lt.kind, tt.kind} == {K_ENUM, K_ENUM64}:
                return (not lt.name or not tt.name
                        or essential_name(lt.name) == essential_name(tt.name))
            return False
        k = lt.kind
        if k == K_PTR:
            return True
        if k in (K_INT, K_FLOAT):
            return True  # size/signedness ignored
        if k in (K_ENUM, K_ENUM64):
            return (not lt.name or not tt.name
                    or essential_name(lt.name) == essential_name(tt.name))
        if k == K_FWD:
            return (not lt.name or not tt.name
                    or essential_name(lt.name) == essential_name(tt.name))
        if k == K_ARRAY:
            lid, tid = lt.array[0], tt.array[0]
            continue
        return False
    return False


def match_member(lbtf, lacc, tbtf, t_tid, tspec):
    """Find member named lacc.name in target composite t_tid, recursing
    through anonymous members. Appends accessors/bit offsets to tspec.
    Returns matched member type id or None."""
    t = tbtf.resolve(t_tid)
    if t.kind not in COMPOSITE:
        return None
    for i, m in enumerate(t.members):
        if not m.name:
            # anonymous struct/union: descend
            save_len = len(tspec.accessors)
            save_off = tspec.bit_offset
            tspec.bit_offset += m.bit_offset
            found = match_member(lbtf, lacc, tbtf, m.type, tspec)
            if found is not None:
                return found
            del tspec.accessors[save_len:]
            tspec.bit_offset = save_off
        elif m.name == lacc.name:
            if not fields_are_compat(lbtf, lacc.type_id, tbtf, m.type):
                return None
            tspec.bit_offset += m.bit_offset
            tspec.accessors.append(Accessor(i, m.name, m.type))
            return (m.type, m)
    return None


def match_spec(lspec, tbtf, t_root):
    """libbpf bpf_core_spec_match: produce target spec or None."""
    tspec = Spec(tbtf, t_root)
    lbtf = lspec.btf

    # enumval
    lacc0 = lspec.accessors[0] if lspec.accessors else None
    lroot = lbtf.resolve(lspec.root_id)
    troot = tbtf.resolve(t_root)
    if lroot.kind in (K_ENUM, K_ENUM64):
        if troot.kind not in (K_ENUM, K_ENUM64):
            return None
        want = essential_name(lacc0.name)  # local enumerator may be flavored
        for i, (n, _v) in enumerate(troot.enums):
            if n == want:
                tspec.accessors.append(Accessor(i, n, troot.id))
                return tspec
        return None

    # field relo: first accessor indexes an array of root
    tsz = tbtf.type_size(t_root)
    if tsz is None:
        return None
    tspec.bit_offset = lacc0.idx * tsz * 8
    tspec.accessors.append(Accessor(lacc0.idx, None, t_root))
    t_tid = t_root
    for lacc in lspec.accessors[1:]:
        if lacc.name is not None:
            r = match_member(lbtf, lacc, tbtf, t_tid, tspec)
            if r is None:
                return None
            t_tid = r[0]
        else:
            # array (or anon-member positional) access: same index
            t = tbtf.resolve(t_tid)
            if t.kind == K_ARRAY:
                elem, n = t.array
                if n and lacc.idx >= n:  # nelems 0 = flexible array
                    return None
                es = tbtf.type_size(elem)
                if es is None:
                    return None
                tspec.bit_offset += lacc.idx * es * 8
                tspec.accessors.append(Accessor(lacc.idx, None, elem))
                t_tid = elem
            elif t.kind in COMPOSITE:
                # positional access into composite (anon member in local BTF):
                # libbpf requires same index and compatible types
                if lacc.idx >= len(t.members):
                    return None
                m = t.members[lacc.idx]
                if not fields_are_compat(lbtf, lacc.type_id, tbtf, m.type):
                    return None
                tspec.bit_offset += m.bit_offset
                tspec.accessors.append(Accessor(lacc.idx, None, m.type))
                t_tid = m.type
            else:
                return None
    return tspec


def types_are_compat(lbtf, lid, tbtf, tid, depth=32):
    """libbpf bpf_core_types_are_compat (for TYPE_EXISTS / func protos)."""
    if depth < 0:
        return False
    lt, tt = lbtf.resolve(lid), tbtf.resolve(tid)
    if lt.kind != tt.kind:
        if {lt.kind, tt.kind} == {K_ENUM, K_ENUM64}:
            return True
        return False
    k = lt.kind
    if lt.name and tt.name and essential_name(lt.name) != essential_name(tt.name):
        if k in (K_STRUCT, K_UNION, K_ENUM, K_ENUM64, K_FWD):
            return False
    if k in (K_STRUCT, K_UNION, K_ENUM, K_ENUM64, K_FWD, K_INT, K_FLOAT):
        return True  # shallow: names match (checked), that's enough here
    if k == K_PTR:
        return types_are_compat(lbtf, lt.type, tbtf, tt.type, depth - 1)
    if k == K_ARRAY:
        return types_are_compat(lbtf, lt.array[0], tbtf, tt.array[0], depth - 1)
    if k == K_FUNC_PROTO:
        lr, lp = lt.proto
        tr, tp = tt.proto
        if len(lp) != len(tp):
            return False
        if not types_are_compat(lbtf, lr, tbtf, tr, depth - 1):
            return False
        return all(types_are_compat(lbtf, a, tbtf, b, depth - 1)
                   for a, b in zip(lp, tp))
    return False


def _names_match(ln, tn):
    """libbpf bpf_core_names_match: essential-name equality; empty target
    name requires empty local name."""
    if not tn:
        return not ln
    return essential_name(ln) == essential_name(tn)


def types_match(lbtf, lid, tbtf, tid, behind_ptr=False, depth=32):
    """libbpf __bpf_core_types_match (TYPE_MATCHES relos). Mods/typedefs are
    stripped; names must match at every level; ints match on size+signedness;
    composites: every local member has a same-named, recursively matching
    target member (offsets ignored); behind a pointer, same-kind composites
    match by name alone and FWDs may stand in for structs/unions."""
    if depth < 0:
        return False
    lt, tt = lbtf.resolve(lid), tbtf.resolve(tid)
    if not _names_match(lt.name, tt.name):
        return False
    lk, tk = lt.kind, tt.kind
    if lk == K_FWD:
        lf = lt.kflag  # kflag: 0 = struct fwd, 1 = union fwd
        if behind_ptr:
            if tk == K_FWD:
                return lf == tt.kflag
            return ((tk == K_STRUCT and not lf)
                    or (tk == K_UNION and lf))
        return tk == K_FWD and lf == tt.kflag
    if lk in (K_ENUM, K_ENUM64):
        if tk not in (K_ENUM, K_ENUM64):
            return False
        return _enums_match(lt, tt)
    if lk in COMPOSITE:
        if behind_ptr:
            if tk == lk:
                return True
            if tk != K_FWD:
                return False
            return (lk == K_UNION) == bool(tt.kflag)
        if tk != lk:
            return False
        if len(lt.members) > len(tt.members):
            return False
        for lm in lt.members:
            if not any(_names_match(lm.name, tm.name)
                       and types_match(lbtf, lm.type, tbtf, tm.type,
                                       behind_ptr, depth - 1)
                       for tm in tt.members):
                return False
        return True
    if lk != tk:
        return False
    if lk == K_INT:
        return lt.size == tt.size and lt.int_signed == tt.int_signed
    if lk == K_FLOAT:
        return lt.size == tt.size
    if lk == K_PTR:
        return types_match(lbtf, lt.type, tbtf, tt.type, True, depth - 1)
    if lk == K_ARRAY:
        if lt.array[1] != tt.array[1]:
            return False
        return types_match(lbtf, lt.array[0], tbtf, tt.array[0], behind_ptr,
                           depth - 1)
    if lk == K_FUNC_PROTO:
        lr, lp = lt.proto
        tr, tp = tt.proto
        if len(lp) != len(tp):
            return False
        if not types_match(lbtf, lr, tbtf, tr, behind_ptr, depth - 1):
            return False
        return all(types_match(lbtf, a, tbtf, b, behind_ptr, depth - 1)
                   for a, b in zip(lp, tp))
    return lk == 0  # void matches void


def _enums_match(lt, tt):
    """libbpf bpf_core_enums_match: same size, every local enumerator has a
    symbolic-name counterpart in the target (values NOT compared)."""
    if lt.size != tt.size or len(lt.enums) > len(tt.enums):
        return False
    return all(any(_names_match(n, m) for m, _x in tt.enums)
               for n, _v in lt.enums)


def _field_info(btf, spec, kind):
    """(value, validate) per libbpf bpf_core_calc_field_relo for a resolved
    spec (local or target). Returns (value, validate_flag)."""
    acc = spec.accessors[-1]
    if acc.name is None:
        # array element or root: no bitfield possible
        if kind == R_FIELD_BYTE_OFFSET:
            return spec.bit_offset // 8, True
        if kind == R_FIELD_BYTE_SIZE:
            sz = btf.type_size(acc.type_id)
            if sz is None:
                raise CoreError("unsizeable field")
            return sz, True
        if kind == R_FIELD_SIGNED:
            t = btf.resolve(acc.type_id)
            if t.kind == K_INT:
                return int(t.int_signed), True
            if t.kind in (K_ENUM, K_ENUM64):
                return int(t.kflag), True
            raise CoreError("signed of non-int")
        raise CoreError(f"{KIND_NAMES[kind]} on non-member")

    # the composite containing the last accessor is the previous accessor's type
    pt = btf.resolve(spec.accessors[-2].type_id)
    m = None
    if pt.kind in COMPOSITE and acc.idx < len(pt.members):
        m = pt.members[acc.idx]
    bit_off = spec.bit_offset
    bit_sz = m.bitfield_size if m is not None else 0
    t = btf.resolve(acc.type_id)
    if bit_sz == 0:
        byte_sz = btf.type_size(acc.type_id)
        if byte_sz is None:
            raise CoreError("unsizeable member")
        byte_off = bit_off // 8
        bit_sz = byte_sz * 8
        validate = True
    else:
        # bitfield: compute smallest aligned load window
        byte_sz = t.size
        byte_off = bit_off // 8 // byte_sz * byte_sz
        while bit_off + bit_sz - byte_off * 8 > byte_sz * 8:
            if byte_sz >= 8:
                raise CoreError("bitfield spans >8 bytes")
            byte_sz *= 2
            byte_off = bit_off // 8 // byte_sz * byte_sz
        validate = False  # libbpf: bitfield relos not validated

    if kind == R_FIELD_BYTE_OFFSET:
        return byte_off, validate
    if kind == R_FIELD_BYTE_SIZE:
        return byte_sz, validate
    if kind == R_FIELD_SIGNED:
        if t.kind == K_INT:
            return int(t.int_signed), validate
        if t.kind in (K_ENUM, K_ENUM64):
            return int(t.kflag), validate
        raise CoreError("signed of non-int")
    if kind == R_FIELD_LSHIFT_U64:
        # little-endian
        return 64 - bit_sz - (bit_off - byte_off * 8), validate
    if kind == R_FIELD_RSHIFT_U64:
        return 64 - bit_sz, True
    raise CoreError(f"bad field kind {kind}")


def core_relo_records(elf):
    """Full parse of .BTF.ext core_relo: {secname: [(insn_idx, type_id,
    access_str, kind), ...]}."""
    ext = elf.section_by_name(".BTF.ext")
    btf = elf.section_by_name(".BTF")
    if ext is None or btf is None or len(ext.data) < 32:
        return {}
    d = ext.data
    hdr_len, = struct.unpack_from("<I", d, 4)
    if hdr_len < 32:
        return {}
    core_off, core_len = struct.unpack_from("<II", d, 24)
    if core_len == 0:
        return {}
    b = btf.data
    btf_hdr_len, = struct.unpack_from("<I", b, 4)
    str_off, str_len = struct.unpack_from("<II", b, 16)
    strings = b[btf_hdr_len + str_off:btf_hdr_len + str_off + str_len]

    def cstr(off):
        return strings[off:strings.index(b"\x00", off)].decode()

    out = {}
    pos = hdr_len + core_off
    end = pos + core_len
    rec_size, = struct.unpack_from("<I", d, pos)
    pos += 4
    while pos < end:
        name_off, num = struct.unpack_from("<II", d, pos)
        sec = cstr(name_off)
        pos += 8
        for _ in range(num):
            insn_off, type_id, access_off, kind = struct.unpack_from("<IIII", d, pos)
            out.setdefault(sec, []).append(
                (insn_off // 8, type_id, cstr(access_off), kind))
            pos += rec_size
    return out


class Applier:
    """Applies CO-RE relocations of one object against a target BTF.

    apply() patches executable-section bytes in the BpfElf in place and
    returns {(secname, insn_idx): reason} for every instruction that must
    make the symbolic executor bail if reached (unresolvable relo — libbpf
    poison — or TYPE_ID_LOCAL, whose value is incomparable across objects).
    """

    def __init__(self, target_btf, module_btfs=()):
        """target_btf: vmlinux Btf; module_btfs: split Btfs (kernel modules),
        searched for candidates alongside vmlinux as libbpf does."""
        self.targets = [target_btf] + list(module_btfs)
        self._cand_cache = {}

    def _candidates(self, lbtf, root_id):
        """libbpf bpf_core_find_cands: same essential name AND same raw kind
        as the local root type (typedef roots match typedefs; ENUM and ENUM64
        are mutually compatible). Returns [(target Btf, type id)]."""
        lt = lbtf.types.get(root_id)
        if lt is None or not lt.name:
            return []
        key = (essential_name(lt.name), lt.kind)  # target-side only
        if key in self._cand_cache:
            return self._cand_cache[key]
        kinds = ({K_ENUM, K_ENUM64} if lt.kind in (K_ENUM, K_ENUM64)
                 else {lt.kind})
        cands = []
        for i, tbtf in enumerate(self.targets):
            ids = tbtf.by_name(essential_name(lt.name))
            if i > 0:
                # a split BTF re-lists its base's types; only ids the module
                # itself owns are candidates (the base is a distilled stub
                # set or a vmlinux copy — either way not module material)
                ids = [c for c in ids if c >= tbtf.start_id]
            cands.extend((tbtf, c) for c in ids
                         if tbtf.types[c].kind in kinds)
            if cands:
                # libbpf bpf_core_find_cands: module BTFs are searched only
                # when vmlinux (or an earlier module) yields no candidate
                break
        self._cand_cache[key] = cands
        return cands

    def relocate(self, lbtf, type_id, access_str, kind):
        """Compute (target_value, local_value, validate) or ('poison', why).
        For EXISTS kinds a failed match is value 0, not poison."""
        spec = parse_spec(lbtf, type_id, access_str, kind)

        if kind == R_TYPE_ID_LOCAL:
            return ("local_id", spec.root_id, False)

        exists_kind = kind in (R_FIELD_EXISTS, R_TYPE_EXISTS, R_ENUMVAL_EXISTS,
                               R_TYPE_MATCHES)

        matches = []
        for cbtf, cand in self._candidates(lbtf, type_id):
            if kind == R_TYPE_MATCHES:
                if types_match(lbtf, spec.root_id, cbtf, cand):
                    matches.append((cbtf, cand, None))
            elif kind in TYPE_RELOS:  # TYPE_EXISTS / TYPE_ID_TARGET / TYPE_SIZE
                if types_are_compat(lbtf, spec.root_id, cbtf, cand):
                    matches.append((cbtf, cand, None))
            else:
                tspec = match_spec(spec, cbtf, cand)
                if tspec is not None:
                    matches.append((cbtf, cand, tspec))

        if not matches:
            # type-based relos (and all EXISTS kinds) resolve to 0 when the
            # target type is absent — libbpf only poisons field/enumval value
            # relos (bpf_core_calc_type_relo: "return zero when target type
            # is not found")
            if exists_kind or kind in TYPE_RELOS:
                return (0, self._local_value(lbtf, spec, kind)[0], False)
            return ("poison", f"no target candidate for "
                              f"{lbtf.types[type_id].name or type_id}"
                              f" {KIND_NAMES.get(kind, kind)} '{access_str}'",
                    False)

        if exists_kind:
            return (1, self._local_value(lbtf, spec, kind)[0], False)

        vals = set()
        validate = True
        for cbtf, cand, tspec in matches:
            try:
                if kind in FIELD_RELOS:
                    v, val_ok = _field_info(cbtf, tspec, kind)
                    validate = validate and val_ok
                elif kind == R_TYPE_ID_TARGET:
                    v, validate = cand, False
                elif kind == R_TYPE_SIZE:
                    v = cbtf.type_size(cand)
                    validate = False
                    if v is None:
                        raise CoreError("target type unsizeable")
                elif kind == R_ENUMVAL_VALUE:
                    acc = tspec.accessors[0]
                    v = cbtf.resolve(acc.type_id).enums[acc.idx][1]
                    validate = False
                else:
                    raise CoreError(f"unhandled kind {kind}")
            except CoreError as e:
                return ("poison", str(e), False)
            vals.add(v)
        if len(vals) != 1:
            return ("poison", f"ambiguous candidates: values {sorted(vals)}",
                    False)

        local_val, lval_ok = self._local_value(lbtf, spec, kind)
        return (vals.pop(), local_val, validate and lval_ok)

    def _local_value(self, lbtf, spec, kind):
        """Value the compiler baked into the instruction (for validation)."""
        try:
            if kind in FIELD_RELOS and kind != R_FIELD_EXISTS:
                return _field_info(lbtf, spec, kind)
            if kind == R_FIELD_EXISTS:
                return 1, False
            if kind in (R_TYPE_EXISTS, R_TYPE_MATCHES):
                return 1, False
            if kind == R_TYPE_ID_TARGET:
                return spec.root_id, False
            if kind == R_TYPE_SIZE:
                return lbtf.type_size(spec.root_id) or 0, False
            if kind == R_ENUMVAL_VALUE:
                acc = spec.accessors[0]
                return lbtf.resolve(acc.type_id).enums[acc.idx][1], False
            if kind == R_ENUMVAL_EXISTS:
                return 1, False
        except CoreError:
            return 0, False
        return 0, False

    def apply(self, elf, verbose=False):
        recs = core_relo_records(elf)
        if not recs:
            return {}, []
        lbtf = Btf(elf.section_by_name(".BTF").data)
        poison = {}
        notes = []
        for secname, entries in recs.items():
            sec = elf.section_by_name(secname)
            if sec is None or not sec.data:
                continue
            buf = bytearray(sec.data)
            for insn_idx, type_id, access_str, kind in entries:
                label = f"{secname}+{insn_idx}"
                try:
                    res = self.relocate(lbtf, type_id, access_str, kind)
                except CoreError as e:
                    res = ("poison", f"local spec: {e}", False)
                if res[0] == "poison":
                    self._poison_insn(buf, insn_idx)
                    poison[(secname, insn_idx)] = res[1]
                    notes.append(f"POISON {label}: {res[1]}")
                    continue
                if res[0] == "local_id":
                    # patched faithfully below, but incomparable across objects
                    val = res[1]
                    poison[(secname, insn_idx)] = "core-type-id-local"
                    err = self._patch_insn(buf, insn_idx, val, None, False)
                    if err:
                        notes.append(f"PATCHFAIL {label}: {err}")
                    continue
                val, local_val, validate = res
                err = self._patch_insn(buf, insn_idx, val, local_val, validate)
                if err:
                    self._poison_insn(buf, insn_idx)
                    poison[(secname, insn_idx)] = err
                    notes.append(f"PATCHFAIL {label}: {err}")
                elif verbose:
                    notes.append(f"OK {label}: {KIND_NAMES.get(kind, kind)} "
                                 f"{local_val} -> {val}")
            # write back (Section is a namedtuple)
            i = sec.idx
            elf.sections[i] = elf.sections[i]._replace(data=bytes(buf))
        return poison, notes

    @staticmethod
    def _poison_insn(buf, idx):
        # libbpf: convert to invalid `call 0xbad2310`
        struct.pack_into("<BBHi", buf, idx * 8, 0x85, 0, 0, POISON_CALL_IMM)

    @staticmethod
    def _patch_insn(buf, idx, val, local_val, validate):
        """Returns error string or None. Mirrors bpf_core_patch_insn."""
        off = idx * 8
        code = buf[off]
        cls = code & 0x07
        if cls in (1, 2, 3):  # LDX/ST/STX: patch off16
            old_off, = struct.unpack_from("<h", buf, off + 2)
            if validate and local_val is not None and old_off != local_val:
                return f"insn off {old_off} != local spec {local_val}"
            if not -32768 <= val <= 32767:
                return f"new off {val} doesn't fit in s16"
            struct.pack_into("<h", buf, off + 2, val)
            return None
        if cls in (4, 7):  # ALU/ALU64 (BPF_K expected): patch imm
            if code & 0x08:
                return "ALU with BPF_X src carries a relo"
            old_imm, = struct.unpack_from("<i", buf, off + 4)
            if validate and local_val is not None and old_imm != local_val:
                return f"insn imm {old_imm} != local spec {local_val}"
            if not -2**31 <= val < 2**31:
                return f"new imm {val} doesn't fit in s32"
            struct.pack_into("<i", buf, off + 4, val)
            return None
        if code == 0x18:  # LD_IMM64: patch 64-bit imm pair
            if off + 16 > len(buf):
                return "ld_imm64 relo at section end"
            old_lo, = struct.unpack_from("<i", buf, off + 4)
            old_hi, = struct.unpack_from("<i", buf, off + 12)
            old = ((old_hi << 32) | (old_lo & 0xFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
            if (validate and local_val is not None
                    and old != local_val & 0xFFFFFFFFFFFFFFFF):
                return f"insn imm64 {old} != local spec {local_val}"
            v = val & 0xFFFFFFFFFFFFFFFF
            lo = v & 0xFFFFFFFF
            hi = v >> 32
            struct.pack_into("<i", buf, off + 4, lo - 2**32 if lo >= 2**31 else lo)
            struct.pack_into("<i", buf, off + 12, hi - 2**32 if hi >= 2**31 else hi)
            return None
        return f"unexpected insn code 0x{code:02x} for relo"


def load_kernel_btf(path, base=None):
    """Read raw BTF from a .btf dump or extract .BTF from an ELF (vmlinux or
    a module .ko — pass base=vmlinux Btf for the module's split BTF)."""
    with open(path, "rb") as f:
        head = f.read(4)
    if head == b"\x7fELF":
        import bpfelf
        elf = bpfelf.BpfElf(path)
        sec = elf.section_by_name(".BTF")
        if sec is None:
            raise ValueError(f"{path}: no .BTF section")
        # modules built with a distilled base carry it in .BTF.base and
        # their split BTF is relative to THAT, not to full vmlinux (libbpf
        # auto-detects this the same way)
        base_sec = elf.section_by_name(".BTF.base")
        if base_sec is not None and base_sec.data:
            base = Btf(base_sec.data)
        return Btf(sec.data, base)
    with open(path, "rb") as f:
        return Btf(f.read(), base)
