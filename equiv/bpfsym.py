"""Symbolic executor: lifts BPF bytecode to Z3 and produces per-path summaries.

Value model
-----------
Registers hold either a plain 64-bit bitvector (data) or Ptr(region, off) —
a pointer into a named memory region. Regions:

  ctx          shared symbolic byte array (the program's context argument)
  kmem         shared symbolic byte array indexed by absolute address; backs
               loads through data-valued pointers (fentry PROBE_MEM reads of
               kernel structs). Read-only; assumed non-faulting.
  g:<symbol>   one region per named global (bss/data): shared symbolic init
               array, so both programs see the same pre-run state. Writes are
               the observable output.
  ro:<obj>:<sec>  per-object read-only section with concrete initial bytes.
  stack:<tag>  per-run 512-byte frame, r10 = end.
  map:<name>   opaque map pointer (identity only; deref bails).

Unsupported constructs raise Bail — the driver reports the program as
out-of-scope rather than guessing.
"""
import z3

from bpfelf import (SHF_ALLOC, SHF_EXECINSTR, SHT_NOBITS, STT_SECTION,
                    normalize_name)

STACK_SIZE = 512
MAX_INSNS_PER_PATH = 50_000
MAX_PATHS = 4096
FEAS_TIMEOUT_MS = 200
MAX_COPY = 512  # largest concrete probe_read size we'll expand byte-wise

# Argument-free helpers whose return value is environment-determined: modeled
# as a shared oracle stream — the nth call in the C program and the nth call
# in the Rust program observe the same value. Value is the helper's true
# return width (zero-extended), so impossible upper bits can't fake diffs.
PURE_ORACLE_HELPERS = {
    5: 64,    # ktime_get_ns
    7: 32,    # get_prandom_u32
    8: 32,    # get_smp_processor_id
    14: 64,   # get_current_pid_tgid
    15: 64,   # get_current_uid_gid
    35: 64,   # get_current_task
    42: 32,   # get_numa_node_id
    125: 64,  # ktime_get_boot_ns
    158: 64,  # get_current_task_btf
    160: 64,  # ktime_get_coarse_ns
    208: 64,  # ktime_get_tai_ns
}
PROBE_READ_HELPERS = {4, 112, 113}       # probe_read, _kernel, _user
PROBE_READ_STR_HELPERS = {45, 114, 115}  # probe_read_str, _kernel_str, _user_str

# Tier 2: side-effecting helpers become events in a shared observable trace
# region — equivalence then requires both programs to make the same call
# sequence with the same arguments (pointer args compared by pointed-to
# bytes, sizes from the map's BTF def). Their environment-determined errno
# return is a shared per-call-index oracle, sign-extended from 32 bits (real
# returns fit in an int; full-width symbolic values would fake divergences
# between C long compares and Rust i32 compares). Sharing per index is sound
# because equal traces imply equal map/env state at the nth call.
H_MAP_UPDATE, H_MAP_DELETE = 2, 3
H_MAP_PUSH, H_MAP_POP, H_MAP_PEEK = 87, 88, 89
H_PERF_EVENT_OUTPUT, H_RINGBUF_OUTPUT = 25, 130
H_GET_STACKID = 27
H_TRACE_PRINTK = 6
H_GET_CURRENT_COMM = 16
H_SKB_LOAD_BYTES = 26
H_GET_RETVAL, H_SET_RETVAL = 186, 187  # 4-byte shared "sysret" state region

# Environment refinement: values the kernel can actually produce.
# pid_tgid packs tgid<<32|pid, both bounded by PID_MAX_LIMIT (< 2^31) —
# without this, C's sign-extended int-vs-u64 pid compares "diverge" from
# Rust's 32-bit compares on impossible tgid values.
ORACLE_MASK = {14: 0x7FFFFFFF_7FFFFFFF}

BV64S = z3.BitVecSort(64)
BV32S = z3.BitVecSort(32)
BV8S = z3.BitVecSort(8)


class Bail(Exception):
    """Program uses a construct the executor doesn't model yet."""


class Ptr:
    __slots__ = ("region", "off")

    def __init__(self, region, off):
        self.region = region
        self.off = off  # BV64

    def __repr__(self):
        return f"Ptr({self.region}, {self.off})"


def bv64(x):
    return z3.BitVecVal(x & 0xFFFFFFFFFFFFFFFF, 64)


def is_ptr(v):
    return isinstance(v, Ptr)


def need_data(v, what):
    if is_ptr(v):
        raise Bail(f"pointer used as data in {what} (region {v.region})")
    return v


def lo32(v):
    return z3.Extract(31, 0, v)


def zext64(v32):
    return z3.ZeroExt(32, v32)


class Path:
    """One executed path: conjunction of branch conditions + final state."""

    def __init__(self, conds, ret, mem):
        self.conds = conds      # list of z3 Bool
        self.ret = ret          # BV64 (r0 at exit)
        self.mem = mem          # region -> array expr at exit


class Executor:
    def __init__(self, elf, sec, shared, tag):
        """shared: dict of region name -> z3 array, common to both programs."""
        self.elf = elf
        self.sec = sec
        self.shared = shared
        self.tag = tag  # 'A' / 'B', namespaces per-run regions
        self.insns = self._decode(sec)
        self.paths = []
        self.nclobber = 0
        self.feas = z3.Solver()
        self.feas.set("timeout", FEAS_TIMEOUT_MS)

    # ---------- decode ----------

    def _decode(self, sec):
        data = sec.data
        if len(data) % 8:
            raise Bail(f"section {sec.name} size not insn-aligned")
        relocs = self.elf.relocs.get(sec.idx, {})
        insns = []
        i = 0
        n = len(data) // 8
        while i < n:
            off = i * 8
            op = data[off]
            dst = data[off + 1] & 0xF
            src = data[off + 1] >> 4
            soff = int.from_bytes(data[off + 2:off + 4], "little", signed=True)
            imm = int.from_bytes(data[off + 4:off + 8], "little", signed=True)
            ins = dict(op=op, dst=dst, src=src, off=soff, imm=imm, reloc=relocs.get(off))
            if op == 0x18:  # ld_imm64: two slots
                if i + 1 >= n:
                    raise Bail("truncated ld_imm64")
                hi = int.from_bytes(data[off + 12:off + 16], "little", signed=False)
                ins["imm64"] = (imm & 0xFFFFFFFF) | (hi << 32)
                insns.append(ins)
                insns.append(None)  # second slot placeholder
                i += 2
                continue
            insns.append(ins)
            i += 1
        return insns

    # ---------- memory regions ----------

    def _region_array(self, mem, region):
        if region in mem:
            return mem[region]
        if region in self.shared:
            mem[region] = self.shared[region]
        elif region.startswith("stack:"):
            # Initial (uninit) stack garbage is shared between the two runs —
            # the bisimulation assumption that both environments hand the
            # program the same residue. Writes still diverge per run.
            mem[region] = z3.Array("stack_init", z3.BitVecSort(64), z3.BitVecSort(8))
        elif region.startswith("ro:"):
            mem[region] = self._concrete_array(region)
        else:
            raise Bail(f"load/store in unmodeled region {region}")
        return mem[region]

    def _concrete_array(self, region):
        _, _obj, secname = region.split(":", 2)
        s = self.elf.section_by_name(secname)
        arr = z3.K(z3.BitVecSort(64), z3.BitVecVal(0, 8))
        for i, b in enumerate(s.data):
            if b:
                arr = z3.Store(arr, bv64(i), z3.BitVecVal(b, 8))
        return arr

    def _load(self, mem, ptr, size):
        if is_ptr(ptr):
            region, addr = ptr.region, ptr.off
            if region.startswith("map:"):
                raise Bail(f"deref of map pointer {region}")
        else:
            region, addr = "kmem", ptr  # probe-read of kernel memory
        arr = self._region_array(mem, region)
        byts = [z3.Select(arr, addr + bv64(k)) for k in range(size)]
        val = z3.Concat(*reversed(byts)) if size > 1 else byts[0]
        return z3.ZeroExt(64 - size * 8, val) if size < 8 else val

    def _store(self, mem, ptr, size, val):
        if not is_ptr(ptr):
            raise Bail("store through data-valued (kernel) pointer")
        region, addr = ptr.region, ptr.off
        if region.startswith(("ro:", "map:")) or region == "kmem":
            raise Bail(f"store into read-only region {region}")
        arr = self._region_array(mem, region)
        for k in range(size):
            arr = z3.Store(arr, addr + bv64(k), z3.Extract(8 * k + 7, 8 * k, val))
        mem[region] = arr

    # ---------- relocation resolution ----------

    def _resolve_ld64(self, ins):
        rel = ins["reloc"]
        addend = ins["imm64"]
        if rel is None:
            return bv64(addend)
        sym = rel.sym
        if sym.type == STT_SECTION:
            secname = self.elf.sections[sym.shndx].name
            named = self.elf.named_symbol_at(sym.shndx, addend)
            if named is not None:
                sym, addend = named, addend - named.value
            else:
                return self._section_ptr(secname, addend)
        secname = self.elf.sections[sym.shndx].name
        if secname == ".maps":
            return Ptr(f"map:{normalize_name(sym.name)}", bv64(addend))
        sec = self.elf.sections[sym.shndx]
        if not sec.flags & SHF_ALLOC or sec.flags & SHF_EXECINSTR:
            raise Bail(f"reloc into unsupported section {secname}")
        if secname.startswith(".rodata"):
            return Ptr(f"ro:{self.tag}:{secname}", bv64(sym.value + addend))
        return Ptr(f"g:{normalize_name(sym.name)}", bv64(addend))

    def _section_ptr(self, secname, addend):
        if secname.startswith(".rodata") or ".rodata" in secname:
            return Ptr(f"ro:{self.tag}:{secname}", bv64(addend))
        raise Bail(f"anonymous reloc into {secname}+{addend:#x}")

    # ---------- ALU ----------

    def _alu(self, code, is64, dst, src_val, soff, what):
        if code == 11:  # MOV
            if soff in (8, 16, 32) and not is_ptr(src_val):  # MOVSX
                s = z3.SignExt(64 - soff, z3.Extract(soff - 1, 0, src_val))
                return s if is64 else zext64(lo32(s))
            if is64:
                return src_val
            return zext64(lo32(need_data(src_val, what)))
        if code == 0 and is64:  # ADD
            if is_ptr(dst) and not is_ptr(src_val):
                return Ptr(dst.region, dst.off + src_val)
            if is_ptr(src_val) and not is_ptr(dst):
                return Ptr(src_val.region, src_val.off + dst)
        if code == 1 and is64 and is_ptr(dst):  # SUB
            if is_ptr(src_val):
                if src_val.region != dst.region:
                    raise Bail("pointer difference across regions")
                return dst.off - src_val.off
            return Ptr(dst.region, dst.off - src_val)
        a = need_data(dst, what)
        b = need_data(src_val, what)
        if not is64:
            a, b = lo32(a), lo32(b)
        w = 64 if is64 else 32

        def zx(v):
            return v if is64 else zext64(v)

        if code == 0:
            return zx(a + b)
        if code == 1:
            return zx(a - b)
        if code == 2:
            return zx(a * b)
        if code == 3:  # DIV / SDIV(off=1); div-by-zero -> 0
            q = (a / b) if soff == 1 else z3.UDiv(a, b)
            return zx(z3.If(b == 0, z3.BitVecVal(0, w), q))
        if code == 4:
            return zx(a | b)
        if code == 5:
            return zx(a & b)
        if code == 6:
            return zx(a << (b & (w - 1)))
        if code == 7:
            return zx(z3.LShR(a, b & (w - 1)))
        if code == 8:
            return zx(-a)
        if code == 9:  # MOD / SMOD(off=1); mod-by-zero -> dst unchanged
            r = z3.SRem(a, b) if soff == 1 else z3.URem(a, b)
            return zx(z3.If(b == 0, a, r))
        if code == 10:
            return zx(a ^ b)
        if code == 12:
            return zx(a >> (b & (w - 1)))
        raise Bail(f"ALU opcode {code} in {what}")

    def _endian_op(self, op, is64_cls, v, width, what):
        """BPF_END: to_le/to_be (ALU class) or unconditional bswap (ALU64
        class). Target is little-endian; result is zero-extended."""
        if width not in (16, 32, 64):
            raise Bail(f"bswap width {width} in {what}")
        low = z3.Extract(width - 1, 0, v)
        swapped = z3.Concat(*[z3.Extract(8 * k + 7, 8 * k, low)
                              for k in range(width // 8)])
        if is64_cls or op & 8:   # bswap, or to_be on a LE target
            res = swapped
        else:                    # to_le on a LE target: just truncate
            res = low
        return z3.ZeroExt(64 - width, res) if width < 64 else res

    # ---------- atomics ----------

    def _atomic(self, ins, regs, mem, what):
        """STX mode 6: read-modify-write on [dst+off]; returns new regs."""
        size = (8, 4, 2, 1)[[3, 0, 1, 2].index((ins["op"] >> 3) & 3)]
        aop = ins["imm"]
        if aop in (0x100, 0x110):  # LOAD_ACQ / STORE_REL: plain load/store
            # under sequential semantics; note LOAD_ACQ's pointer is src
            regs = regs[:]
            if aop == 0x100:
                ptr = regs[ins["src"]]
                p = Ptr(ptr.region, ptr.off + bv64(ins["off"])) if is_ptr(ptr) \
                    else need_data(ptr, what) + bv64(ins["off"])
                regs[ins["dst"]] = self._load(mem, p, size)
            else:
                ptr = regs[ins["dst"]]
                p = Ptr(ptr.region, ptr.off + bv64(ins["off"])) if is_ptr(ptr) \
                    else need_data(ptr, what) + bv64(ins["off"])
                self._store(mem, p, size, need_data(regs[ins["src"]], what))
            return regs
        if size not in (4, 8):
            raise Bail(f"atomic size {size} in {what}")
        ptr = regs[ins["dst"]]
        p = Ptr(ptr.region, ptr.off + bv64(ins["off"])) if is_ptr(ptr) \
            else need_data(ptr, what) + bv64(ins["off"])
        srcv = need_data(regs[ins["src"]], what)
        old = self._load(mem, p, size)  # zero-extended to 64
        regs = regs[:]
        if aop == 0xF1:  # CMPXCHG: compares r0, stores src on match, r0 = old
            w = size * 8
            eq = z3.Extract(w - 1, 0, old) == z3.Extract(w - 1, 0, regs[0])
            self._store(mem, p, size, z3.If(eq, srcv, old))
            regs[0] = old
            return regs
        if aop == 0xE1:  # XCHG
            new = srcv
        elif aop & ~1 in (0x00, 0x40, 0x50, 0xA0):  # ADD/OR/AND/XOR [|FETCH]
            fn = {0x00: lambda a, b: a + b, 0x40: lambda a, b: a | b,
                  0x50: lambda a, b: a & b, 0xA0: lambda a, b: a ^ b}[aop & ~1]
            new = fn(old, srcv)
        else:
            raise Bail(f"atomic imm {aop:#x} in {what}")
        self._store(mem, p, size, new)
        if aop == 0xE1 or aop & 1:  # XCHG and FETCH variants return old
            regs[ins["src"]] = old
        return regs

    # ---------- JMP condition ----------

    def _cond(self, code, is32, dstv, srcv, what):
        if is_ptr(dstv) or is_ptr(srcv):
            # pointer comparisons: only ptr==ptr same region, or ptr vs NULL
            if is_ptr(dstv) and is_ptr(srcv) and dstv.region == srcv.region:
                dstv, srcv = dstv.off, srcv.off
            elif is_ptr(dstv) and not is_ptr(srcv):
                # LD_IMM64 global/map pointers are never NULL
                if code == 1:
                    return z3.BoolVal(False)  # JEQ ptr, 0
                if code == 5:
                    return z3.BoolVal(True)   # JNE ptr, 0
                raise Bail(f"pointer/scalar compare in {what}")
            else:
                raise Bail(f"pointer compare across regions in {what}")
        if is32:
            dstv, srcv = lo32(dstv), lo32(srcv)
        ops = {
            1: lambda a, b: a == b,
            2: z3.UGT, 3: z3.UGE,
            4: lambda a, b: (a & b) != 0,
            5: lambda a, b: a != b,
            6: lambda a, b: a > b, 7: lambda a, b: a >= b,
            10: z3.ULT, 11: z3.ULE,
            12: lambda a, b: a < b, 13: lambda a, b: a <= b,
        }
        if code not in ops:
            raise Bail(f"JMP opcode {code} in {what}")
        return ops[code](dstv, srcv)

    # ---------- helper calls (tier 1) ----------

    def _addr_add(self, p, k):
        if is_ptr(p):
            return Ptr(p.region, p.off + bv64(k))
        return p + bv64(k)

    def _concrete_u64(self, v, what):
        if is_ptr(v):
            raise Bail(f"pointer where scalar expected in {what}")
        v = z3.simplify(v)
        if not z3.is_bv_value(v):
            raise Bail(f"symbolic size argument in {what}")
        return v.as_long()

    # ---------- tier-2 machinery: observable call trace ----------

    def _emit_event(self, mem, counters, hid, payload):
        """Append [hid:1][len:2][payload] to the shared trace region.

        The cursor is concrete (event sizes are concrete), so equal call
        sequences write identical bytes at identical offsets; the first
        diverging event differs in place, and a missing trailing event
        leaves symbolic trace_init residue that some input distinguishes."""
        cur = counters.get("cursor", 0)
        arr = self._region_array(mem, "trace")
        ev = [hid & 0xFF, len(payload) & 0xFF, (len(payload) >> 8) & 0xFF] + payload
        for k, b in enumerate(ev):
            b = z3.BitVecVal(b, 8) if isinstance(b, int) else b
            arr = z3.Store(arr, bv64(cur + k), b)
        mem["trace"] = arr
        counters["cursor"] = cur + len(ev)

    def _errno_oracle(self, hid, idx):
        f = z3.Function(f"oracle_err_h{hid}", BV64S, BV32S)
        return z3.SignExt(32, f(bv64(idx)))

    def _map_name(self, v, what):
        if not is_ptr(v) or not v.region.startswith("map:"):
            raise Bail(f"non-map pointer as map argument in {what}")
        return v.region[4:]

    def _map_kv(self, mname, what):
        d = self.elf.map_defs().get(mname)
        if d is None:
            raise Bail(f"no BTF def for map {mname} in {what}")
        return d["key_size"], d["value_size"]

    def _name_bytes(self, name):
        enc = name.encode()
        return [len(enc) & 0xFF] + list(enc)

    def _mem_bytes(self, mem, ptr, n, what):
        if n > MAX_COPY:
            raise Bail(f"arg byte compare of {n} > {MAX_COPY} in {what}")
        return [z3.Extract(7, 0, self._load(mem, self._addr_add(ptr, k), 1))
                for k in range(n)]

    def _val_bytes(self, v, n, what):
        v = need_data(v, what)
        return [z3.Extract(8 * k + 7, 8 * k, v) for k in range(n)]

    def _concrete_bytes(self, mem, ptr, n, what):
        out = []
        for k in range(n):
            b = z3.simplify(self._load(mem, self._addr_add(ptr, k), 1))
            if not z3.is_bv_value(b):
                raise Bail(f"symbolic byte in {what}")
            out.append(b.as_long())
        return out

    def _printk_arg_widths(self, fmt, what):
        """Byte widths of the args a bpf_printk format consumes."""
        widths, i = [], 0
        while i < len(fmt):
            if fmt[i] != ord("%"):
                i += 1
                continue
            i += 1
            if i < len(fmt) and fmt[i] == ord("%"):
                i += 1
                continue
            while i < len(fmt) and chr(fmt[i]) in "0123456789.-+ #":
                i += 1
            longs = 0
            while i < len(fmt) and fmt[i] == ord("l"):
                longs += 1
                i += 1
            conv = chr(fmt[i]) if i < len(fmt) else "?"
            if conv not in "diuxXc":
                raise Bail(f"printk conversion %{'l' * longs}{conv} in {what}")
            widths.append(8 if longs else 4)
            i += 1
        if len(widths) > 3:
            raise Bail(f"printk with {len(widths)} args in {what}")
        return widths

    # ---------- helper dispatch ----------

    def _helper_call(self, hid, regs, mem, counters, what):
        """Model one helper call; mutates mem/counters, returns new regs."""
        idx = counters.get(hid, 0)
        counters[hid] = idx + 1
        dst, size, src = regs[1], regs[2], regs[3]

        if hid in PURE_ORACLE_HELPERS:
            width = PURE_ORACLE_HELPERS[hid]
            f = z3.Function(f"oracle_h{hid}", BV64S, z3.BitVecSort(width))
            ret = z3.ZeroExt(64 - width, f(bv64(idx))) if width < 64 else f(bv64(idx))
            if hid in ORACLE_MASK:
                ret = ret & bv64(ORACLE_MASK[hid])
        elif hid in PROBE_READ_HELPERS:
            n = self._concrete_u64(size, what)
            if n > MAX_COPY:
                raise Bail(f"probe_read size {n} > {MAX_COPY} in {what}")
            for k in range(n):  # assumed non-faulting (see module docstring)
                byte = self._load(mem, self._addr_add(src, k), 1)
                self._store(mem, self._addr_add(dst, k), 1, byte)
            ret = bv64(0)
        elif hid in PROBE_READ_STR_HELPERS:
            n = self._concrete_u64(size, what)
            if n > MAX_COPY:
                raise Bail(f"probe_read_str size {n} > {MAX_COPY} in {what}")
            # NUL position abstracted as a shared oracle length in [1, n]:
            # both programs' nth _str call sees the same L and the same bytes.
            # Out-of-range oracle values clamp to 1 (keeps L in range without
            # polluting path conditions with environment assumptions).
            Lr = z3.Function(f"oracle_strlen_h{hid}", BV64S, BV64S)(bv64(idx))
            L = z3.If(z3.And(z3.UGE(Lr, bv64(1)), z3.ULE(Lr, bv64(n))),
                      Lr, bv64(1))
            for k in range(n):
                old = self._load(mem, self._addr_add(dst, k), 1)
                kb = self._load(mem, self._addr_add(src, k), 1)
                val = z3.If(z3.ULT(bv64(k + 1), L), kb,
                            z3.If(bv64(k + 1) == L, bv64(0), old))
                self._store(mem, self._addr_add(dst, k), 1, val)
            ret = L
        elif hid in (H_MAP_UPDATE, H_MAP_PUSH):
            mname = self._map_name(regs[1], what)
            ks, vs = self._map_kv(mname, what)
            if vs is None or (hid == H_MAP_UPDATE and ks is None):
                raise Bail(f"map {mname} def lacks key/value size in {what}")
            payload = self._name_bytes(mname)
            if hid == H_MAP_UPDATE:
                payload += self._mem_bytes(mem, regs[2], ks, what)
                payload += self._mem_bytes(mem, regs[3], vs, what)
                flags = regs[4]
            else:
                payload += self._mem_bytes(mem, regs[2], vs, what)
                flags = regs[3]
            payload += self._val_bytes(flags, 8, what)
            self._emit_event(mem, counters, hid, payload)
            ret = self._errno_oracle(hid, idx)
        elif hid == H_MAP_DELETE:
            mname = self._map_name(regs[1], what)
            ks, _vs = self._map_kv(mname, what)
            if ks is None:
                raise Bail(f"map {mname} def lacks key size in {what}")
            payload = self._name_bytes(mname) + self._mem_bytes(mem, regs[2], ks, what)
            self._emit_event(mem, counters, hid, payload)
            ret = self._errno_oracle(hid, idx)
        elif hid in (H_MAP_POP, H_MAP_PEEK):
            # State-dependent read (pop also mutates): event keeps the call
            # order observable; the value produced is a shared per-index
            # oracle, written only on success, so equal traces see equal data.
            mname = self._map_name(regs[1], what)
            _ks, vs = self._map_kv(mname, what)
            if vs is None:
                raise Bail(f"map {mname} def lacks value size in {what}")
            self._emit_event(mem, counters, hid, self._name_bytes(mname))
            err = self._errno_oracle(hid, idx)
            f = z3.Function(f"oracle_val_h{hid}", BV64S, BV64S, BV8S)
            for k in range(vs):
                old = z3.Extract(7, 0, self._load(mem, self._addr_add(regs[2], k), 1))
                self._store(mem, self._addr_add(regs[2], k), 1,
                            z3.If(err == bv64(0), f(bv64(idx), bv64(k)), old))
            ret = err
        elif hid == H_PERF_EVENT_OUTPUT:
            mname = self._map_name(regs[2], what)
            n = self._concrete_u64(regs[5], what)
            payload = (self._name_bytes(mname) + self._val_bytes(regs[3], 8, what)
                       + self._mem_bytes(mem, regs[4], n, what))
            self._emit_event(mem, counters, hid, payload)
            ret = self._errno_oracle(hid, idx)
        elif hid == H_RINGBUF_OUTPUT:
            mname = self._map_name(regs[1], what)
            n = self._concrete_u64(regs[3], what)
            payload = (self._name_bytes(mname) + self._mem_bytes(mem, regs[2], n, what)
                       + self._val_bytes(regs[4], 8, what))
            self._emit_event(mem, counters, hid, payload)
            ret = self._errno_oracle(hid, idx)
        elif hid == H_GET_STACKID:
            mname = self._map_name(regs[2], what)
            payload = self._name_bytes(mname) + self._val_bytes(regs[3], 8, what)
            self._emit_event(mem, counters, hid, payload)
            ret = self._errno_oracle(hid, idx)
        elif hid == H_TRACE_PRINTK:
            n = self._concrete_u64(size, what) & 0xFFFFFFFF
            if n > MAX_COPY:
                raise Bail(f"printk fmt size {n} > {MAX_COPY} in {what}")
            fmt = self._concrete_bytes(mem, dst, n, what)
            payload = [n & 0xFF, (n >> 8) & 0xFF] + fmt
            for j, w in enumerate(self._printk_arg_widths(fmt, what)):
                payload += self._val_bytes(regs[3 + j], w, what)
            self._emit_event(mem, counters, hid, payload)
            ret = self._errno_oracle(hid, idx)
        elif hid == H_GET_CURRENT_COMM:
            # Deterministic environment read: contents are a shared oracle
            # keyed by (buffer size, position) — kernel pads/NULs per size,
            # so different sizes must not alias. Zero-filled on error.
            n = self._concrete_u64(size, what) & 0xFFFFFFFF
            if n > MAX_COPY:
                raise Bail(f"comm size {n} > {MAX_COPY} in {what}")
            err = z3.SignExt(32, z3.Function("oracle_comm_err", BV64S, BV32S)(bv64(n)))
            f = z3.Function("oracle_comm", BV64S, BV64S, BV8S)
            for k in range(n):
                self._store(mem, self._addr_add(dst, k), 1,
                            z3.If(err == bv64(0), f(bv64(n), bv64(k)),
                                  z3.BitVecVal(0, 8)))
            ret = err
        elif hid == H_SKB_LOAD_BYTES:
            # Packet payload = shared symbolic array; success is a shared
            # oracle keyed by (offset, len) — the environment answers the
            # same question the same way in both programs. Zero-fill on error.
            if not is_ptr(regs[1]) or regs[1].region != "ctx":
                raise Bail(f"skb_load_bytes on non-ctx skb in {what}")
            if "skbdata" not in self.shared:
                raise Bail(f"no skbdata region provided in {what}")
            off = zext64(lo32(need_data(regs[2], what)))
            n = self._concrete_u64(regs[4], what) & 0xFFFFFFFF
            if n > MAX_COPY:
                raise Bail(f"skb_load_bytes len {n} > {MAX_COPY} in {what}")
            skb = self.shared["skbdata"]
            err = z3.SignExt(32, z3.Function("oracle_skb_err", BV64S, BV64S,
                                             BV32S)(off, bv64(n)))
            for k in range(n):
                self._store(mem, self._addr_add(regs[3], k), 1,
                            z3.If(err == bv64(0), z3.Select(skb, off + bv64(k)),
                                  z3.BitVecVal(0, 8)))
            ret = err
        elif hid == H_GET_RETVAL:
            # reads the syscall-retval cell; helper returns int, and the
            # BPF_CALL wrapper's int->u64 conversion sign-extends
            ret = z3.SignExt(32, z3.Extract(31, 0,
                                            self._load(mem, Ptr("sysret", bv64(0)), 4)))
        elif hid == H_SET_RETVAL:
            self._store(mem, Ptr("sysret", bv64(0)), 4, need_data(regs[1], what))
            err = z3.Function("oracle_setretval_err", BV32S, BV32S)
            ret = z3.SignExt(32, err(lo32(need_data(regs[1], what))))
        else:
            raise Bail(f"helper {hid} in {what}")

        regs = regs[:]
        regs[0] = ret
        for i in range(1, 6):  # caller-saved, unreadable after the call
            self.nclobber += 1
            regs[i] = z3.BitVec(f"clobber_{self.tag}_{self.nclobber}", 64)
        return regs

    # ---------- main loop ----------

    def run(self, entry_pc=0):
        regs = [None] * 11
        for i in range(10):
            regs[i] = z3.BitVec(f"uninit_{self.tag}_r{i}", 64)
        regs[1] = Ptr("ctx", bv64(0))
        regs[10] = Ptr(f"stack:{self.tag}", bv64(STACK_SIZE))
        self.init_r0 = regs[0]
        work = [(entry_pc, regs, {}, [], {})]
        while work:
            if len(self.paths) + len(work) > MAX_PATHS:
                raise Bail("path explosion (> MAX_PATHS)")
            pc, regs, mem, conds, counters = work.pop()
            steps = 0
            while True:
                steps += 1
                if steps > MAX_INSNS_PER_PATH:
                    raise Bail("path too long (loop?)")
                if pc < 0 or pc >= len(self.insns) or self.insns[pc] is None:
                    raise Bail(f"jump to invalid pc {pc}")
                ins = self.insns[pc]
                op, dst, src = ins["op"], ins["dst"], ins["src"]
                cls = op & 7
                what = f"{self.sec.name}@{pc}"

                if op == 0x18:  # ld_imm64
                    if src not in (0,):
                        # pseudo-src set at .o stage is unusual; relocs carry meaning
                        raise Bail(f"ld_imm64 pseudo src={src} in {what}")
                    regs = regs[:]
                    regs[dst] = self._resolve_ld64(ins)
                    pc += 2
                    continue

                if cls in (4, 7) and (op >> 4) == 13:  # END (byte swap family)
                    regs = regs[:]
                    regs[dst] = self._endian_op(op, cls == 7,
                                                need_data(regs[dst], what),
                                                ins["imm"], what)
                    pc += 1
                    continue

                if cls in (4, 7):  # ALU32 / ALU64
                    is64 = cls == 7
                    srcv = regs[src] if op & 8 else bv64(ins["imm"]) if is64 \
                        else zext64(z3.BitVecVal(ins["imm"] & 0xFFFFFFFF, 32))
                    if (op >> 4) == 8:  # NEG has no source operand
                        srcv = bv64(0)
                    regs = regs[:]
                    regs[dst] = self._alu(op >> 4, is64, regs[dst], srcv, ins["off"], what)
                    pc += 1
                    continue

                if cls == 1:  # LDX
                    mode = (op >> 5) & 7
                    size = (8, 4, 2, 1)[[3, 0, 1, 2].index((op >> 3) & 3)]
                    ptr = regs[src]
                    p = Ptr(ptr.region, ptr.off + bv64(ins["off"])) if is_ptr(ptr) \
                        else need_data(ptr, what) + bv64(ins["off"])
                    val = self._load(mem, p, size)
                    if mode == 4:  # MEMSX
                        val = z3.SignExt(64 - size * 8, z3.Extract(size * 8 - 1, 0, val))
                    elif mode != 3:
                        raise Bail(f"LDX mode {mode} in {what}")
                    regs = regs[:]
                    regs[dst] = val
                    pc += 1
                    continue

                if cls in (2, 3):  # ST / STX
                    mode = (op >> 5) & 7
                    if mode == 6:  # atomic (sequential semantics — the model
                        # is single-threaded, same stance as everywhere else)
                        if cls != 3:
                            raise Bail(f"atomic ST in {what}")
                        mem = dict(mem)
                        regs = self._atomic(ins, regs, mem, what)
                        pc += 1
                        continue
                    if mode != 3:
                        raise Bail(f"store mode {mode} in {what}")
                    size = (8, 4, 2, 1)[[3, 0, 1, 2].index((op >> 3) & 3)]
                    ptr = regs[dst]
                    p = Ptr(ptr.region, ptr.off + bv64(ins["off"])) if is_ptr(ptr) \
                        else need_data(ptr, what) + bv64(ins["off"])
                    val = bv64(ins["imm"]) if cls == 2 else regs[src]
                    if is_ptr(val):
                        raise Bail(f"spilled pointer store in {what}")
                    mem = dict(mem)
                    self._store(mem, p, size, val)
                    pc += 1
                    continue

                if cls in (5, 6):  # JMP / JMP32
                    code = op >> 4
                    if code == 8:
                        if src == 1:
                            raise Bail(f"subprog call in {what}")
                        if src == 2:
                            raise Bail(f"kfunc call in {what}")
                        mem = dict(mem)
                        regs = self._helper_call(ins["imm"], regs, mem,
                                                 counters, what)
                        pc += 1
                        continue
                    if code == 9:  # EXIT
                        ret = need_data(regs[0], what)
                        self.paths.append(Path(conds, ret, mem))
                        break
                    if code == 0:  # JA (gotol when JMP32)
                        pc += 1 + (ins["imm"] if cls == 6 else ins["off"])
                        continue
                    if code == 14:
                        raise Bail(f"JCOND/may_goto in {what}")
                    srcv = regs[src] if op & 8 else \
                        (bv64(ins["imm"]) if cls == 5
                         else zext64(z3.BitVecVal(ins["imm"] & 0xFFFFFFFF, 32)))
                    c = z3.simplify(self._cond(code, cls == 6, regs[dst], srcv, what))
                    taken = pc + 1 + ins["off"]
                    if z3.is_true(c):
                        pc = taken
                        continue
                    if z3.is_false(c):
                        pc += 1
                        continue
                    if self._feasible(conds + [c]):
                        work.append((taken, regs[:], dict(mem), conds + [c],
                                     dict(counters)))
                    if self._feasible(conds + [z3.Not(c)]):
                        pc += 1
                        conds = conds + [z3.Not(c)]
                        continue
                    break  # fallthrough infeasible; taken side queued (or dead)

                raise Bail(f"opcode {op:#04x} in {what}")
        if not self.paths:
            raise Bail("no feasible paths")
        return self.paths

    def _feasible(self, conds):
        self.feas.push()
        for c in conds:
            self.feas.add(c)
        r = self.feas.check()
        self.feas.pop()
        return r != z3.unsat
