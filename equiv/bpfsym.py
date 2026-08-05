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

from bpfelf import SHF_ALLOC, SHF_EXECINSTR, SHT_NOBITS, STT_SECTION

STACK_SIZE = 512
MAX_INSNS_PER_PATH = 50_000
MAX_PATHS = 4096
FEAS_TIMEOUT_MS = 200


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
            mem[region] = z3.Array(f"{region}", z3.BitVecSort(64), z3.BitVecSort(8))
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
            return Ptr(f"map:{sym.name}", bv64(addend))
        sec = self.elf.sections[sym.shndx]
        if not sec.flags & SHF_ALLOC or sec.flags & SHF_EXECINSTR:
            raise Bail(f"reloc into unsupported section {secname}")
        if secname.startswith(".rodata"):
            return Ptr(f"ro:{self.tag}:{secname}", bv64(sym.value + addend))
        return Ptr(f"g:{sym.name}", bv64(addend))

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
        if code == 13:  # END (byte swap family)
            return self._endian(a if is64 else zext64(a), is64, soff, what)
        raise Bail(f"ALU opcode {code} in {what}")

    def _endian(self, v, is64_class, _soff, what):
        raise Bail(f"endian/bswap op in {what}")

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

    # ---------- main loop ----------

    def run(self, entry_pc=0):
        regs = [None] * 11
        for i in range(10):
            regs[i] = z3.BitVec(f"uninit_{self.tag}_r{i}", 64)
        regs[1] = Ptr("ctx", bv64(0))
        regs[10] = Ptr(f"stack:{self.tag}", bv64(STACK_SIZE))
        self.init_r0 = regs[0]
        work = [(entry_pc, regs, {}, [])]
        while work:
            if len(self.paths) + len(work) > MAX_PATHS:
                raise Bail("path explosion (> MAX_PATHS)")
            pc, regs, mem, conds = work.pop()
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
                    if mode == 6:
                        raise Bail(f"atomic op in {what}")
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
                        raise Bail(f"call (helper/subprog) in {what}")
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
                        work.append((taken, regs[:], dict(mem), conds + [c]))
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
