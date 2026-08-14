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
import re
import zlib

import z3

from bpfelf import (SHF_ALLOC, SHF_EXECINSTR, SHT_NOBITS, STT_FUNC,
                    STT_SECTION, normalize_name)

STACK_SIZE = 512
MAX_INSNS_PER_PATH = 50_000
MAX_PATHS = 4096
FEAS_TIMEOUT_MS = 200
MAX_COPY = 512  # largest concrete probe_read size we'll expand byte-wise
MAX_ARG = 8192  # largest key/value/data arg we will byte-compare in an event
STR_POINTEE = -1  # see check.kernel_kfunc_sigs: a `p__str` argument
STR_CAP = 64    # symbolic-contents window captured for string kfunc args

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
    # tier 5: attachment-determined constants and frame geometry
    173: 64,  # get_func_ip
    174: 64,  # get_attach_cookie
    185: 64,  # get_func_arg_cnt
    188: 64,  # xdp_get_buff_len
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
H_SKB_STORE_BYTES = 9
H_GET_RETVAL, H_SET_RETVAL = 186, 187  # 4-byte shared "sysret" state region

# Tier 3: helpers returning a nullable pointer fork the path on a shared
# per-call-index NULL oracle; the non-null side points into a fresh
# per-call-index region with shared initial contents ("both environments
# hand back the same memory"), whose final state is observable. Each call
# also appends a trace event carrying its question (map, key/flags), which
# is what justifies the per-index sharing — see tier-2 rationale.
H_MAP_LOOKUP, H_MAP_LOOKUP_PERCPU = 1, 195
H_SK_STORAGE_GET, H_INODE_STORAGE_GET = 107, 145
H_TASK_STORAGE_GET, H_CGRP_STORAGE_GET = 156, 210
H_GET_LOCAL_STORAGE = 81                     # verifier-typed non-null
H_RINGBUF_RESERVE, H_RINGBUF_SUBMIT, H_RINGBUF_DISCARD = 131, 132, 133
H_RINGBUF_QUERY = 134
H_SPIN_LOCK, H_SPIN_UNLOCK = 93, 94
H_TAIL_CALL = 12
MAX_CALL_DEPTH = 8  # verifier limit on bpf2bpf nesting

# Tier 6: callback helpers. The callback is a function pointer (ld_imm64 of
# a .text symbol); the helper invokes it a bounded, environment-shared
# number of times with per-iteration inputs. Both objects run their own
# callback against the same shared environment, so equal observables prove
# the callbacks equivalent.
H_FOR_EACH_MAP_ELEM = 164
H_LOOP = 181
H_TIMER_SET_CALLBACK = 170
CALLBACK_HELPERS = {H_FOR_EACH_MAP_ELEM, H_LOOP}  # timers: see TIMER_CB_INLINE
MAX_CB_ITERS = 8  # unroll cap for callback loops

# Timers. init/start/cancel are ordinary side-effecting helpers (trace event
# + errno oracle); set_callback additionally EXECUTES the registered
# callback once, inline, with shared per-registration arguments. The
# callback really runs later, asynchronously — running it here is not a
# faithful schedule, but it is conservative: both objects run their own
# callback at the same point against the same environment, so equivalent
# callbacks produce equal observables and divergent ones are caught. Nested
# re-registration (a self-rearming timer) is capped.
H_TIMER_INIT, H_TIMER_START, H_TIMER_CANCEL = 169, 171, 172
MAX_TIMER_CB_DEPTH = 1

MAP_IN_MAP_TYPES = {12, 13}  # ARRAY_OF_MAPS, HASH_OF_MAPS

# Tier 5: socket-object helpers. sk_lookup_* return a nullable pointer to a
# per-call-index socket-state region (tier-3 pattern, question in the trace);
# sk_fullsock/tcp_sock derive a view from an existing socket pointer.
H_SK_LOOKUP_TCP, H_SK_LOOKUP_UDP, H_SKC_LOOKUP_TCP = 84, 85, 99
H_SK_FULLSOCK, H_TCP_SOCK = 95, 96
H_SK_RELEASE = 86

# Tier 7: socket down-cast helpers (skc_to_*): nullable views derived from
# an existing socket pointer — same shape as sk_fullsock/tcp_sock, keyed by
# the source pointer's identity so repeated casts of the same socket agree.
SKC_CAST_HELPERS = {136, 137, 138, 139, 140}
H_PER_CPU_PTR, H_THIS_CPU_PTR = 153, 154
H_KPTR_XCHG = 194
H_GET_FUNC_ARG, H_GET_FUNC_RET = 183, 184
H_GET_NETNS_COOKIE = 122
H_STRNCMP = 182
H_SKB_GET_TUNNEL_OPT, H_SKB_SET_TUNNEL_OPT = 29, 30

PTR_FORK_HELPERS = {H_MAP_LOOKUP, H_MAP_LOOKUP_PERCPU, H_SK_STORAGE_GET,
                    H_INODE_STORAGE_GET, H_TASK_STORAGE_GET,
                    H_CGRP_STORAGE_GET, H_RINGBUF_RESERVE,
                    H_SK_LOOKUP_TCP, H_SK_LOOKUP_UDP, H_SKC_LOOKUP_TCP,
                    H_SK_FULLSOCK, H_TCP_SOCK,
                    H_PER_CPU_PTR, H_KPTR_XCHG} | SKC_CAST_HELPERS
PTR_HELPERS = PTR_FORK_HELPERS | {H_GET_LOCAL_STORAGE, H_THIS_CPU_PTR}

# Tier 5: generically-captured side-effecting helpers — trace event + shared
# errno oracle, per the tier-2 rationale. Event arg specs:
#   ("val", i)     register i as an 8-byte value
#   ("mem", i, j)  bytes pointed to by register i, concrete length in reg j
#   ("map", i)     map name from register i
#   ("arg", i)     pointer-or-scalar identity (region tag + offset)
SIDE_EFFECT_HELPERS = {
    23:  [("val", 1), ("val", 2)],                 # redirect
    39:  [("val", 2)],                             # skb_pull_data
    43:  [("val", 2), ("val", 3)],                 # skb_change_head
    49:  [("val", 2), ("val", 3), ("mem", 4, 5)],  # setsockopt
    50:  [("val", 2), ("val", 3), ("val", 4)],     # skb_adjust_room
    21:  [("mem", 2, 3), ("val", 4)],              # skb_set_tunnel_key
    51:  [("map", 1), ("val", 2), ("val", 3)],     # redirect_map
    52:  [("map", 2), ("val", 3), ("val", 4)],     # sk_redirect_map
    64:  [("mem", 2, 3)],                          # bind
    73:  [("val", 2), ("mem", 3, 4)],              # lwt_push_encap
    86:  [("arg", 1)],                             # sk_release
    124: [("arg", 2), ("val", 3)],                 # sk_assign
    108: [("map", 1), ("arg", 2)],                 # sk_storage_delete
    146: [("map", 1), ("arg", 2)],                 # inode_storage_delete
    157: [("map", 1), ("arg", 2)],                 # task_storage_delete
    211: [("map", 1), ("arg", 2)],                 # cgrp_storage_delete
    13:  [("val", 2), ("val", 3)],                 # clone_redirect
    31:  [("val", 2), ("val", 3)],                 # skb_change_proto
    32:  [("val", 2)],                             # skb_change_type
    38:  [("val", 2), ("val", 3)],                 # skb_change_tail
    155: [("val", 1), ("val", 2)],                 # redirect_peer(ifindex, flags)
    # the key is compared by its CONTENTS (size from the map's BTF def),
    # never by pointer identity — the two compilers place the key at
    # different stack offsets
    82:  [("map", 2), ("mapkey", 3, 2), ("val", 4)],  # sk_select_reuseport
    30:  [("mem", 2, 3)],                          # skb_set_tunnel_opt
    170: [("arg", 1), ("func", 2)],                # timer_set_callback
    171: [("arg", 1), ("val", 2), ("val", 3)],     # timer_start
    172: [("arg", 1)],                             # timer_cancel
}
H_GET_STACK = 67
H_SKB_GET_TUNNEL_KEY = 20
H_GETSOCKOPT = 57
H_CHECK_MTU = 163
H_COPY_FROM_USER = 148
H_GET_SOCKET_COOKIE = 46
H_SEQ_PRINTF, H_SEQ_WRITE = 126, 127

# Tier 5: kfunc calls (call insns whose relocation names an undefined
# symbol — a kernel function in both objects). Dispatch is by name; each
# class reuses a tier-2/3 pattern. Unknown kfuncs still bail.
KFUNC_EVENT_ID = 255  # single trace id; the kfunc name is in the payload
KFUNC_NOOP = {"bpf_rcu_read_lock", "bpf_rcu_read_unlock",
              "bpf_preempt_disable", "bpf_preempt_enable"}
KFUNC_RELEASE = {"bpf_task_release", "bpf_cgroup_release",
                 "bpf_cpumask_release", "bpf_kfunc_call_test_release",
                 "bpf_key_put"}
KFUNC_IDENTITY = {"bpf_cast_to_kern_ctx"}
# acquire-style: nullable pointer to a kernel object; the returned address
# is a shared per-index oracle scalar, so derefs read the shared kmem and
# the program's own NULL check is the fork
KFUNC_ACQUIRE = {"bpf_task_from_pid", "bpf_cgroup_from_id",
                 "bpf_task_get_cgroup1", "bpf_kfunc_call_test_acquire",
                 "bpf_cpumask_create", "bpf_cpumask_acquire",
                 "bpf_task_acquire", "bpf_cgroup_acquire",
                 "bpf_cgroup_ancestor", "bpf_lookup_user_key",
                 "bpf_lookup_system_key"}
# pure functions of their (string) arguments: the trace pins the actual
# contents, the result is a shared per-index errno-width oracle
KFUNC_STR = {"bpf_strcmp", "bpf_strcasecmp", "bpf_strncmp",
             "bpf_strncasecmp", "bpf_strchr", "bpf_strchrnul",
             "bpf_strnchr", "bpf_strrchr", "bpf_strlen", "bpf_strnlen",
             "bpf_strspn", "bpf_strcspn", "bpf_strstr", "bpf_strcasestr",
             "bpf_strnstr", "bpf_strncasestr"}

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
    def __init__(self, elf, sec, shared, tag, kfunc_sigs=None,
                 helper_sigs=None):
        """shared: dict of region name -> z3 array, common to both programs.
        kfunc_sigs: optional {name: (params, void_ret)} that OVERRIDES this
        object's own BTF — check.py passes the signatures both objects
        agree on, so a declaration difference (one side declaring a kernel
        struct opaque) can never manufacture a divergence.
        helper_sigs: {hid: (name, [(is_ptr, pointee size, scalar width)],
        return width)} for helpers with no bespoke model; check.py builds it
        from the UAPI header and the target kernel's BTF, so it is identical
        for both objects by construction."""
        self.kfunc_sig_override = kfunc_sigs or {}
        self.helper_sigs = helper_sigs or {}
        self.elf = elf
        self.sec = sec
        self.shared = shared
        self.tag = tag  # 'A' / 'B', namespaces per-run regions
        # CO-RE state set by check.py after bpfcore.Applier.apply():
        # poisoned (secname, pc) -> reason; reaching one bails the program
        self.core_applied = getattr(elf, "core_applied", False)
        self.core_poison = getattr(elf, "core_poison", {})
        self.code = {sec.name: self._decode(sec)}  # secname -> insns
        self.dynamic_maps = {}  # inner-map handles from map-in-map lookups
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
        elif region.startswith(("mapval:", "rbuf:")):
            # per-call-index memory handed back by the environment: shared
            # initial contents, per-run writes (observable for mapval)
            mem[region] = self.shared.setdefault(
                region, z3.Array("init_" + region.replace(":", "_"),
                                 BV64S, BV8S))
        elif region.startswith("arenapg:"):
            # freshly allocated arena pages are zeroed by the kernel; the
            # zero init is identical for both runs and writes are arena
            # state, visible to userspace (observable)
            mem[region] = self.shared.setdefault(
                region, z3.K(BV64S, z3.BitVecVal(0, 8)))
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

    def _concrete_addr(self, addr, what):
        a = z3.simplify(addr)
        if not z3.is_bv_value(a):
            raise Bail(f"symbolic address over pointer-spill shadow in {what}")
        return a.as_long()

    def _load(self, mem, ptr, size):
        if is_ptr(ptr):
            region, addr = ptr.region, ptr.off
            if region.startswith("map:"):
                raise Bail(f"deref of map pointer {region}")
        else:
            region, addr = "kmem", ptr  # probe-read of kernel memory
        sh = mem.get(("shadow", region))
        if sh:
            a = self._concrete_addr(addr, region)
            if size == 8 and a in sh:
                return sh[a]  # reload of a spilled pointer
            if any(o < a + size and a < o + 8 for o in sh):
                raise Bail(f"partial read of spilled pointer in {region}")
        arr = self._region_array(mem, region)
        byts = [z3.Select(arr, addr + bv64(k)) for k in range(size)]
        val = z3.Concat(*reversed(byts)) if size > 1 else byts[0]
        return z3.ZeroExt(64 - size * 8, val) if size < 8 else val

    def _store(self, mem, ptr, size, val):
        if not is_ptr(ptr):
            # Tier 7: a store through a data-valued pointer writes kernel
            # memory — the same shared `kmem` array probe-reads and
            # data-pointer loads read. kmem is an observable, so a
            # divergent address or value surfaces as INEQUIV; both objects
            # start from the same symbolic snapshot, so agreeing writes
            # cancel. (Conservative: never fakes EQUIV.)
            region, addr = "kmem", ptr
        else:
            region, addr = ptr.region, ptr.off
        if region.startswith(("ro:", "map:")):
            raise Bail(f"store into read-only region {region}")
        if is_ptr(val):
            # pointer spill: kept in a per-region shadow keyed by concrete
            # offset. On the (non-observable) stack the byte array is left
            # alone, so any byte-wise read of the slot bails instead of
            # seeing garbage. In observable regions (globals, map values,
            # arena pages — where arena data structures keep their link
            # pointers) a canonical identity encoding is also written into
            # the byte array, so storing different abstract pointers stays
            # distinguishable to the observable comparison.
            if size != 8 or not (region == "kmem" or region.startswith(
                    ("stack:", "g:", "mapval:", "arenapg:"))):
                raise Bail(f"spilled pointer store into {region}")
            a = self._concrete_addr(addr, region)
            sh = dict(mem.get(("shadow", region), {}))
            for o in [o for o in sh if o < a + 8 and a < o + 8]:
                del sh[o]
            sh[a] = val
            mem[("shadow", region)] = sh
            self._note_write(mem, region, addr, 8)
            if not region.startswith("stack:"):
                import zlib
                cname = self._canon_region(val.region)
                canon = bv64(zlib.crc32(cname.encode()) << 32) + val.off
                arr = self._region_array(mem, region)
                for k in range(8):
                    arr = z3.Store(arr, addr + bv64(k),
                                   z3.Extract(8 * k + 7, 8 * k, canon))
                mem[region] = arr
            return
        sh = mem.get(("shadow", region))
        if sh:
            a = self._concrete_addr(addr, region)
            hit = [o for o in sh if o < a + size and a < o + 8]
            if hit:  # data overwrite invalidates the spilled pointer
                sh = dict(sh)
                for o in hit:
                    del sh[o]
                mem[("shadow", region)] = sh
        arr = self._region_array(mem, region)
        for k in range(size):
            arr = z3.Store(arr, addr + bv64(k), z3.Extract(8 * k + 7, 8 * k, val))
        mem[region] = arr
        self._note_write(mem, region, addr, size)

    def _note_write(self, mem, region, addr, size):
        """Record which bytes of a private region the program has stored to.

        Only _written_bytes uses this, to tell a byte the program supplied
        from untouched residue. Copy-on-write, like the spill shadow, so a
        path fork's `dict(mem)` stays independent."""
        if not region.startswith("stack:"):
            return
        a = z3.simplify(addr)
        key = ("wrote", region)
        if not z3.is_bv_value(a):
            mem[key] = None  # symbolic store: extent unknown from here on
            return
        prev = mem.get(key, frozenset())
        if prev is None:
            return
        a = a.as_long()
        mem[key] = prev | frozenset(range(a, a + size))

    # ---------- relocation resolution ----------

    def _resolve_ld64(self, ins):
        rel = ins["reloc"]
        addend = ins["imm64"]
        if rel is None:
            return bv64(addend)
        sym = rel.sym
        if sym.shndx == 0:
            # __kconfig externs (LINUX_HAS_SYSCALL_WRAPPER, LINUX_KERNEL_-
            # VERSION, ...) are build constants libbpf resolves at load;
            # rustc can't emit them, so translations hardcode the target
            # value. A free oracle would let the C side explore config
            # branches the target kernel never takes (spurious INEQUIV vs a
            # correctly-hardcoded translation) — bail, as this is a known
            # translation divergence the prover can't adjudicate.
            if sym.name in self.elf.kconfig_externs():
                raise Bail(f"__kconfig extern {sym.name} in ld_imm64")
            # otherwise it's a ksym address (a kernel function/variable, e.g.
            # get_func_ip comparisons `ip == &bpf_fentry_test1`). Assign each
            # (symbol, addend) a DISTINCT fixed constant rather than a free
            # oracle: these values are only ever compared for equality, both
            # objects resolve a given symbol to the same constant, and —
            # crucially — distinct kernel symbols get distinct addresses.
            # A free oracle would let two symbols alias, breaking clang's
            # switch-lowering (which assumes distinct function addresses)
            # against an unoptimized translation's independent compares.
            key = f"{sym.name}\x00{addend}"
            return bv64(0x1000_0000_0000 + (zlib.crc32(key.encode()) << 8))
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
        if sec.flags & SHF_EXECINSTR:
            # function pointer (callback for bpf_loop / for_each_map_elem /
            # timers): the region carries its (section, insn index) so a
            # callback helper can execute it inline
            if sym.type in (STT_FUNC, STT_SECTION):
                idx = (sym.value + addend) // 8
                return Ptr(f"func:{secname}:{idx}", bv64(0))
            raise Bail(f"reloc into unsupported section {secname}")
        if not sec.flags & SHF_ALLOC:
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
            if is64 and soff == 1:
                # addr_space_cast (arena <-> kernel view of the same
                # address): provenance-preserving identity in this model —
                # both programs cast the same abstract arena addresses
                return src_val
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
        old = need_data(self._load(mem, p, size), what)  # zero-extended to 64
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

    def _map_def(self, mname, what):
        d = self.dynamic_maps.get(mname) or self.elf.map_defs().get(mname)
        if d is None:
            raise Bail(f"no BTF def for map {mname} in {what}")
        return d

    def _map_kv(self, mname, what):
        d = self._map_def(mname, what)
        return d["key_size"], d["value_size"]

    def _name_bytes(self, name):
        enc = name.encode()
        return [len(enc) & 0xFF] + list(enc)

    def _mem_bytes(self, mem, ptr, n, what):
        if n > MAX_ARG:
            raise Bail(f"arg byte compare of {n} > {MAX_ARG} in {what}")
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

    def _canon_region(self, region):
        """Region name with the per-run tag neutralized, so the same logical
        pointer (own stack, own rodata) encodes identically in both runs."""
        parts = region.split(":")
        if len(parts) > 1 and parts[1] == self.tag:
            parts[1] = "T"
        return ":".join(parts)

    def _arg_id_bytes(self, v, what):
        """Identity of a pointer-or-scalar argument for event payloads.
        Pointers encode as (canonical region name, offset) — shared regions
        keep their names and per-run regions have the tag neutralized, so
        identity compares across the two objects; scalars encode as their
        value."""
        if is_ptr(v):
            return ([1] + self._name_bytes(self._canon_region(v.region))
                    + self._val_bytes(v.off, 8, what))
        return [0] + self._val_bytes(v, 8, what)

    def _cstr_bytes(self, mem, ptr, what):
        """String-argument contents for pure string kfuncs: the trace must
        carry the bytes, not the pointer identity (the same literal usually
        lives at different rodata offsets in the two objects).

        Concrete contents (rodata, concretely-built stack buffers) are
        captured exactly up to the NUL. Symbolic contents (globals, map
        values — regions that are SHARED between the two runs) are captured
        as a fixed window of symbolic bytes: identical args produce
        identical terms, different args leave the solver free to
        distinguish, so the capture stays honest either way."""
        out = [1]  # mode byte: concrete
        for k in range(MAX_COPY):
            b = z3.simplify(z3.Extract(7, 0,
                                       self._load(mem, self._addr_add(ptr, k), 1)))
            if not z3.is_bv_value(b):
                return [2] + self._mem_bytes(mem, ptr, STR_CAP, what)
            out.append(b.as_long())
            if out[-1] == 0:
                return out
        raise Bail(f"unterminated string arg in {what}")

    def _exception_cb(self, what):
        """(section name, insn idx) of the entry program's exception
        callback, from its BTF decl tag 'exception_callback:<fn>'; None if
        the program is untagged (bpf_throw then returns the cookie)."""
        self._kfunc_proto("")  # ensure self._btf_full
        b = self._btf_full
        if b is None or not getattr(self, "entry_func", None):
            return None
        cb_name = None
        for t in b.types.values():
            if t.kind == 17 and t.name.startswith("exception_callback:"):
                tagged = b.types.get(t.type)
                if tagged is not None and tagged.name == self.entry_func:
                    cb_name = t.name.split(":", 1)[1]
                    break
        if cb_name is None:
            return None
        for sym in self.elf.symbols:
            if sym.name == cb_name and sym.type == STT_FUNC:
                return self.elf.sections[sym.shndx].name, sym.value // 8
        raise Bail(f"exception callback {cb_name} not found in {what}")

    def _kfunc_proto(self, name):
        """Per-parameter is-pointer flags from the object's own BTF FUNC
        declaration of the kfunc, or None if undeclared."""
        sig = self._kfunc_sig(name)
        return None if sig is None else [p[0] for p in sig[0]]

    @staticmethod
    def kfunc_sigs_of(elf):
        """{kfunc name: (params, void_ret)} for every FUNC in an object's
        BTF that is only declared (a kfunc), in the same shape as
        _kfunc_sig. Used by check.py to intersect the two objects."""
        import bpfcore
        sec = elf.section_by_name(".BTF")
        if sec is None:
            return {}
        b = bpfcore.Btf(sec.data)
        out = {}
        for t in b.types.values():
            if t.kind != 12 or not t.name:      # FUNC
                continue
            proto = b.resolve(t.type)
            if proto.kind != 13:                # FUNC_PROTO
                continue
            rett, params = proto.proto
            ps = []
            for p in params:
                pt = b.resolve(p)
                ps.append((True, b.type_size(pt.type)) if pt.kind == 2
                          else (False, b.type_size(p)))
            out[t.name] = (ps, b.resolve(rett).kind == 0)
        return out

    def _kfunc_sig(self, name):
        """(params, returns_void) for a kfunc, from the object's own BTF.

        params is a list of (is_pointer, pointee_size) — pointee_size is
        None when the pointee has no size (void*, a forward declaration, a
        function pointer), which is what forces a bail in the generic
        model: we cannot capture the argument's contents."""
        if not hasattr(self, "_kf_protos"):
            self._kf_protos = {}
            sec = self.elf.section_by_name(".BTF")
            self._btf_full = None
            if sec is not None:
                import bpfcore
                self._btf_full = bpfcore.Btf(sec.data)
        if name in self.kfunc_sig_override:
            return self.kfunc_sig_override[name]
        if name in self._kf_protos:
            return self._kf_protos[name]
        sig = None
        b = self._btf_full
        if b is not None:
            for t in b.types.values():
                if t.kind == 12 and t.name == name:  # FUNC
                    proto = b.resolve(t.type)
                    if proto.kind == 13:  # FUNC_PROTO
                        rett, params = proto.proto
                        out = []
                        for p in params:
                            pt = b.resolve(p)
                            if pt.kind == 2:  # PTR
                                out.append((True, b.type_size(pt.type), None))
                            else:
                                out.append((False, b.type_size(p), None))
                        rt = b.resolve(rett)
                        sig = (out, rt.kind == 0, rt.kind == 2)
                    break
        self._kf_protos[name] = sig
        return sig

    def _kfunc_generic(self, name, regs, mem, counters, what, event, err):
        """Fallback for kfuncs with no bespoke model.

        Sound on the same footing as the tier-2 helper events: the call is
        pinned in the observable trace with EVERY argument — scalars by
        value, pointers by canonical identity AND pointed-to contents (so
        two calls that look alike but read different memory are still
        distinguished) — and the return is a shared per-(name, index)
        oracle. Both objects therefore ask the kernel the same question at
        the same point and get the same answer; any difference in what
        they ask shows up in the trace.

        Bails rather than guessing when an argument's contents cannot be
        captured (an unsized pointee), when the kfunc returns a pointer
        (its provenance would be unmodeled), or when the object carries no
        BTF prototype for it."""
        sig = self._kfunc_sig(name)
        if sig is None:
            raise Bail(f"kfunc {name} has no BTF proto in {what}")
        params, void_ret = sig[0], sig[1]
        if len(params) > 5:
            raise Bail(f"kfunc {name} takes {len(params)} args in {what}")
        payload, priv = [], []
        for i, (ptr_param, size, lenarg) in enumerate(params):
            a = regs[1 + i]
            if not ptr_param:
                # compare a scalar argument at the width the KERNEL reads
                # (its declared type), not the full register: a u8 param
                # ignores the upper 56 bits, so a caller that leaves an
                # un-truncated product there is not making a different call
                w = size if size in (1, 2, 4, 8) else 8
                payload += self._val_bytes(a, w, what)
                continue
            # Identity pins WHICH object is passed; contents pin what the
            # kfunc would read out of it. For a pointer into PRIVATE memory
            # the address itself is not an observable — the two objects put
            # the same local at different frame offsets (C's `p1` at
            # stack:T+496 where the translation has it at +376) — so
            # identity there is the aliasing structure only, exactly as in
            # the generic helper model.
            if is_ptr(a) and not self._is_observable(a.region):
                payload += self._name_bytes(self._private_kind(a.region))
                payload += [z3.If(a.off == p.off, z3.BitVecVal(1, 8),
                                  z3.BitVecVal(0, 8))
                            if a.region == p.region else z3.BitVecVal(0, 8)
                            for p in priv]
                priv.append(a)
            else:
                payload += self._arg_id_bytes(a, what)
            if not is_ptr(a):
                continue          # a scalar in a pointer slot (NULL, ksym)
            if size == STR_POINTEE:
                # `p__str` in the kernel's prototype: a NUL-terminated
                # string, compared by contents rather than by length
                payload += self._cstr_bytes(mem, a, what)
                continue
            if size is None and lenarg is not None:
                # the kernel's kfunc ABI spells the extent in the next
                # argument's NAME (`p__sz`), so that argument says how much
                # of the buffer is read; a symbolic one leaves no extent
                size = self._concrete_u64(
                    need_data(regs[1 + lenarg], what), what)
            if size is None:
                raise Bail(f"kfunc {name} arg{i} points to an unsized type "
                           f"in {what}")
            if size > MAX_ARG:
                raise Bail(f"kfunc {name} arg{i} pointee {size}B too large "
                           f"in {what}")
            payload += self._mem_bytes(mem, a, size, what)
        event(payload)
        return err()

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
        elif hid == H_SKB_STORE_BYTES:
            # writes `from` bytes into the packet at `offset`. The packet
            # (skbdata) is an observable region, so a divergent write shows
            # up; on error (shared oracle keyed by offset+len) it's unchanged.
            if not is_ptr(regs[1]) or regs[1].region != "ctx":
                raise Bail(f"skb_store_bytes on non-ctx skb in {what}")
            if "skbdata" not in self.shared:
                raise Bail(f"no skbdata region provided in {what}")
            off = zext64(lo32(need_data(regs[2], what)))
            n = self._concrete_u64(regs[4], what) & 0xFFFFFFFF
            if n > MAX_COPY:
                raise Bail(f"skb_store_bytes len {n} > {MAX_COPY} in {what}")
            skb = self._region_array(mem, "skbdata")
            err = z3.SignExt(32, z3.Function("oracle_skbstore_err", BV64S,
                                             BV64S, BV32S)(off, bv64(n)))
            for k in range(n):
                src = z3.Extract(7, 0,
                                 self._load(mem, self._addr_add(regs[3], k), 1))
                old = z3.Select(skb, off + bv64(k))
                skb = z3.Store(skb, off + bv64(k),
                               z3.If(err == bv64(0), src, old))
            mem["skbdata"] = skb
            ret = err
        elif hid in (H_SPIN_LOCK, H_SPIN_UNLOCK):
            # no-ops under sequential semantics, but lock identity stays
            # observable so lock placement must match across programs
            p = regs[1]
            if not is_ptr(p) or p.region.startswith("stack:"):
                raise Bail(f"spin_lock on non-region pointer in {what}")
            payload = self._name_bytes(p.region) + self._val_bytes(p.off, 8, what)
            self._emit_event(mem, counters, hid, payload)
            ret = bv64(0)
        elif hid in (H_RINGBUF_SUBMIT, H_RINGBUF_DISCARD):
            p = regs[1]
            if not is_ptr(p) or not p.region.startswith("rbuf:"):
                raise Bail(f"ringbuf submit/discard of non-reserve ptr in {what}")
            off = z3.simplify(p.off)
            if not z3.is_bv_value(off) or off.as_long() != 0:
                raise Bail(f"ringbuf submit at nonzero offset in {what}")
            payload = self._val_bytes(regs[2], 8, what)
            if hid == H_RINGBUF_SUBMIT:  # publication is the observable moment
                n = counters.get(("rbufsz", p.region))
                if n is None:
                    raise Bail(f"submit of unknown reservation in {what}")
                payload += self._mem_bytes(mem, Ptr(p.region, bv64(0)), n, what)
            self._emit_event(mem, counters, hid, payload)
            ret = bv64(0)
        elif hid == H_RINGBUF_QUERY:
            # state read whose answer evolves with submits: per-index shared
            # oracle, order kept observable by the trace event
            mname = self._map_name(regs[1], what)
            self._emit_event(mem, counters, hid,
                             self._name_bytes(mname) + self._val_bytes(regs[2], 8, what))
            ret = z3.Function(f"oracle_h{hid}", BV64S, BV64S)(bv64(idx))
        elif hid == H_GET_RETVAL:
            # reads the syscall-retval cell; helper returns int, and the
            # BPF_CALL wrapper's int->u64 conversion sign-extends
            ret = z3.SignExt(32, z3.Extract(31, 0,
                                            self._load(mem, Ptr("sysret", bv64(0)), 4)))
        elif hid == H_SET_RETVAL:
            self._store(mem, Ptr("sysret", bv64(0)), 4, need_data(regs[1], what))
            err = z3.Function("oracle_setretval_err", BV32S, BV32S)
            ret = z3.SignExt(32, err(lo32(need_data(regs[1], what))))
        elif hid in SIDE_EFFECT_HELPERS:
            payload = []
            for spec in SIDE_EFFECT_HELPERS[hid]:
                if spec[0] == "val":
                    payload += self._val_bytes(regs[spec[1]], 8, what)
                elif spec[0] == "map":
                    payload += self._name_bytes(self._map_name(regs[spec[1]], what))
                elif spec[0] == "mapkey":
                    # ("mapkey", key ptr reg, map reg): bytes pointed to,
                    # sized by the map's own BTF key_size
                    ks, _vs = self._map_kv(
                        self._map_name(regs[spec[2]], what), what)
                    if ks is None:
                        raise Bail(f"map for helper {hid} lacks key size "
                                   f"in {what}")
                    payload += self._mem_bytes(mem, regs[spec[1]], ks, what)
                elif spec[0] == "func":
                    # identity of a registered callback: its SOURCE symbol
                    # name, which both objects share (the build's keep-list
                    # forces matching symbol names). Registering a different
                    # callback is therefore detected; the callback's BODY is
                    # not proved here — see the README's assumptions.
                    payload += self._name_bytes(self._func_name(regs[spec[1]],
                                                                what))
                elif spec[0] == "arg":
                    payload += self._arg_id_bytes(regs[spec[1]], what)
                else:  # ("mem", ptr reg, len reg)
                    n = self._concrete_u64(regs[spec[2]], what) & 0xFFFFFFFF
                    payload += list(n.to_bytes(4, "little"))
                    payload += self._mem_bytes(mem, regs[spec[1]], n, what)
            self._emit_event(mem, counters, hid, payload)
            ret = self._errno_oracle(hid, idx)
        elif hid == H_GET_SOCKET_COOKIE:
            # pure function of the socket identity: oracle keyed by the arg
            a = regs[1]
            if is_ptr(a):
                f = z3.Function(f"oracle_sock_cookie_{a.region}".replace(":", "_"),
                                BV64S, BV64S)
                ret = f(a.off)
            else:
                f = z3.Function("oracle_sock_cookie", BV64S, BV64S)
                ret = f(need_data(a, what))
        elif hid == H_GET_STACK:
            # env-determined stack dump: event pins (size, flags); return is
            # a shared per-index length clamped into [-err, n]; buffer bytes
            # are a shared oracle written only on success
            n = self._concrete_u64(regs[3], what) & 0xFFFFFFFF
            if n > MAX_COPY:
                raise Bail(f"get_stack size {n} > {MAX_COPY} in {what}")
            self._emit_event(mem, counters, hid,
                             self._val_bytes(regs[3], 8, what)
                             + self._val_bytes(regs[4], 8, what))
            raw = self._errno_oracle(hid, idx)
            ret = z3.If(z3.And(raw >= bv64(0), z3.UGT(raw, bv64(n))),
                        bv64(n), raw)
            f = z3.Function("oracle_stackbuf", BV64S, BV64S, BV8S)
            for k in range(n):
                old = z3.Extract(7, 0, self._load(mem, self._addr_add(regs[2], k), 1))
                self._store(mem, self._addr_add(regs[2], k), 1,
                            z3.If(ret >= bv64(0), f(bv64(idx), bv64(k)), old))
        elif hid in (H_SKB_GET_TUNNEL_KEY, H_GETSOCKOPT):
            # env reads into a caller buffer: event pins the question, bytes
            # are a shared per-index oracle written on success (on error the
            # buffer keeps its prior — shared-residue — contents)
            if hid == H_SKB_GET_TUNNEL_KEY:
                bufp, n = regs[2], self._concrete_u64(regs[3], what) & 0xFFFFFFFF
                payload = (self._val_bytes(regs[3], 8, what)
                           + self._val_bytes(regs[4], 8, what))
            else:
                bufp, n = regs[4], self._concrete_u64(regs[5], what) & 0xFFFFFFFF
                payload = (self._val_bytes(regs[2], 8, what)
                           + self._val_bytes(regs[3], 8, what)
                           + self._val_bytes(regs[5], 8, what))
            if n > MAX_COPY:
                raise Bail(f"helper {hid} buf size {n} > {MAX_COPY} in {what}")
            self._emit_event(mem, counters, hid, payload)
            # Both helpers contractually return 0 or -errno, never positive;
            # fold the oracle's positive range away so "ret >= 0" (the branch
            # programs take) coincides with "buffer was written". Without
            # this, an impossible ret > 0 execution leaves the buffer holding
            # its prior residue — uninit C stack vs a zero-initialized Rust
            # local at different frame offsets — a spurious INEQUIV for
            # programs that print the buffer afterwards (test_tunnel_kern
            # *_get_tunnel).
            err = self._errno_oracle(hid, idx)
            err = z3.If(err > bv64(0), -err, err)
            f = z3.Function(f"oracle_buf_h{hid}", BV64S, BV64S, BV8S)
            for k in range(n):
                old = z3.Extract(7, 0, self._load(mem, self._addr_add(bufp, k), 1))
                self._store(mem, self._addr_add(bufp, k), 1,
                            z3.If(err == bv64(0), f(bv64(idx), bv64(k)), old))
            ret = err
        elif hid in (H_GET_FUNC_ARG, H_GET_FUNC_RET):
            # reads the traced function's nth argument / return value into
            # *value: a pure environment read keyed by the question (which
            # arg), so both objects asking the same question get the same
            # answer. Errors leave the buffer untouched, as the kernel does.
            if hid == H_GET_FUNC_ARG:
                nth = zext64(lo32(need_data(regs[2], what)))
                dstp = regs[3]
            else:
                nth = bv64(0)
                dstp = regs[2]
            err = z3.SignExt(32, z3.Function(f"oracle_funcarg_err_h{hid}",
                                             BV64S, BV32S)(nth))
            f = z3.Function(f"oracle_funcarg_h{hid}", BV64S, BV64S)
            self._store(mem, dstp, 8,
                        z3.If(err == bv64(0), f(nth),
                              self._load(mem, dstp, 8)))
            ret = err
        elif hid == H_GET_NETNS_COOKIE:
            # pure environment value keyed by the ctx identity (NULL ctx =
            # the initial netns, a distinct question)
            a = regs[1]
            key = (self._canon_region(a.region) if is_ptr(a) else "null")
            ret = z3.Function("oracle_netns_cookie_"
                              + re.sub(r"\W", "_", key), BV64S, BV64S)(bv64(0))
        elif hid == H_STRNCMP:
            # pure function of the two strings' contents: the event pins the
            # actual bytes, the result is a shared per-index oracle (same
            # rationale as the string kfuncs)
            n = self._concrete_u64(regs[2], what) & 0xFFFFFFFF
            if n > MAX_COPY:
                raise Bail(f"strncmp size {n} > {MAX_COPY} in {what}")
            payload = (list(n.to_bytes(4, "little"))
                       + self._mem_bytes(mem, regs[1], n, what)
                       + self._cstr_bytes(mem, regs[3], what))
            self._emit_event(mem, counters, hid, payload)
            ret = self._errno_oracle(hid, idx)
        elif hid == H_TIMER_INIT:
            # bind the timer slot to its map: set_callback needs the map to
            # build the callback's arguments
            mname = self._map_name(regs[2], what)
            counters[("timer_map", self._slot_key(regs[1], what))] = mname
            self._emit_event(mem, counters, hid,
                             self._arg_id_bytes(regs[1], what)
                             + self._name_bytes(mname)
                             + self._val_bytes(regs[3], 8, what))
            ret = self._errno_oracle(hid, idx)
        elif hid == H_SKB_GET_TUNNEL_OPT:
            # env read into a caller buffer (like skb_get_tunnel_key): the
            # size is the question, bytes are a shared per-index oracle
            n = self._concrete_u64(regs[3], what) & 0xFFFFFFFF
            if n > MAX_COPY:
                raise Bail(f"tunnel_opt size {n} > {MAX_COPY} in {what}")
            self._emit_event(mem, counters, hid,
                             self._val_bytes(regs[3], 8, what))
            err = self._errno_oracle(hid, idx)
            err = z3.If(err > bv64(0), -err, err)
            f = z3.Function("oracle_tunnelopt", BV64S, BV64S, BV8S)
            for k in range(n):
                old = z3.Extract(7, 0, self._load(mem, self._addr_add(regs[2], k), 1))
                self._store(mem, self._addr_add(regs[2], k), 1,
                            z3.If(err == bv64(0), f(bv64(idx), bv64(k)), old))
            ret = err
        elif hid == H_CHECK_MTU:
            # mtu_len is in/out: current value pinned in the event, result is
            # a shared per-index 32-bit oracle written on success
            payload = (self._val_bytes(regs[2], 8, what)
                       + self._mem_bytes(mem, regs[3], 4, what)
                       + self._val_bytes(regs[4], 8, what)
                       + self._val_bytes(regs[5], 8, what))
            self._emit_event(mem, counters, hid, payload)
            err = self._errno_oracle(hid, idx)
            mtu = z3.Function("oracle_mtu", BV64S, BV32S)(bv64(idx))
            for k in range(4):
                old = z3.Extract(7, 0, self._load(mem, self._addr_add(regs[3], k), 1))
                self._store(mem, self._addr_add(regs[3], k), 1,
                            z3.If(err == bv64(0),
                                  z3.Extract(8 * k + 7, 8 * k, mtu), old))
            ret = err
        elif hid == H_COPY_FROM_USER:
            # like probe_read_user, but fallible: success is an oracle keyed
            # by (addr, len) — the environment answers the same question the
            # same way — and the kernel zero-fills the buffer on failure
            n = self._concrete_u64(regs[2], what) & 0xFFFFFFFF
            if n > MAX_COPY:
                raise Bail(f"copy_from_user size {n} > {MAX_COPY} in {what}")
            src = need_data(regs[3], what)
            err = z3.SignExt(32, z3.Function("oracle_cfu_err", BV64S, BV64S,
                                             BV32S)(src, bv64(n)))
            for k in range(n):
                byte = z3.Extract(7, 0, self._load(mem, src + bv64(k), 1))
                self._store(mem, self._addr_add(regs[1], k), 1,
                            z3.If(err == bv64(0), byte, z3.BitVecVal(0, 8)))
            ret = err
        elif hid == H_SEQ_WRITE:
            n = self._concrete_u64(regs[3], what) & 0xFFFFFFFF
            payload = (list(n.to_bytes(4, "little"))
                       + self._mem_bytes(mem, regs[2], n, what))
            self._emit_event(mem, counters, hid, payload)
            ret = self._errno_oracle(hid, idx)
        elif hid == H_SEQ_PRINTF:
            # seq output is the bpf_iter observable: format + raw data array
            # bytes (numeric args only — a %s pointer arg sits in the data
            # array as a spilled pointer and bails in _mem_bytes)
            fsz = self._concrete_u64(regs[3], what) & 0xFFFFFFFF
            if fsz > MAX_COPY:
                raise Bail(f"seq_printf fmt size {fsz} > {MAX_COPY} in {what}")
            fmt = self._concrete_bytes(mem, regs[2], fsz, what)
            n = self._concrete_u64(regs[5], what) & 0xFFFFFFFF
            payload = [fsz & 0xFF, (fsz >> 8) & 0xFF] + fmt \
                + list(n.to_bytes(4, "little"))
            if n:
                payload += self._mem_bytes(mem, regs[4], n, what)
            self._emit_event(mem, counters, hid, payload)
            ret = self._errno_oracle(hid, idx)
        elif hid in self.helper_sigs:
            ret = self._helper_generic(hid, regs, mem, counters, idx, what)
        else:
            raise Bail(f"helper {hid} in {what}")

        return self._ret_clobbered(regs, ret)

    def _helper_generic(self, hid, regs, mem, counters, idx, what):
        """Fallback for helpers with no bespoke model, driven by the
        prototype in the kernel's own UAPI header (see bpfhelpers.py).

        Same footing as every other trace-event helper: the call is pinned
        in the observable trace with each argument compared the way the
        KERNEL reads it — scalars at their declared width, pointers by
        canonical identity, plus pointed-to bytes when the prototype names
        a sizable pointee. The return is a shared per-(id, index) oracle at
        the declared width. Equal traces therefore mean both objects made
        the same call, so the environment answers identically.

        A pointer into an OBSERVABLE region is compared by identity alone:
        its contents are already compared globally, and the prototype's
        pointee type is often not the layout the program sees anyway (the
        context arg is declared `struct xdp_buff *` where the program holds
        an `xdp_md`). A pointer into private memory — a stack buffer — must
        have its bytes captured, so an unsizable pointee bails rather than
        being silently skipped.

        Those bytes are captured as WRITTEN-OR-NOT rather than raw: the
        prototype does not say which pointers are outputs, and an output
        buffer holds nothing but uninitialized residue at call time. Since
        the two objects put their buffers at different frame offsets, that
        residue reads as two different symbolic values and comparing it
        would manufacture a divergence over bytes the kernel never looks
        at. A byte still equal to its entry value contributes a marker
        instead; every byte the program actually stored is compared for
        real, which is what soundness needs.

        Private buffers are then HAVOCKED with a shared per-call value, so
        an output the kernel fills reads back equal on both sides instead
        of each side seeing its own residue. Havoc after capture is sound:
        a genuine difference in what was passed IN is already pinned in the
        trace event."""
        name, params, ret_kind = self.helper_sigs[hid]
        if len(params) > 5:
            raise Bail(f"helper {hid} ({name}) takes {len(params)} args "
                       f"in {what}")
        payload, buffers, priv = self._name_bytes(name), [], []
        for i, (is_pointer, size, extra) in enumerate(params):
            a = regs[1 + i]
            if not is_pointer:
                payload += self._val_bytes(a, extra or 8, what)
                continue
            if size is None and extra is not None:
                # buffer whose length is a later argument: that argument
                # says how much the kernel reads, so a symbolic one leaves
                # us with no extent to capture
                size = self._concrete_u64(need_data(regs[1 + extra], what),
                                          what)
            if not is_ptr(a) or self._is_observable(a.region):
                payload += self._arg_id_bytes(a, what)
                continue
            # A private buffer's ADDRESS is not an observable: the two
            # objects place their locals at different frame offsets, and
            # even in different FRAMES — one compiler inlines the helper
            # that owns the buffer, the other leaves it a bpf2bpf callee,
            # so the same local is `stack:T` in one and `stack:T:f1` in the
            # other. What is observable is the aliasing structure — whether
            # this argument is the same buffer as an earlier one — plus the
            # bytes below.
            payload += self._name_bytes(self._private_kind(a.region))
            payload += [z3.If(a.off == p.off, z3.BitVecVal(1, 8),
                              z3.BitVecVal(0, 8))
                        if a.region == p.region else z3.BitVecVal(0, 8)
                        for p in priv]
            priv.append(a)
            if size is None:
                raise Bail(f"helper {hid} ({name}) arg{i} points to an "
                           f"unsized type in {what}")
            if size > MAX_COPY:
                raise Bail(f"helper {hid} ({name}) arg{i} pointee {size}B "
                           f"> {MAX_COPY} in {what}")
            payload += self._written_bytes(mem, a, size, what)
            buffers.append((i, a, size))
        self._emit_event(mem, counters, hid, payload)
        f = z3.Function(f"oracle_hbuf{hid}", BV64S, BV64S, BV64S, BV8S)
        for argno, ptr, size in buffers:
            for k in range(size):
                self._store(mem, self._addr_add(ptr, k), 1,
                            f(bv64(idx), bv64(argno), bv64(k)))
        if ret_kind == 8:
            return z3.Function(f"oracle_h{hid}_ret", BV64S, BV64S)(bv64(idx))
        return self._errno_oracle(hid, idx)

    def _written_bytes(self, mem, ptr, n, what):
        """`n` bytes at `ptr`, with bytes the program never stored to
        reported as zero rather than as their residue. See _helper_generic.

        Untouched residue must not be compared: the two objects lay their
        frames out differently, so the same untouched byte reads as two
        unrelated symbolic values. Zero also makes an uninitialized C local
        agree with the `[0u8; N]` its translation declares — and for an
        OUTPUT buffer (bpf_xdp_load_bytes' `meta_have`) neither the kernel
        nor the program ever looks at those bytes.

        Writtenness comes from the recorded store set, not from comparing
        against the entry value: residue is symbolic, so `cur == init` is
        satisfiable for a byte that WAS written, and a solver picking that
        model on one side only would invent a divergence between two
        buffers holding identical data.

        The cost is that a byte stored as zero reads the same as one never
        stored, so a translation that left an INPUT byte uninitialized
        where C writes zero would slip through. That is the one imprecision
        here; every other difference in what the program hands the kernel
        is compared exactly."""
        if not ptr.region.startswith("stack:"):
            # Only the stack carries residue. Other private regions (rodata,
            # a ringbuf reservation) hold values that are equal by
            # construction across the two runs, so capture them as they are.
            return self._mem_bytes(mem, ptr, n, what)
        wrote = mem.get(("wrote", ptr.region), frozenset())
        if wrote is None:
            raise Bail(f"buffer arg after a symbolically-addressed store "
                       f"in {what}")
        base = z3.simplify(ptr.off)
        if not z3.is_bv_value(base):
            raise Bail(f"symbolic buffer address in {what}")
        base = base.as_long()
        out = []
        for k in range(n):
            if base + k not in wrote:
                out.append(z3.BitVecVal(0, 8))
                continue
            out.append(z3.Extract(
                7, 0, self._load(mem, self._addr_add(ptr, k), 1)))
        return out

    def _private_kind(self, region):
        """What KIND of private memory a pointer refers to, with the frame
        it happens to live in dropped — see _helper_generic."""
        if region.startswith("stack:"):
            return "stack"
        return self._canon_region(region)

    def _is_observable(self, region):
        """Regions compared in their own right by check.py, so a pointer
        into one needs no content capture (kept in sync with obs_regions)."""
        return (region in ("ctx", "kmem", "trace", "sysret", "skbdata")
                or region.startswith(("g:", "mapval:", "arenapg:")))

    def _ret_clobbered(self, regs, ret):
        regs = regs[:]
        regs[0] = ret
        for i in range(1, 6):  # caller-saved, unreadable after the call
            self.nclobber += 1
            regs[i] = z3.BitVec(f"clobber_{self.tag}_{self.nclobber}", 64)
        return regs

    # ---------- tier-3: nullable-pointer helpers (path fork) ----------

    def _ptr_helper(self, hid, regs, mem, counters, what):
        """Model a pointer-returning helper. Returns continuations
        [(cond, regs, mem, counters), ...]; the first is the primary path."""
        idx = counters.get(hid, 0)
        counters[hid] = idx + 1

        inner = None
        mname = None  # set only by the map-taking helpers below
        if hid in (H_MAP_LOOKUP, H_MAP_LOOKUP_PERCPU):
            mname = self._map_name(regs[1], what)
            d = self._map_def(mname, what)
            if d.get("map_type") in MAP_IN_MAP_TYPES:
                inner = d.get("inner")  # lookup returns an inner-map handle
                if inner is None:
                    raise Bail(f"map-in-map {mname} without inner def in {what}")
            ks = d["key_size"]
            if ks is None:
                raise Bail(f"map {mname} def lacks key size in {what}")
            payload = self._name_bytes(mname) + self._mem_bytes(mem, regs[2], ks, what)
            if hid == H_MAP_LOOKUP_PERCPU:
                payload += self._val_bytes(regs[3], 8, what)
        elif hid == H_GET_LOCAL_STORAGE:
            mname = self._map_name(regs[1], what)
            payload = self._name_bytes(mname) + self._val_bytes(regs[2], 8, what)
        elif hid == H_RINGBUF_RESERVE:
            mname = self._map_name(regs[1], what)
            n = self._concrete_u64(regs[2], what)
            if n > MAX_COPY:
                raise Bail(f"ringbuf_reserve size {n} > {MAX_COPY} in {what}")
            payload = (self._name_bytes(mname) + list(n.to_bytes(8, "little"))
                       + self._val_bytes(regs[3], 8, what))
        elif hid in (H_SK_LOOKUP_TCP, H_SK_LOOKUP_UDP, H_SKC_LOOKUP_TCP):
            # sk_lookup(ctx, tuple, tuple_size, netns, flags): the tuple
            # bytes are the question; the found socket's state is a fresh
            # per-index region with shared contents
            n = self._concrete_u64(regs[3], what) & 0xFFFFFFFF
            payload = (list(n.to_bytes(4, "little"))
                       + self._mem_bytes(mem, regs[2], n, what)
                       + self._val_bytes(regs[4], 8, what)
                       + self._val_bytes(regs[5], 8, what))
        elif hid in (H_SK_FULLSOCK, H_TCP_SOCK) or hid in SKC_CAST_HELPERS:
            # views/down-casts derived from an existing socket pointer; the
            # source socket's identity is the question
            payload = self._arg_id_bytes(regs[1], what)
        elif hid in (H_PER_CPU_PTR, H_THIS_CPU_PTR):
            # per-cpu view of a percpu pointer: keyed by the source pointer
            # (and cpu for per_cpu_ptr) so repeated views of the same object
            # alias consistently
            payload = self._arg_id_bytes(regs[1], what)
            if hid == H_PER_CPU_PTR:
                payload += self._val_bytes(regs[2], 8, what)
        elif hid == H_KPTR_XCHG:
            # atomically swaps a kernel pointer into a map value and returns
            # the old one: the destination slot and the incoming pointer are
            # the question, the old pointer is the (nullable) answer
            payload = (self._arg_id_bytes(regs[1], what)
                       + self._arg_id_bytes(regs[2], what))
        else:  # sk/inode/task/cgrp storage_get(map, obj, value, flags)
            mname = self._map_name(regs[1], what)
            payload = (self._name_bytes(mname) + self._val_bytes(regs[2], 8, what)
                       + self._val_bytes(regs[4], 8, what))
            if is_ptr(regs[3]):  # optional initial-value pointer (CREATE flag)
                _ks, vs = self._map_kv(mname, what)
                if vs is None:
                    raise Bail(f"map {mname} def lacks value size in {what}")
                payload += [1] + self._mem_bytes(mem, regs[3], vs, what)
            else:
                payload += [0] + self._val_bytes(regs[3], 8, what)

        self._emit_event(mem, counters, hid, payload)
        if inner is not None:  # a map handle, not value memory
            region = f"map:{mname}#in{idx}"
            self.dynamic_maps[region[4:]] = inner
        elif hid == H_RINGBUF_RESERVE:
            region = f"rbuf:{idx}"
            counters[("rbufsz", region)] = n
        elif hid in (H_SK_LOOKUP_TCP, H_SK_LOOKUP_UDP, H_SKC_LOOKUP_TCP):
            region = f"mapval:{hid}:sk:{idx}"
        elif hid in SKC_CAST_HELPERS or hid == H_TCP_SOCK:
            # RE-TYPING casts (skc_to_tcp_sock, bpf_tcp_sock, ...) hand back
            # the SAME kernel object, so they must alias their argument —
            # a fresh region would make a program that reads through the
            # cast disagree with one that reads through the original
            # (exactly the bpf_iter_setsockopt false INEQUIV).
            region = None
        elif hid in (H_PER_CPU_PTR, H_THIS_CPU_PTR):
            # a per-cpu VIEW is a different object than its percpu base;
            # key it by the source identity so repeated views alias
            src = regs[1]
            tag = (self._canon_region(src.region) if is_ptr(src)
                   else "scalar")
            region = f"mapval:{hid}:{tag}"
        elif hid == H_KPTR_XCHG:
            region = f"mapval:{hid}:old:{idx}"
        else:
            region = f"mapval:{hid}:{mname}:{idx}"
        ret_ptr = regs[1] if region is None else Ptr(region, bv64(0))
        ptr_regs = self._ret_clobbered(regs, ret_ptr)
        if hid == H_GET_LOCAL_STORAGE:  # never NULL, no fork
            return [(None, ptr_regs, mem, counters)]
        isnull = z3.Function(f"oracle_null_h{hid}", BV64S, z3.BoolSort())(bv64(idx))
        null_regs = self._ret_clobbered(regs, bv64(0))
        return [(z3.Not(isnull), ptr_regs, mem, counters),
                (isnull, null_regs, dict(mem), dict(counters))]

    # ---------- tier-5: kfunc calls ----------

    def _kfunc_name(self, ins):
        """Kernel-function name if this call insn relocates against an
        undefined symbol (how kfunc calls appear in both objects: clang
        emits src=2, rustc extern-"C" declarations emit src=1)."""
        rel = ins["reloc"]
        if rel is not None and rel.sym.shndx == 0 and rel.sym.name:
            return rel.sym.name
        return None

    def _kfunc_call(self, name, regs, mem, counters, conds, what):
        """Model one kfunc call. Returns continuations like _ptr_helper
        ([] when the path terminates, i.e. bpf_throw)."""
        key = ("kf", name)
        idx = counters.get(key, 0)
        counters[key] = idx + 1

        def event(payload):
            self._emit_event(mem, counters, KFUNC_EVENT_ID,
                             self._name_bytes(name) + payload)

        def err():
            f = z3.Function(f"oracle_kf_err_{name}", BV64S, BV32S)
            return z3.SignExt(32, f(bv64(idx)))

        def one(ret):
            return [(None, self._ret_clobbered(regs, ret), mem, counters)]

        if name in KFUNC_NOOP:
            event([])
            return one(err())
        if name in KFUNC_RELEASE:
            event(self._arg_id_bytes(regs[1], what))
            return one(err())
        if name in KFUNC_IDENTITY:
            return one(regs[1])
        if name == "bpf_local_irq_save":
            # writes the saved flags word; a shared oracle, restore reads it
            # back through the event so save/restore pairing must match
            event(self._arg_id_bytes(regs[1], what))
            self._store(mem, regs[1], 8,
                        z3.Function("oracle_kf_irqflags", BV64S, BV64S)(bv64(idx)))
            return one(err())
        if name == "bpf_local_irq_restore":
            event(self._arg_id_bytes(regs[1], what)
                  + self._mem_bytes(mem, regs[1], 8, what))
            return one(err())
        if name in KFUNC_STR:
            flags = self._kfunc_proto(name)
            if flags is None:
                raise Bail(f"kfunc {name} lacks a BTF proto in {what}")
            payload = []
            for i, isptr in enumerate(flags):
                if isptr:
                    cb = self._cstr_bytes(mem, regs[1 + i], what)
                    payload += list(len(cb).to_bytes(2, "little")) + cb
                else:
                    payload += self._val_bytes(regs[1 + i], 8, what)
            event(payload)
            return one(err())
        if name in KFUNC_ACQUIRE:
            flags = self._kfunc_proto(name)
            if flags is None:
                raise Bail(f"kfunc {name} lacks a BTF proto in {what}")
            payload = []
            for i, isptr in enumerate(flags):
                payload += (self._arg_id_bytes(regs[1 + i], what) if isptr
                            else self._val_bytes(regs[1 + i], 8, what))
            event(payload)
            # the object's address is the shared oracle; NULL-or-not is the
            # program's own check on it, so both sides fork identically
            addr = z3.Function(f"oracle_kf_obj_{name}", BV64S, BV64S)(bv64(idx))
            return [(addr != bv64(0), self._ret_clobbered(regs, addr),
                     mem, counters),
                    (addr == bv64(0), self._ret_clobbered(regs, bv64(0)),
                     dict(mem), dict(counters))]
        if name == "bpf_session_is_return":
            b = z3.Function("oracle_kf_sess_isret", BV64S,
                            z3.BitVecSort(1))(bv64(idx))
            return one(z3.ZeroExt(63, b))
        if name == "bpf_session_cookie":
            event([])
            region = f"mapval:kf:cookie:{idx}"
            isnull = z3.Function("oracle_kf_null_cookie", BV64S,
                                 z3.BoolSort())(bv64(idx))
            return [(z3.Not(isnull),
                     self._ret_clobbered(regs, Ptr(region, bv64(0))),
                     mem, counters),
                    (isnull, self._ret_clobbered(regs, bv64(0)),
                     dict(mem), dict(counters))]
        if name.startswith("bpf_cpumask_"):
            # cpumask operations on kfunc-acquired objects: every op (set,
            # clear, test, and, or, first, empty, ...) is an event pinning
            # (op, object identities, scalar args) with an oracle result —
            # equal traces imply equal object state at the nth op, so the
            # shared per-index result is justified exactly as in tier 2
            flags = self._kfunc_proto(name)
            if flags is None:
                raise Bail(f"kfunc {name} lacks a BTF proto in {what}")
            payload = []
            for i, isptr in enumerate(flags):
                payload += (self._arg_id_bytes(regs[1 + i], what) if isptr
                            else self._val_bytes(regs[1 + i], 8, what))
            event(payload)
            return one(err())

        m = re.fullmatch(r"bpf_iter_(\w+)_(new|next|destroy)", name)
        if m:
            kind, op = m.groups()
            if op == "next":
                # loop driver: shared per-index NULL oracle; the non-null
                # side points at a shared per-index element (the environment
                # hands both programs the same iteration sequence)
                event(self._arg_id_bytes(regs[1], what))
                region = f"mapval:kf:iter_{kind}:{idx}"
                isnull = z3.Function(f"oracle_kf_null_iter_{kind}", BV64S,
                                     z3.BoolSort())(bv64(idx))
                return [(z3.Not(isnull),
                         self._ret_clobbered(regs, Ptr(region, bv64(0))),
                         mem, counters),
                        (isnull, self._ret_clobbered(regs, bv64(0)),
                         dict(mem), dict(counters))]
            # new/destroy: args pinned in the trace (ptrs by identity,
            # scalars by value, per the object's own BTF proto)
            flags = self._kfunc_proto(name)
            if flags is None:
                raise Bail(f"kfunc {name} lacks a BTF proto in {what}")
            payload = []
            for i, isptr in enumerate(flags):
                payload += (self._arg_id_bytes(regs[1 + i], what) if isptr
                            else self._val_bytes(regs[1 + i], 8, what))
            event(payload)
            return one(err())
        # bpf_throw is handled in the run loop (it unwinds the call stack
        # and transfers to the program's exception callback, if tagged)
        if name == "bpf_arena_alloc_pages":
            # (map, addr_hint, page_cnt, numa, flags) -> zeroed pages or NULL
            event(self._name_bytes(self._map_name(regs[1], what))
                  + self._arg_id_bytes(regs[2], what)
                  + self._val_bytes(regs[3], 8, what)
                  + self._val_bytes(regs[4], 8, what)
                  + self._val_bytes(regs[5], 8, what))
            region = f"arenapg:{idx}"
            isnull = z3.Function("oracle_kf_null_arena", BV64S,
                                 z3.BoolSort())(bv64(idx))
            return [(z3.Not(isnull),
                     self._ret_clobbered(regs, Ptr(region, bv64(0))),
                     mem, counters),
                    (isnull, self._ret_clobbered(regs, bv64(0)),
                     dict(mem), dict(counters))]
        if name == "bpf_arena_free_pages":
            event(self._name_bytes(self._map_name(regs[1], what))
                  + self._arg_id_bytes(regs[2], what)
                  + self._val_bytes(regs[3], 8, what))
            return one(err())

        # No bespoke model: fall back to the generic one, but only when the
        # kfunc returns a scalar. A pointer return would need provenance we
        # do not have (which region does it point into? is it nullable?),
        # so those still bail rather than guess.
        sig = self._kfunc_sig(name)
        if sig is not None:
            ret_is_ptr = sig[2] if len(sig) > 2 else None
            if ret_is_ptr is None:
                # no kernel prototype for it: fall back to this object's BTF
                b, rett = self._btf_full, None
                if b is not None:
                    for t in b.types.values():
                        if t.kind == 12 and t.name == name:
                            rett = b.resolve(b.resolve(t.type).proto[0])
                            break
                ret_is_ptr = None if rett is None else rett.kind == 2
            if ret_is_ptr is False:                   # not a PTR return
                return one(self._kfunc_generic(name, regs, mem, counters,
                                               what, event, err))
        raise Bail(f"kfunc {name} in {what}")

    # ---------- tier-6: callback helpers ----------

    def _func_name(self, ptr, what):
        """Source symbol name of a function pointer (func: region)."""
        if not is_ptr(ptr) or not ptr.region.startswith("func:"):
            raise Bail(f"expected a function pointer in {what}")
        _, secname, idx = ptr.region.split(":", 2)
        sec = self.elf.section_by_name(secname)
        sym = self.elf.named_symbol_at(sec.idx, int(idx) * 8)
        if sym is None:
            raise Bail(f"unnamed callback at {secname}+{idx} in {what}")
        return normalize_name(sym.name)

    def _slot_key(self, ptr, what):
        """Stable identity of an embedded struct slot (a timer inside a map
        value), comparable across the two objects."""
        if not is_ptr(ptr):
            raise Bail(f"timer slot is not a pointer in {what}")
        off = z3.simplify(ptr.off)
        offs = off.as_long() if z3.is_bv_value(off) else "sym"
        return f"{self._canon_region(ptr.region)}+{offs}"

    def _cb_target(self, ptr, what):
        """(section, insn idx) of a callback function pointer arg."""
        if not is_ptr(ptr) or not ptr.region.startswith("func:"):
            raise Bail(f"callback arg is not a function pointer in {what}")
        _, secname, idx = ptr.region.split(":", 2)
        return secname, int(idx)

    def _cb_iter_regs(self, frame, i, mem, counters):
        """Registers r1..r5 for callback iteration i, plus a fresh callee
        frame r10. frame = the ('__cb', ...) tuple."""
        (_tag, hid, csec, cidx, _i, n, _rs, _rp, _r10c, cbfid,
         arg_ctx, arg_map, mapname) = frame
        regs = [None] * 11
        for k in range(11):
            regs[k] = z3.BitVec(f"cbclobber_{self.tag}_{cbfid}_{i}_{k}", 64)
        regs[10] = Ptr(f"stack:{self.tag}:cb{cbfid}", bv64(STACK_SIZE))
        if hid == H_LOOP:
            regs[1] = zext64(z3.BitVecVal(i, 32))  # u32 index
            regs[2] = arg_ctx
            regs[3] = bv64(0)
            regs[4] = bv64(0)
        elif hid == H_TIMER_SET_CALLBACK:
            # timer callback: (map, key, value) — shared per-registration
            # key region, observable per-registration value region
            kreg = f"cbkey:{mapname}:{cbfid}:0"
            self.shared.setdefault(
                kreg, z3.Array("init_" + kreg.replace(":", "_"), BV64S, BV8S))
            regs[1] = arg_map
            regs[2] = Ptr(kreg, bv64(0))
            regs[3] = Ptr(f"mapval:timer:{mapname}:{cbfid}", bv64(0))
            regs[4] = bv64(0)
        else:  # for_each_map_elem: (map, key, value, ctx)
            regs[1] = arg_map
            # key: shared per-(map,call,iter) region — both programs see the
            # same key sequence (same map, same environment)
            kreg = f"cbkey:{mapname}:{cbfid}:{i}"
            self._region_array(mem, kreg) if kreg in self.shared else \
                self.shared.setdefault(
                    kreg, z3.Array("init_" + kreg.replace(":", "_"),
                                   BV64S, BV8S))
            regs[2] = Ptr(kreg, bv64(0))
            # value: observable per-iteration map region, like a lookup
            regs[3] = Ptr(f"mapval:cb:{mapname}:{cbfid}:{i}", bv64(0))
            regs[4] = arg_ctx
        return regs

    def _cb_start(self, hid, regs, mem, counters, what):
        """Set up the first callback iteration. n is a symbolic upper bound
        (concrete for for_each's max_entries; possibly symbolic for
        bpf_loop's nr_loops); the run loop forks on `i < n` per iteration
        and bails past MAX_CB_ITERS. Returns (frame, new_regs, csec, cidx)
        or None when the bound is a concrete zero."""
        csec, cidx = self._cb_target(regs[2], what)
        cbfid = counters.get("cbframe", 0) + 1
        counters["cbframe"] = cbfid
        arg_ctx = regs[3]
        if hid == H_TIMER_SET_CALLBACK:
            slot = self._slot_key(regs[1], what)
            mapname = counters.get(("timer_map", slot))
            if mapname is None:
                raise Bail(f"timer callback set on uninitialized slot {slot} "
                           f"in {what}")
            depth = counters.get("timer_cb_depth", 0)
            self._emit_event(mem, counters, hid,
                             self._arg_id_bytes(regs[1], what)
                             + self._name_bytes(mapname))
            if depth >= MAX_TIMER_CB_DEPTH:
                return None  # registration recorded; don't recurse further
            counters["timer_cb_depth"] = depth + 1
            n = bv64(1)
            arg_map = Ptr(f"map:{mapname}", bv64(0))
            frame = ("__cb", hid, csec, cidx, 0, n, None, None, regs[10],
                     cbfid, arg_ctx, arg_map, mapname)
            return frame, self._cb_iter_regs(frame, 0, mem, counters), \
                csec, cidx
        if hid == H_LOOP:
            nr = regs[1]
            if is_ptr(nr):
                raise Bail(f"bpf_loop nr is a pointer in {what}")
            nr = z3.simplify(nr)
            n = z3.Extract(31, 0, nr)  # u32 nr_loops
            n = z3.ZeroExt(32, n)
            arg_map, mapname = None, None
            if z3.is_bv_value(n) and n.as_long() == 0:
                self._emit_event(mem, counters, hid, [0, 0, 0, 0, 0])
                return None
            trace_n = n.as_long() if z3.is_bv_value(n) else 0xFFFFFFFF
        else:
            mapname = self._map_name(regs[1], what)
            d = self._map_def(mapname, what)
            me = d.get("max_entries")
            if me is None:
                raise Bail(f"for_each map {mapname} has no max_entries in {what}")
            if me == 0:
                return None
            if me > MAX_CB_ITERS:
                raise Bail(f"for_each trip bound {me} > {MAX_CB_ITERS} in {what}")
            n = bv64(me)
            trace_n = me
            arg_map = regs[1]
        # a trace event records the call so the two objects must issue the
        # same callback helper against the same map with the same trip bound
        self._emit_event(mem, counters, hid,
                         (self._name_bytes(mapname) if mapname else [0])
                         + list((trace_n & 0xFFFFFFFF).to_bytes(4, "little")))
        frame = ("__cb", hid, csec, cidx, 0, n, None, None, regs[10], cbfid,
                 arg_ctx, arg_map, mapname)
        new_regs = self._cb_iter_regs(frame, 0, mem, counters)
        return frame, new_regs, csec, cidx

    # ---------- main loop ----------

    def _insns(self, secname, what):
        if secname not in self.code:
            s = self.elf.section_by_name(secname)
            if s is None or not s.flags & SHF_EXECINSTR:
                raise Bail(f"call into non-code section {secname} in {what}")
            if (not self.core_applied
                    and secname in self.elf.core_relo_sections()):
                raise Bail(f"callee section {secname} has CO-RE relocs in {what}")
            self.code[secname] = self._decode(s)
        return self.code[secname]

    def _call_target(self, ins, sec, pc, what):
        """Resolve a src=1 call: (section name, insn index) of the callee."""
        rel = ins["reloc"]
        if rel is None:
            return sec, pc + 1 + ins["imm"]
        sym = rel.sym
        if sym.shndx == 0 or sym.shndx >= len(self.elf.sections):
            raise Bail(f"call to undefined symbol {sym.name} in {what}")
        if sym.type not in (STT_FUNC, STT_SECTION):
            raise Bail(f"call reloc to symbol type {sym.type} in {what}")
        return (self.elf.sections[sym.shndx].name,
                sym.value // 8 + ins["imm"] + 1)

    def run(self, entry_pc=0, callback=False):
        entry_sym = self.elf.named_symbol_at(self.sec.idx, entry_pc * 8)
        self.entry_func = entry_sym.name if entry_sym else None
        regs = [None] * 11
        for i in range(10):
            regs[i] = z3.BitVec(f"uninit_{self.tag}_r{i}", 64)
        if callback:
            # A registered callback is entered with helper-supplied
            # arguments rather than a ctx: (map, key, value) for timers and
            # for_each, (index, ctx) for bpf_loop. Their exact roles differ
            # per helper, so give r1-r5 SHARED regions named by position —
            # both objects' callbacks then run over identical inputs and
            # their observable effects are directly comparable.
            for i in range(1, 6):
                reg = f"cbarg:{i}"
                self.shared.setdefault(
                    reg, z3.Array("init_" + reg.replace(":", "_"),
                                  BV64S, BV8S))
                regs[i] = Ptr(reg, bv64(0))
        else:
            regs[1] = Ptr("ctx", bv64(0))
        regs[10] = Ptr(f"stack:{self.tag}", bv64(STACK_SIZE))
        self.init_r0 = regs[0]
        # work item: (sec name, pc, regs, mem, conds, counters, call stack);
        # call stack = tuple of (return sec, return pc, caller r10)
        work = [(self.sec.name, entry_pc, regs, {}, [], {}, ())]
        while work:
            if len(self.paths) + len(work) > MAX_PATHS:
                raise Bail("path explosion (> MAX_PATHS)")
            cursec, pc, regs, mem, conds, counters, stack = work.pop()
            insns = self._insns(cursec, "resume")
            steps = 0
            while True:
                steps += 1
                if steps > MAX_INSNS_PER_PATH:
                    raise Bail("path too long (loop?)")
                if pc < 0 or pc >= len(insns) or insns[pc] is None:
                    raise Bail(f"jump to invalid pc {cursec}@{pc}")
                if (cursec, pc) in self.core_poison:
                    raise Bail(f"core-poison at {cursec}@{pc}: "
                               f"{self.core_poison[(cursec, pc)]}")
                ins = insns[pc]
                op, dst, src = ins["op"], ins["dst"], ins["src"]
                cls = op & 7
                what = f"{cursec}@{pc}"

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
                        val = z3.SignExt(64 - size * 8,
                                         z3.Extract(size * 8 - 1, 0,
                                                    need_data(val, what)))
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
                    mem = dict(mem)
                    self._store(mem, p, size, val)
                    pc += 1
                    continue

                if cls in (5, 6):  # JMP / JMP32
                    code = op >> 4
                    if code == 8:
                        kname = self._kfunc_name(ins) if src in (1, 2) else None
                        if kname == "bpf_throw":
                            # unwinds every frame; the exception callback's
                            # return (or the cookie itself, if untagged)
                            # becomes the program's return
                            # no trace event: the throw is modeled exactly
                            # (cookie + callback), so there is no oracle to
                            # pin — and a translation that reaches the same
                            # observable state without throwing (the decl-tag
                            # gap, see exceptions_ext.rs) is equivalent
                            mem = dict(mem)
                            counters = dict(counters)
                            cookie = need_data(regs[1], what)
                            cb = self._exception_cb(what)
                            if cb is None:
                                self.paths.append(Path(conds, cookie, mem))
                                break
                            tsec, tidx = cb
                            insns = self._insns(tsec, what)
                            stack = ()
                            fid = counters.get("frame", 0) + 1
                            counters["frame"] = fid
                            regs = self._ret_clobbered(regs, bv64(0))
                            regs[1] = cookie
                            regs[10] = Ptr(f"stack:{self.tag}:f{fid}",
                                           bv64(STACK_SIZE))
                            cursec, pc = tsec, tidx
                            continue
                        if kname is not None:
                            mem = dict(mem)
                            counters = dict(counters)
                            conts = self._kfunc_call(kname, regs, mem,
                                                     counters, conds, what)
                            if not conts:
                                break  # path terminated (bpf_throw)
                            for cond, r2, m2, k2 in conts[1:]:
                                work.append((cursec, pc + 1, r2, m2,
                                             conds + [cond], k2, stack))
                            cond, regs, mem, counters = conts[0]
                            if cond is not None:
                                conds = conds + [cond]
                            pc += 1
                            continue
                        if src == 1:  # bpf2bpf call: execute inline
                            if len(stack) >= MAX_CALL_DEPTH:
                                raise Bail(f"call depth > {MAX_CALL_DEPTH} in {what}")
                            tsec, tidx = self._call_target(ins, cursec, pc, what)
                            tinsns = self._insns(tsec, what)
                            # a subprogram gets its OWN frame: the verifier
                            # keeps the caller's whole register file and
                            # copies back only r0 (prepare_func_exit), so
                            # save the caller's registers, not just r10
                            stack = stack + ((cursec, pc + 1, regs[:]),)
                            fid = counters.get("frame", 0) + 1
                            counters = dict(counters)
                            counters["frame"] = fid
                            regs = regs[:]
                            regs[10] = Ptr(f"stack:{self.tag}:f{fid}",
                                           bv64(STACK_SIZE))
                            cursec, pc, insns = tsec, tidx, tinsns
                            continue
                        if src == 2:
                            raise Bail(f"kfunc call without symbol in {what}")
                        mem = dict(mem)
                        if ins["imm"] == H_TAIL_CALL:
                            # success consumes execution: the path ends with
                            # the target program's (shared oracle) return;
                            # failure continues with an errno oracle
                            idx = counters.get(H_TAIL_CALL, 0)
                            counters = dict(counters)
                            counters[H_TAIL_CALL] = idx + 1
                            mname = self._map_name(regs[2], what)
                            self._emit_event(
                                mem, counters, H_TAIL_CALL,
                                self._name_bytes(mname)
                                + self._val_bytes(zext64(lo32(need_data(
                                    regs[3], what))), 4, what))
                            succ = z3.Function("oracle_tailcall_succ", BV64S,
                                               z3.BoolSort())(bv64(idx))
                            tret = z3.Function("oracle_tailcall_ret", BV64S,
                                               BV64S)(bv64(idx))
                            self.paths.append(Path(conds + [succ], tret, mem))
                            conds = conds + [z3.Not(succ)]
                            regs = self._ret_clobbered(
                                regs, self._errno_oracle(H_TAIL_CALL, idx))
                        elif ins["imm"] in CALLBACK_HELPERS:
                            if len(stack) >= MAX_CALL_DEPTH:
                                raise Bail(f"callback depth > {MAX_CALL_DEPTH} "
                                           f"in {what}")
                            counters = dict(counters)
                            started = self._cb_start(ins["imm"], regs, mem,
                                                     counters, what)
                            if started is None:  # zero iterations
                                regs = self._ret_clobbered(regs, bv64(0))
                                pc += 1
                                continue
                            frame, cbregs, csec, cidx = started
                            frame = frame[:6] + (cursec, pc + 1, regs[:]) \
                                + frame[9:]
                            n = frame[5]
                            enter_c = z3.simplify(z3.UGT(n, bv64(0)))
                            skip_c = z3.simplify(n == bv64(0))
                            if not z3.is_false(skip_c) and \
                                    self._feasible(conds + [skip_c]):
                                rr = self._ret_clobbered(regs, bv64(0))
                                work.append((cursec, pc + 1, rr, dict(mem),
                                             conds + [skip_c], dict(counters),
                                             stack))
                            if not self._feasible(conds + [enter_c]):
                                break
                            if not z3.is_true(enter_c):
                                conds = conds + [enter_c]
                            stack = stack + (frame,)
                            regs = cbregs
                            cursec, pc, insns = csec, cidx, \
                                self._insns(csec, what)
                            continue
                        elif ins["imm"] in PTR_HELPERS:
                            conts = self._ptr_helper(ins["imm"], regs, mem,
                                                     counters, what)
                            for cond, r2, m2, k2 in conts[1:]:
                                work.append((cursec, pc + 1, r2, m2,
                                             conds + [cond], k2, stack))
                            cond, regs, mem, counters = conts[0]
                            if cond is not None:
                                conds = conds + [cond]
                        else:
                            regs = self._helper_call(ins["imm"], regs, mem,
                                                     counters, what)
                        pc += 1
                        continue
                    if code == 9:  # EXIT
                        if stack and stack[-1][0] == "__cb":
                            # callback iteration finished; decide continue vs
                            # stop (nonzero return stops for_each/loop)
                            frame = stack[-1]
                            csec, cidx = frame[2], frame[3]
                            i, n = frame[4], frame[5]
                            retsec, retpc, caller_regs = \
                                frame[6], frame[7], frame[8]
                            r0 = need_data(regs[0], what)
                            next_i = i + 1
                            base_stack = stack[:-1]

                            def stop_item(cond):
                                # the callback helper returns to its caller:
                                # caller frame intact, r0 = iterations done,
                                # r1-r5 clobbered as for any helper
                                rr = self._ret_clobbered(caller_regs,
                                                         bv64(next_i))
                                return (retsec, retpc, rr, dict(mem),
                                        conds + ([cond] if cond is not None
                                                 else []), dict(counters),
                                        base_stack)

                            # more iterations available iff next_i < n;
                            # callback also stops the loop by returning != 0
                            more_c = z3.simplify(z3.UGT(n, bv64(next_i)))
                            cont_c = z3.simplify(z3.And(more_c, r0 == bv64(0)))
                            stop_c = z3.simplify(
                                z3.Or(z3.ULE(n, bv64(next_i)), r0 != bv64(0)))
                            if not z3.is_false(stop_c) and \
                                    self._feasible(conds + [stop_c]):
                                work.append(stop_item(stop_c))
                            if z3.is_false(cont_c) or \
                                    not self._feasible(conds + [cont_c]):
                                break  # only the stop side was feasible
                            if next_i >= MAX_CB_ITERS:
                                raise Bail(f"callback exceeded {MAX_CB_ITERS} "
                                           f"iterations in {what}")
                            frame2 = frame[:4] + (next_i,) + frame[5:]
                            regs = self._cb_iter_regs(frame2, next_i, mem,
                                                      counters)
                            stack = base_stack + (frame2,)
                            conds = conds + [cont_c]
                            cursec, pc = csec, cidx
                            insns = self._insns(cursec, what)
                            continue
                        if stack:  # subprog return
                            cursec, pc, caller_regs = stack[-1]
                            stack = stack[:-1]
                            insns = self._insns(cursec, what)
                            ret_r0 = regs[0]
                            regs = caller_regs[:]   # caller's frame is intact
                            regs[0] = ret_r0        # only r0 comes back
                            continue
                        ret = need_data(regs[0], what)
                        self.paths.append(Path(conds, ret, mem))
                        break
                    if code == 0:  # JA (gotol when JMP32)
                        pc += 1 + (ins["imm"] if cls == 6 else ins["off"])
                        continue
                    if code == 14:  # JCOND (may_goto)
                        # the escape branch only fires after ~8M iterations —
                        # far beyond any path this executor can enumerate —
                        # so it is modeled as never taken (deliberate
                        # assumption, documented in the README)
                        pc += 1
                        continue
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
                        work.append((cursec, taken, regs[:], dict(mem),
                                     conds + [c], dict(counters), stack))
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
