"""__kconfig extern values, filled the way libbpf fills them at load time.

A `extern T CONFIG_X __kconfig;` is not a free input: libbpf resolves it
from the running kernel's config before the program loads, and the
LINUX_* externs are virtual values libbpf computes itself
(bpf_object__resolve_externs). The prover already applies CO-RE against
the pinned kernel; this does the same for kconfig, so a program reading
CONFIG_HZ sees 1000 on both sides rather than a symbolic value the C side
could branch on and a hardcoding translation could not.

Encoding follows tools/lib/bpf/libbpf.c: set_kcfg_value_tri / _str / _num
and bpf_object__process_kconfig_line. Whatever libbpf rejects (a missing
non-weak extern, 'm' into a bool, a value that doesn't fit) is a
KconfigError here: the C object would fail to load, so there is nothing to
prove.
"""
import os
import re

import paths


class KconfigError(Exception):
    pass


TRISTATE = {"n": 0, "y": 1, "m": 2}  # enum libbpf_tristate


class Kconfig:
    def __init__(self, config, version, has_bpf_cookie=True):
        """config: CONFIG_* name -> raw value text as in .config.
        version: KERNEL_VERSION(major, minor, patch) of the target kernel."""
        self.config = config
        self.version = version
        self.has_bpf_cookie = has_bpf_cookie

    @classmethod
    def from_kernel_tree(cls, kernel_src=None):
        """The pinned kernel's .config and Makefile version, or None when
        the tree isn't there (the prover then keeps bailing on kconfig)."""
        kernel_src = kernel_src or paths.KERNEL_SRC
        try:
            config = parse_config(open(os.path.join(kernel_src, ".config")).read())
            version = makefile_version(open(os.path.join(kernel_src, "Makefile")).read())
        except OSError:
            return None
        return cls(config, version)

    def value(self, name, decl, weak):
        """The bytes libbpf writes for one extern.

        decl: (kcfg type, size, signed) from BpfElf.kconfig_externs()."""
        kind, size, signed = decl
        if name.startswith("CONFIG_"):
            raw = self.config.get(name)
            if raw is None:
                if not weak:
                    raise KconfigError(f"{name} is not set and the extern is not __weak")
                return bytes(size)
            return encode(name, raw, decl)
        if name == "LINUX_KERNEL_VERSION":
            v = self.version
        elif name == "LINUX_HAS_BPF_COOKIE":
            v = int(self.has_bpf_cookie)
        elif name == "LINUX_HAS_SYSCALL_WRAPPER":
            # libbpf probes for the arch syscall wrapper (__x64_sys_bpf),
            # which exists exactly when the arch selects it
            v = int(self.config.get("CONFIG_ARCH_HAS_SYSCALL_WRAPPER") == "y")
        elif name.startswith("LINUX_") and weak:
            return bytes(size)
        else:
            raise KconfigError(f"{name}: unrecognized virtual extern")
        return set_num(name, v, decl)


def parse_config(text):
    """CONFIG_X=value lines; `# CONFIG_X is not set` means absent."""
    out = {}
    for line in text.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def makefile_version(text):
    """KERNEL_VERSION() of a kernel tree, from its top-level Makefile."""
    def field(key):
        m = re.search(rf"^{key}\s*=\s*(\d+)", text, re.M)
        if not m:
            raise KconfigError(f"no {key} in the kernel Makefile")
        return int(m.group(1))
    return (field("VERSION") << 16) + (field("PATCHLEVEL") << 8) + min(field("SUBLEVEL"), 255)


def encode(name, raw, decl):
    kind, size, _signed = decl
    if not raw:
        raise KconfigError(f"{name}: no value")
    if raw[0] in "ynm":
        if kind == "bool":
            if raw[0] == "m":
                raise KconfigError(f"{name}: 'm' implies a tristate or char type")
            return bytes([raw[0] == "y"])
        if kind == "tristate":
            return TRISTATE[raw[0]].to_bytes(size, "little")
        if kind == "char":
            return raw[0].encode()
        raise KconfigError(f"{name}: '{raw[0]}' implies a bool, tristate or char type")
    if raw[0] == '"':
        if kind != "char_arr":
            raise KconfigError(f"{name}: a string implies a char array")
        if len(raw) < 2 or raw[-1] != '"':
            raise KconfigError(f"{name}: invalid string {raw}")
        s = raw[1:-1].encode()[:size - 1]
        return s + bytes(size - len(s))
    if kind not in ("int", "char"):
        raise KconfigError(f"{name}: '{raw}' implies an integer type")
    return set_num(name, strtoull(name, raw), decl)


def strtoull(name, text):
    """C strtoull(text, &end, 0) that must consume all of text."""
    neg = text.startswith("-")
    body = text[1:] if neg or text.startswith("+") else text
    try:
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", body):
            v = int(body, 16)
        elif re.fullmatch(r"0[0-7]*", body):
            v = int(body, 8)
        elif re.fullmatch(r"[1-9][0-9]*", body):
            v = int(body)
        else:
            raise ValueError
    except ValueError:
        raise KconfigError(f"{name}: '{text}' isn't a valid integer") from None
    if v >= 1 << 64:
        raise KconfigError(f"{name}: '{text}' overflows")
    return (-v) % (1 << 64) if neg else v


def set_num(name, v, decl):
    """libbpf set_kcfg_value_num(): range-checked little-endian store."""
    kind, size, signed = decl
    if kind not in ("int", "char", "bool"):
        raise KconfigError(f"{name}: value {v} implies an integer, char or boolean type")
    if kind == "bool" and v > 1:
        raise KconfigError(f"{name}: value {v} isn't boolean compatible")
    if size not in (1, 2, 4, 8):
        raise KconfigError(f"{name}: unsupported size {size}")
    bits = size * 8
    if size != 8 and not (
            (v + (1 << (bits - 1))) % (1 << 64) < (1 << bits) if signed
            else v >> bits == 0):
        raise KconfigError(f"{name}: value {v} doesn't fit in {size} bytes")
    return (v & ((1 << bits) - 1)).to_bytes(size, "little")
