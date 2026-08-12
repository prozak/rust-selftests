"""Helper prototypes, parsed from the kernel's own UAPI header.

`include/uapi/linux/bpf.h` documents every helper with its exact C
prototype in the comment block above the FN() list, e.g.

    * long bpf_fib_lookup(void *ctx, struct bpf_fib_lookup *params,
    *                     int plen, u32 flags)

and the FN() list gives each helper its number. Parsing both yields
id -> (name, return type, [parameter types]), which is what lets the
generic helper model in bpfsym.py compare a call at the widths the
kernel actually reads instead of hand-listing every helper.

Types are returned as raw C spellings; `arg_width()` resolves the scalar
ones and `pointee()` names the struct a pointer refers to (sized against
the target kernel's BTF by the caller, since only that knows the layout).
"""
import os
import re

DEFAULT_HEADER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))),
    "uml-harness", ".build", "bpf-next", "include", "uapi", "linux", "bpf.h")

# scalar C spellings -> byte width
_SCALARS = {
    "char": 1, "signed char": 1, "unsigned char": 1, "u8": 1, "__u8": 1,
    "s8": 1, "__s8": 1, "bool": 1,
    "short": 2, "unsigned short": 2, "u16": 2, "__u16": 2, "s16": 2,
    "__s16": 2, "__be16": 2, "__le16": 2,
    "int": 4, "unsigned int": 4, "unsigned": 4, "u32": 4, "__u32": 4,
    "s32": 4, "__s32": 4, "__be32": 4, "__le32": 4, "__wsum": 4,
    "long": 8, "unsigned long": 8, "long long": 8, "unsigned long long": 8,
    "u64": 8, "__u64": 8, "s64": 8, "__s64": 8, "__be64": 8, "size_t": 8,
    "void": 0,
}

_PROTO_RE = re.compile(
    r"^\s*\*\s*((?:const\s+)?[A-Za-z_][\w ]*?[\w*]+)\s+"
    r"(bpf_[a-z0-9_]+)\(([^)]*)\)\s*$")


def _norm(t):
    t = " ".join(t.replace("*", " * ").split())
    t = t.replace("const ", "").replace("volatile ", "").strip()
    return t


def parse_header(path=None):
    """{helper name: (return type, [param types])} from the doc comments."""
    path = path or DEFAULT_HEADER
    if not os.path.exists(path):
        return {}
    protos, buf = {}, ""
    with open(path, errors="replace") as f:
        for line in f:
            if not line.startswith(" *"):
                buf = ""
                continue
            # prototypes may wrap across comment lines
            stripped = line.rstrip("\n")
            buf = (buf + " " + stripped.lstrip(" *")).strip() if buf else stripped
            if "(" in buf and ")" not in buf:
                continue
            m = _PROTO_RE.match(buf if buf.startswith(" *") else " * " + buf)
            buf = ""
            if not m:
                continue
            ret, name, args = m.group(1), m.group(2), m.group(3)
            if name in protos:
                continue
            params = []
            for a in args.split(","):
                a = _norm(a)
                if not a or a == "void":
                    continue
                # split the parameter NAME off the type when present; the
                # name matters (`u32 size` following `void *dst` is how the
                # kernel says how much of dst it reads)
                pname, toks = "", a.split()
                if len(toks) > 1 and toks[-1] != "*" and "*" not in toks[-1]:
                    if _norm(" ".join(toks[:-1])) in _SCALARS or "*" in toks:
                        pname, a = toks[-1], " ".join(toks[:-1])
                params.append((_norm(a), pname))
            protos[name] = (_norm(ret), params)
    return protos


def helper_ids(path=None):
    """{id: helper name} from the FN(...) list."""
    path = path or DEFAULT_HEADER
    if not os.path.exists(path):
        return {}
    out = {}
    for m in re.finditer(r"FN\((\w+),\s*(\d+),", open(path, errors="replace").read()):
        out[int(m.group(2))] = "bpf_" + m.group(1)
    return out


_LEN_NAME = re.compile(r"(^|_)(size|len|size_t|sz)$")


def length_param(params, i):
    """Index of the argument giving the length of pointer argument `i`, or
    None. The UAPI prototypes state this positionally and by name — a
    buffer pointer is followed by its size (`void *dst, u32 size`,
    `const char *buf, size_t buf_len`) — which is the only thing that says
    how much of an unsized buffer the kernel actually reads."""
    j = i + 1
    if j >= len(params):
        return None
    ctype, pname = params[j]
    if "*" in ctype or arg_width(ctype) not in (4, 8):
        return None
    return j if _LEN_NAME.search(pname or "") else None


def signatures(path=None):
    """{helper id: (name, return type, [(param type, param name)])}."""
    protos = parse_header(path)
    out = {}
    for hid, name in helper_ids(path).items():
        if name in protos:
            ret, params = protos[name]
            out[hid] = (name, ret, params)
    return out


def arg_width(ctype):
    """Byte width of a scalar C type, or None if it is not a scalar."""
    t = _norm(ctype)
    if "*" in t:
        return 8
    return _SCALARS.get(t)


def pointee(ctype):
    """('struct foo' | 'void' | 'char' | ...) for a pointer type, else None."""
    t = _norm(ctype)
    if "*" not in t:
        return None
    return _norm(t.split("*")[0])
