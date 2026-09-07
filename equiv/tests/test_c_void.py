"""C void pointers must not become pointers to Rust's c_void enum."""
import pathlib
import struct
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from btf_rename import main, elf_find_section
from bpfelf import BpfElf
from test_test_tags import synth_object


@pytest.mark.parametrize("enabled", [False, True])
def test_void_override_preserves_other_types_and_references(tmp_path, enabled):
    obj = tmp_path / "void.bpf.o"
    synth_object(obj)
    buf = bytearray(obj.read_bytes())
    sh, _, _, _ = elf_find_section(buf, ".BTF")
    strings = b"\0c_void\0unsigned int\0user_ptr\0"
    types = struct.pack("<III", 0, 2 << 24, 2)  # PTR, forward reference
    types += struct.pack("<III", 1, 6 << 24, 1)  # ENUM c_void
    types += struct.pack("<IIII", 8, 1 << 24, 4, 32)  # INT unsigned int
    types += struct.pack("<III", 0, 2 << 24, 3)  # unrelated PTR
    types += struct.pack("<III", 0, 2 << 24, 1)  # pointer-to-pointer
    types += struct.pack("<IIII", 21, 14 << 24, 1, 1)  # VAR -> first PTR
    btf = struct.pack("<HBBIIIII", 0xeb9f, 1, 0, 24, 0, len(types),
                      len(types), len(strings)) + types + strings
    off = len(buf)
    buf.extend(btf)
    struct.pack_into("<QQ", buf, sh + 24, off, len(btf))
    obj.write_bytes(buf)
    before = BpfElf(obj)
    source = tmp_path / "void.rs"
    source.write_text("// BTF_C_VOID: c_void\n" if enabled else "")
    main(obj, source=source)
    after = BpfElf(obj)
    expected = before.btf_types().copy()
    if enabled:
        expected[1] = (2, "", 0, 0, None)
    assert after.btf_types() == expected
    assert after.section_by_name(".shstrtab").data == before.section_by_name(".shstrtab").data
    if not enabled:
        assert obj.read_bytes() == bytes(buf)


def test_void_override_without_matching_pointer_fails_without_writing(tmp_path):
    obj = tmp_path / "no-void.bpf.o"
    synth_object(obj)
    before = obj.read_bytes()
    source = tmp_path / "void.rs"
    source.write_text("// BTF_C_VOID: c_void\n")
    with pytest.raises(ValueError, match="requires a pointer"):
        main(obj, source=source)
    assert obj.read_bytes() == before
