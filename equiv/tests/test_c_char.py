"""The C-char override is opt-in and preserves byte storage and type IDs."""
import pathlib
import struct
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from btf_rename import main, elf_find_section
from bpfelf import BpfElf
from test_test_tags import synth_object


@pytest.mark.parametrize('enabled', [False, True])
def test_byte_type_override(tmp_path, enabled):
    obj = str(tmp_path / 'char.bpf.o')
    synth_object(obj)
    buf = bytearray(pathlib.Path(obj).read_bytes())
    sh, _, _, _ = elf_find_section(buf, '.BTF')
    strings = b'\0u8\0u32\0'
    types = struct.pack('<IIII', 1, 1 << 24, 1, 8)
    types += struct.pack('<IIII', 4, 1 << 24, 4, 32)
    btf = struct.pack('<HBBIIIII', 0xeb9f, 1, 0, 24, 0, len(types), len(types), len(strings)) + types + strings
    off = len(buf)
    buf.extend(btf)
    struct.pack_into('<QQ', buf, sh + 24, off, len(btf))
    pathlib.Path(obj).write_bytes(buf)
    source = tmp_path / 'char.rs'
    source.write_text('// BTF_C_CHAR: u8\n' if enabled else '')
    main(obj, source=str(source))
    after = BpfElf(obj).btf_types()
    assert after[1][:3] == (1, 'char' if enabled else 'unsigned char', 1)
    assert after[2][:3] == (1, 'unsigned int', 4)
    raw = pathlib.Path(obj).read_bytes()
    _, off, _, _ = elf_find_section(raw, '.BTF')
    assert struct.unpack_from('<I', raw, off + 24 + 12)[0] == (0x01000008 if enabled else 8)
