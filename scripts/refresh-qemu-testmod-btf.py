#!/usr/bin/env python3
"""Regenerate bpf_testmod BTF from existing DWARF, preserving machine code.

Uses the kernel's recorded link command and gen-btf.sh with its normal BTF
features, including consistent_func. Stages a fresh link so resolved BTF IDs
are recalculated. --install updates the kernel module and QEMU runtime copy.
No kernel source, configuration, BPF objects, or test assertions are changed.
Run serially with other builds, swaps, proofs, and QEMU tests.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'equiv'))
from bpfelf import BpfElf
from bpfcore import load_kernel_btf


def executable_hashes(path):
    return {s.name: hashlib.sha256(s.data).hexdigest()
            for s in BpfElf(path).sections if s.flags & 4}


def link_command(saved, output):
    command = shlex.split(saved.split(' := ', 1)[1].strip())
    if Path(command[0]).name not in ('ld', 'ld.lld', 'ld.bfd') or command.count('-o') != 1:
        raise ValueError('expected the recorded kernel module linker command')
    index = command.index('-o') + 1
    if command[index] != 'bpf_testmod.ko':
        raise ValueError('recorded command does not link bpf_testmod.ko')
    command[index] = str(output)
    return command


def atomic_copy(source, destination):
    temporary = destination.with_name(destination.name + '.btf-new')
    shutil.copy2(source, temporary)
    os.replace(temporary, destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, default=REPO.parent / 'uml-harness/.build/bpf-next-x86')
    parser.add_argument('--selftests-output', type=Path, default=REPO.parent / 'uml-harness/.build/selftests-output-qemu')
    parser.add_argument('--output', type=Path, default=REPO / 'bld/testmod-btf')
    parser.add_argument('--install', action='store_true')
    args = parser.parse_args()
    revision = (REPO / 'pahole-commit').read_text().strip()
    pahole = REPO / f'bld/pahole-{revision}/install/bin/pahole'
    if not pahole.is_file():
        parser.error('run bash scripts/build-qemu-pahole.sh first')
    kernel, output = args.kernel.resolve(), args.output.resolve()
    kernel_pin = (REPO / 'kernel-commit').read_text().strip()
    actual_pin = subprocess.check_output(
        ['git', '-C', str(kernel), 'merge-base', 'HEAD', 'origin/master'], text=True).strip()
    if actual_pin != kernel_pin:
        parser.error(f'kernel base {actual_pin} differs from pin {kernel_pin}')
    module_dir = kernel / 'tools/testing/selftests/bpf/test_kmods'
    original = module_dir / 'bpf_testmod.ko'
    runtime = args.selftests_output.resolve() / 'bpf_testmod.ko'
    rebuilt = output / 'bpf_testmod.ko'
    if rebuilt in (original, runtime):
        parser.error('--output must be a separate staging directory')
    output.mkdir(parents=True, exist_ok=True)
    before = executable_hashes(original)
    command = link_command((module_dir / '.bpf_testmod.ko.cmd').read_text(), rebuilt)
    subprocess.run(command, cwd=module_dir, check=True)
    env = os.environ.copy()
    # Resolve the normal kernel feature flags instead of duplicating a list
    # that could drift when the kernel pin changes.
    flags, resolve_flags = subprocess.check_output(
        ['make', '-s', '--no-print-directory', '-f', '-', 'JOBS=4',
         f'KBUILD_EXTMOD={module_dir}', 'print'], cwd=kernel,
        input=b'include include/config/auto.conf\ninclude scripts/Kbuild.include\ninclude scripts/Makefile.btf\nprint:\n\t@echo $(PAHOLE_FLAGS)\n\t@echo $(RESOLVE_BTFIDS_FLAGS)\n',
        env=env, text=False).decode().splitlines()
    env.update(PAHOLE=str(pahole), PAHOLE_FLAGS=flags, OBJCOPY='objcopy',
               RESOLVE_BTFIDS_FLAGS=resolve_flags,
               RESOLVE_BTFIDS=str(kernel / 'tools/bpf/resolve_btfids/resolve_btfids'))
    subprocess.run(['bash', str(kernel / 'scripts/gen-btf.sh'), '--btf_base',
                    str(kernel / 'vmlinux'), str(rebuilt)], env=env, check=True)
    if not before or executable_hashes(rebuilt) != before:
        raise RuntimeError('rebuilt module machine code differs; refusing to install')
    btf = load_kernel_btf(rebuilt, base=load_kernel_btf(kernel / 'vmlinux'))
    names = {t.name for t in btf.types.values() if t.kind == 12}
    if 'bpf_testmod_test_int128_arg' not in names:
        raise RuntimeError('int128 tracing target is still absent from regenerated BTF')
    if args.install:
        atomic_copy(rebuilt, original)
        atomic_copy(rebuilt, runtime)
    manifest = dict(pahole_commit=revision, pahole_sha256=hashlib.sha256(pahole.read_bytes()).hexdigest(),
                    kernel_pin=kernel_pin,
                    vmlinux_btf_sha256=hashlib.sha256(BpfElf(kernel / 'vmlinux').section_by_name('.BTF').data).hexdigest(),
                    pahole_flags=flags, resolve_btfids_flags=resolve_flags, executable_sha256=before,
                    module_sha256=hashlib.sha256(rebuilt.read_bytes()).hexdigest(),
                    installed=args.install, int128_target_present=True)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Module BTF rebuilt; int128 target present; executable sections unchanged; installed={args.install}')


if __name__ == '__main__':
    main()
