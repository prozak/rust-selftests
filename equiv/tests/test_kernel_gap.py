"""Gap reports use upstream snapshots and check the complete ordered patch stack."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import kernel_gap as gap


def run(repo, *args):
    return gap.git(repo, *args).stdout.decode().strip()


def write(root, path, text):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


def save(repo):
    run(repo, "add", ".")
    run(repo, "-c", "user.name=Test", "-c", "user.email=test@example.com",
        "commit", "-qm", "fixture")
    return run(repo, "rev-parse", "HEAD")


@pytest.fixture
def kernel(tmp_path):
    repo = tmp_path / "kernel with spaces"
    repo.mkdir()
    run(repo, "init", "-q")
    write(repo, gap.BPF + "/progs/a.c", "__success\nint a;\n")
    write(repo, gap.BPF + "/progs/old.c", "int old;\n")
    write(repo, gap.BPF + "/progs/bpf_misc.h",
          '#define __test_tag(t) attribute(t)\n#define __success __test_tag("success")\n')
    write(repo, gap.BPF + "/test_loader.c", "int loader;\n")
    write(repo, "tools/lib/bpf/lib.c", "int library;\n")
    base = save(repo)
    return repo, base


def test_object_overlap_headers_loader_consumers_and_new_tags(kernel, tmp_path):
    repo, base = kernel
    old_tree = tmp_path / "old"
    old_tree.mkdir()
    gap.snapshot(repo, base, old_tree)
    write(repo, gap.BPF + "/progs/a.c", '__skip("reason")\nint a = 1;\n')
    write(repo, gap.BPF + "/progs/bpf_misc.h",
          '#define __test_tag(t) attribute(t)\n#define __skip(t) __test_tag(t)\n')
    (repo / gap.BPF / "progs/old.c").rename(repo / gap.BPF / "progs/new.c")
    write(repo, gap.BPF + "/progs/fixture.c", "")
    write(repo, gap.BPF + "/progs/nested/not-an-object.c", "int nested;\n")
    write(repo, gap.BPF + "/test_loader.c", "int new_loader;\n")
    write(repo, gap.BPF + "/prog_tests/consumer.c", "int consumer;\n")
    report = gap.compare(gap.files(old_tree), gap.files(repo), {"a", "old", "absent"},
                         {"fixture": "fixture only"})
    assert report["coverage"]["base_objects"] == 2
    assert report["coverage"]["candidate_objects"] == 3
    assert report["coverage"]["candidate_translated"] == 1
    assert report["coverage"]["translations_absent_at_candidate"] == ["absent", "old"]
    assert report["coverage"]["candidate_non_targets"] == {"fixture": "fixture only"}
    assert [r["name"] for r in report["objects"]["added"]] == ["fixture", "new"]
    assert report["objects"]["removed"][0]["translated"]
    change, = report["objects"]["modified"]
    assert change["tag_lines_removed"] == ["__success"]
    assert change["tag_lines_added"] == ['__skip("reason")']
    assert len(report["headers"]) == len(report["test_loader"]) == len(report["consumers"]) == 1
    assert "+int new_loader;" in report["test_loader"][0]["diff"]


def patches(repo, directory, count=2):
    directory.mkdir()
    names = []
    for i in range(count):
        write(repo, "tools/lib/bpf/lib.c", f"int library = {i};\n")
        name = f"{i}.patch"
        (directory / name).write_bytes(gap.git(repo, "diff", "--binary").stdout)
        names.append(name)
        save(repo)
    return names


def test_patch_stack_dependencies_and_read_only_snapshots(kernel, tmp_path):
    repo, base = kernel
    patch_dir = tmp_path / "patches"
    names = patches(repo, patch_dir)
    original_index = (repo / ".git/index").read_bytes()
    original_head = run(repo, "rev-parse", "HEAD")
    write(repo, "tools/lib/bpf/lib.c", "dirty local edit\n")
    tree = tmp_path / "snapshot"
    tree.mkdir()
    gap.snapshot(repo, base, tree)
    # The second patch cannot apply on its own; it requires the first one.
    assert gap.git(tree, "apply", "--check", str(patch_dir / names[1]), check=False).returncode
    assert [r["status"] for r in gap.check_patches(tree, patch_dir, names)] == ["applies", "applies"]
    assert (tree / "tools/lib/bpf/lib.c").read_text() == "int library = 1;\n"
    assert (repo / "tools/lib/bpf/lib.c").read_text() == "dirty local edit\n"
    assert (repo / ".git/index").read_bytes() == original_index
    assert run(repo, "rev-parse", "HEAD") == original_head


def test_failed_patch_blocks_remaining_stack_and_missing_patch_is_error(kernel, tmp_path):
    repo, base = kernel
    patch_dir = tmp_path / "patches"
    names = patches(repo, patch_dir)
    tree = tmp_path / "snapshot"
    tree.mkdir()
    gap.snapshot(repo, base, tree)
    write(tree, "tools/lib/bpf/lib.c", "conflicting upstream change\n")
    rows = gap.check_patches(tree, patch_dir, names)
    assert [r["status"] for r in rows] == ["fails", "blocked"]
    assert "patch does not apply" in rows[0]["detail"]
    with pytest.raises(ValueError, match="missing required x86 patch"):
        gap.check_patches(tree, patch_dir, ["missing.patch"])


def test_cli_snapshot_selection_output_and_exit_status(kernel, tmp_path, monkeypatch, capsys):
    repo, base = kernel
    patch_dir = tmp_path / "patches"
    names = patches(repo, patch_dir, len(gap.PATCH_NAMES))
    for old, new in zip(names, gap.PATCH_NAMES):
        (patch_dir / old).rename(patch_dir / new)
    project = tmp_path / "project"
    write(project, "kernel-commit", base + "\n")
    write(project, "progs/a.rs", "")
    write(project, "scripts/non-targets.tsv", "# none\n")
    monkeypatch.setattr(gap, "REPO", project)
    # A separate clone at the base avoids altering the source checkout.
    candidate = tmp_path / "candidate"
    subprocess.run(["git", "clone", "-q", str(repo), str(candidate)], check=True)
    run(candidate, "checkout", "-q", base)
    write(candidate, gap.BPF + "/progs/a.c", "ignored dirty source\n")
    argv = [str(candidate), "--base-repo", str(repo), "--patch-dir", str(patch_dir), "--format", "json"]
    assert gap.main(argv) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["base_commit"] == report["candidate_commit"] == base
    assert all(not rows for rows in report["objects"].values())
    assert all(p["status"] == "applies" for p in report["patches"])
    assert "# Kernel gap report" in gap.markdown(report)
    write(candidate, "tools/lib/bpf/lib.c", "committed conflict\n")
    save(candidate)
    assert gap.main(argv) == 1
    assert json.loads(capsys.readouterr().out)["patches"][0]["status"] == "fails"
    assert gap.main(argv + ["--base-ref", "missing-revision"]) == 2
    assert "kernel-gap:" in capsys.readouterr().err


def test_already_applied_patch_is_reported(kernel, tmp_path):
    repo, _ = kernel
    patch_dir = tmp_path / "patches"
    names = patches(repo, patch_dir, 1)
    tree = tmp_path / "snapshot"
    tree.mkdir()
    gap.snapshot(repo, run(repo, "rev-parse", "HEAD"), tree)
    assert gap.check_patches(tree, patch_dir, names)[0]["status"] == "already_applied"
