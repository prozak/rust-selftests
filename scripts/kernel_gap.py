#!/usr/bin/env python3
"""Report upstream BPF selftest drift and sequential x86 patch applicability."""
import argparse
import difflib
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

REPO = Path(__file__).resolve().parents[1]
BPF = "tools/testing/selftests/bpf"
PATCH_NAMES = (
    "0004-selftests-bpf-fix-bpf_testmod.c-compilation-on-UML.patch",
    "0005-libbpf-handle-duplicate-BTF-types-in-relocations.patch",
    "0005b-libbpf-tolerate-duplicate-target-type-ids-in-core-relos.patch",
    "0007-selftests-bpf-make-benchmark-map-definitions-standal.patch",
    "0007b-selftests-bpf-veristat-preserve-zero-max_entries-for.patch",
    "0009-selftests-bpf-include-btf_ptr.h-in-bpf_iter_task_btf.patch",
    "0011-selftests-bpf-fix-arena-allocator-ASM-fallback-globals.patch",
)


def git(repo, *args, check=True):
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    if check and result.returncode:
        raise ValueError(result.stderr.decode(errors="replace").strip())
    return result


def commit(repo, ref):
    return git(repo, "rev-parse", "--verify", "--end-of-options",
               ref + "^{commit}").stdout.decode().strip()


def snapshot(repo, revision, destination):
    # Archive tracked snapshots, not build outputs or dirty working-tree files.
    data = git(repo, "archive", revision, BPF, "tools/lib/bpf").stdout
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        archive.extractall(destination, filter="data")


def files(root):
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in (root / BPF).rglob("*") if p.is_file()}


def text_lines(data):
    return data.decode(errors="replace").splitlines()


def tag_pattern(*trees):
    # Discover tag macros and wrappers from both bpf_misc.h versions. This
    # includes new upstream annotations without maintaining another tag list.
    macros = {}
    for tree in trees:
        for path, data in tree.items():
            if path.endswith("/bpf_misc.h"):
                source = data.decode(errors="replace").replace("\\\n", " ")
                for name, body in re.findall(
                        r"^\s*#\s*define\s+(__\w+)\b(.*)$", source, re.M):
                    macros.setdefault(name, []).append(body)
    names = {"__test_tag"}
    while True:
        added = {name for name, bodies in macros.items()
                 if any(re.search(r"\b" + re.escape(tag) + r"\b", body)
                        for body in bodies for tag in names)}
        if added <= names:
            break
        names |= added
    return re.compile(r"\b(?:" + "|".join(sorted(names)) + r")\b")


def delta(path, before, after, tags):
    old, new = text_lines(before.get(path, b"")), text_lines(after.get(path, b""))
    removed, added = [], []
    for op, a, b, c, d in difflib.SequenceMatcher(
            None, old, new, autojunk=False).get_opcodes():
        if op in ("replace", "delete"):
            removed.extend(old[a:b])
        if op in ("replace", "insert"):
            added.extend(new[c:d])
    return {
        "path": path,
        "status": "added" if path not in before else "removed" if path not in after else "modified",
        "lines_added": len(added), "lines_removed": len(removed),
        "tag_lines_added": [line for line in added if tags.search(line)],
        "tag_lines_removed": [line for line in removed if tags.search(line)],
        "diff": "\n".join(difflib.unified_diff(old, new, "a/" + path,
                                               "b/" + path, lineterm="")),
    }


def compare(before, after, translations, exclusions):
    tags = tag_pattern(before, after)
    prefix = BPF + "/progs/"

    def objects(tree):
        return {Path(path).stem for path in tree
                if path.startswith(prefix) and "/" not in path[len(prefix):]
                and path.endswith(".c")}

    old, new = objects(before), objects(after)
    changes = {"added": [], "removed": [], "modified": []}
    headers, loaders, consumers = [], [], []
    for path in sorted(before.keys() | after.keys()):
        if before.get(path) == after.get(path):
            continue
        row = delta(path, before, after, tags)
        if path.startswith(prefix) and "/" not in path[len(prefix):] and path.endswith(".c"):
            row.update(name=Path(path).stem, translated=Path(path).stem in translations,
                       exclusion=exclusions.get(Path(path).stem))
            changes[row["status"]].append(row)
        if path.endswith(".h"):
            headers.append(row)
        if Path(path).name in ("test_loader.c", "test_loader.h"):
            loaders.append(row)
        if path.startswith(BPF + "/prog_tests/") and path.endswith(".c"):
            consumers.append(row)
    return {
        "coverage": {
            "base_objects": len(old), "candidate_objects": len(new),
            "translations": len(translations),
            "base_translated": len(old & translations),
            "candidate_translated": len(new & translations),
            "translations_absent_at_candidate": sorted(translations - new),
            "candidate_non_targets": {n: exclusions[n] for n in sorted(new & exclusions.keys())},
        },
        "objects": changes, "headers": headers, "test_loader": loaders,
        "consumers": consumers,
    }


def check_patches(root, patch_dir, names=PATCH_NAMES):
    patches = [patch_dir / name for name in names]
    for patch in patches:
        if not patch.is_file():
            raise ValueError(f"missing required x86 patch: {patch}")
    # A private working tree also prevents Git discovering an enclosing repo.
    git(root, "init", "--quiet")
    rows, blocked = [], False
    for patch in patches:
        row = {"name": patch.name, "sha256": hashlib.sha256(patch.read_bytes()).hexdigest()}
        if blocked:
            row.update(status="blocked", detail="earlier patch failed; stack state is incomplete")
        else:
            result = git(root, "apply", "--check", str(patch.resolve()), check=False)
            if result.returncode == 0:
                git(root, "apply", str(patch.resolve()))
                row.update(status="applies", detail="checked after preceding patches")
            elif git(root, "apply", "--reverse", "--check", str(patch.resolve()), check=False).returncode == 0:
                row.update(status="already_applied", detail="reverse check passes; no patch applied")
            else:
                blocked = True
                row.update(status="fails", detail=result.stderr.decode(errors="replace").strip())
        rows.append(row)
    return rows


def markdown(report):
    out = ["# Kernel gap report", "", f"Base: `{report['base_commit']}`",
           f"Candidate: `{report['candidate_commit']}`", "",
           "Committed snapshots only; local kernel edits and build outputs are ignored.",
           "Renames appear as removed/added objects. Tag deltas are textual macro-line hints,",
           "not compiled BTF validation; changes to multiline arguments need diff review.", ""]
    coverage = report["coverage"]
    out += [f"Objects: {coverage['base_objects']} → {coverage['candidate_objects']}; "
            f"translated overlap: {coverage['base_translated']} → {coverage['candidate_translated']} "
            f"({coverage['translations']} local translations).", ""]
    for status, rows in report["objects"].items():
        out += [f"## {status.title()} objects ({len(rows)})", "",
                "| Object | Translated | Non-target reason | Lines + / − | Tag lines + / − |",
                "|---|---|---|---|---|"]
        for row in rows:
            reason = (row["exclusion"] or "—").replace("|", "\\|")
            out.append(f"| {row['name']} | {'yes' if row['translated'] else 'no'} | {reason} | "
                       f"{row['lines_added']} / {row['lines_removed']} | "
                       f"{len(row['tag_lines_added'])} / {len(row['tag_lines_removed'])} |")
        out.append("")
    out += ["## Translations absent at candidate", "",
            ", ".join(coverage["translations_absent_at_candidate"]) or "None.", "",
            "## Candidate non-targets", ""]
    out += [f"- {name}: {reason}" for name, reason in coverage["candidate_non_targets"].items()] or ["None."]
    out += ["", "## x86 patch stack", ""]
    for row in report["patches"]:
        out += [f"- `{row['name']}`: **{row['status']}**", "", "```text", row["detail"], "```", ""]
    for label, rows in (("Shared headers", report["headers"]),
                        ("Test loader", report["test_loader"]),
                        ("C test consumers", report["consumers"]),
                        ("Changed translated objects", [r for rows in report["objects"].values()
                                                        for r in rows if r["translated"]])):
        out += [f"## {label} ({len(rows)})", ""]
        for row in rows:
            out += [f"### {row['path']} ({row['status']})", "", "````diff", row["diff"], "````", ""]
    return "\n".join(out) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tip_checkout", type=Path, help="candidate Git checkout; compares HEAD")
    parser.add_argument("--base-repo", type=Path, default=REPO.parent / "uml-harness/.build/bpf-next-x86")
    parser.add_argument("--base-ref", help="override kernel-commit for historical comparisons")
    parser.add_argument("--patch-dir", type=Path, default=REPO.parent / "uml-harness/patches/bpf-selftests-uml")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args(argv)
    try:
        base = commit(args.base_repo, args.base_ref or (REPO / "kernel-commit").read_text().strip())
        candidate = commit(args.tip_checkout, "HEAD")
        exclusions = {}
        for line in (REPO / "scripts/non-targets.tsv").read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                name, reason = line.split("\t", 1)
                exclusions[name] = reason
        translations = {p.stem for p in (REPO / "progs").glob("*.rs")}
        with tempfile.TemporaryDirectory(prefix="kernel-gap-") as directory:
            base_tree, tip_tree = Path(directory) / "base", Path(directory) / "tip"
            base_tree.mkdir()
            tip_tree.mkdir()
            snapshot(args.base_repo, base, base_tree)
            snapshot(args.tip_checkout, candidate, tip_tree)
            report = compare(files(base_tree), files(tip_tree), translations, exclusions)
            report.update(schema_version=1, base_commit=base, candidate_commit=candidate)
            report["patches"] = check_patches(tip_tree, args.patch_dir)
        print(json.dumps(report, indent=2) if args.format == "json" else markdown(report), end="\n" if args.format == "json" else "")
        return 1 if any(p["status"] == "fails" for p in report["patches"]) else 0
    except (OSError, ValueError, tarfile.TarError) as error:
        print(f"kernel-gap: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
