"""Export reviewed client source only; never initialize Git in a live workspace.

Use --source-directory to export a new clean directory for Git review. Existing
outputs are refused. The allowlist is a packaging boundary, not a secret scanner.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import posixpath
import re
import stat
import tomllib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]


EXCLUDED_DEMO_TESTS = {
    "test_hydration_plan.py", "test_role_diversity_hydrator.py",
    "test_reader_label_export.py", "test_prepared_diversity_gate.py",
}
EXPLICIT_FILES = (
    "README.md", "pyproject.toml", "requirements.lock", "Dockerfile", ".dockerignore", ".gitignore",
    ".github/workflows/verify.yml", "examples/policyweaver.config.example.json",
    "examples/client-onboarding.request.example.json", "examples/client-onboarding.selections.example.json",
    "examples/client.env.example", "docs/CLIENT-ONBOARDING.md", "docs/CLIENT-INPUTS.md",
    "docs/MIGRATING-FROM-DVACCESS.md",
    "docs/ADAPTER-OPERATIONS.md", "docs/ADAPTER-SECURITY.md", "docs/LIVE-ACCEPTANCE.md",
    "docs/READ-CONTEXT-PLUGIN.md", "docs/TERMINAL-AND-PRODUCTION.md", "docs/MANUAL-RETENTION.md",
    "docs/READABLE-ROLES-AND-DIVERSITY.md", "deploy/README.md", "deploy/azure-watchdog.bicep",
    "deploy/registry-pull.bicep", "deploy/watchdog-alerts.bicep", "scripts/qualify_reader.py",
    "scripts/build_release.py", "scripts/manage_read_context.py", "scripts/Run-PolicyWeaver.ps1",
    "scripts/run_adapter_terminal.py", "scripts/bootstrap_policyweaver.py",
)
TREE_TYPES = {
    "policyweaver": {".py", ".html", ".css", ".js"}, "tests": {".py"},
    "skills/policyweaver-dataverse": {".md", ".yaml"},
    ".agents/skills/policyweaver-dataverse": {".md", ".yaml"},
    "plugins/PolicyWeaver.ReadContext": {".cs", ".csproj", ".ps1", ".props", ".targets", ".md"},
}
SKIP_DIRECTORIES = {"__pycache__", "bin", "obj", "TestResults", ".git", ".pytest_cache"}
# Historical demo identifier fingerprints keep their actual values out of source.
BLOCKED_TOKEN_HASHES = {
    "cbb8d4898ac5639a521681790aa78bbb577d0d520943e6b0d94b2a2931178ef2",
    "92b1a9b68306a7b2a932ee0996d033965f81bb11acf66a4e0e7be1179c0261c9",
    "4f5b40beeeaa7e75f61b0f885ce3c562f1c45521eaff23fb582bc18da94a62a1",
    "3e50ccf7a73a0256f15f6980048d4596086b26d612a9317d1f02d15e5180f3d5",
    "bf01843affea492be16ea96a6dd5ecb197c49b00f41964bb262ea91b1dce3e9d",
    "893a3904c78db69839c2e7e1be4571c21813dc97a2174b463d0c3de699d14fd3",
    "c610c2600634fbb573b8748f5ba7930a7303e5833517c21aa83901bac89c5e2d",
    "d0d2e91cf03698f349468b944a22bce7a9c3f566817fe1a26be82a123e887995",
    "0ad0d9e2c876a8c8173a2a9dea852a2e9e375826487c55036b67117438122757",
    "ea2d0cf76d57114b106f4fb9b9ca43a1146df3f31c03b53cdc9dbe98ea5909fe",
}


def _regular_file(root, path):
    if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root):
        raise ValueError(f"Release source must be a regular workspace file: {path.relative_to(root)}")
    for parent in path.parents:
        if parent == root:
            break
        if parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction()):
            raise ValueError("Release source cannot traverse links or junctions")


def collect_files(root=ROOT):
    root = Path(root).resolve()
    paths = {root / name for name in EXPLICIT_FILES}
    for directory, suffixes in TREE_TYPES.items():
        base = root / directory
        if not base.is_dir():
            raise ValueError(f"Required release directory is missing: {directory}")
        for path in base.rglob("*"):
            if SKIP_DIRECTORIES.intersection(path.relative_to(root).parts):
                continue
            if path.is_file() and (path.suffix in suffixes or
                    (directory.startswith("plugins/") and path.name in {"packages.lock.json", ".gitignore"})):
                if directory == "tests" and path.name in EXCLUDED_DEMO_TESTS:
                    continue
                paths.add(path)
    files = {}
    for path in sorted(paths):
        _regular_file(root, path)
        relative = path.relative_to(root).as_posix()
        content = path.read_bytes()
        decoded = content.decode("utf-8-sig")
        tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9.\-]{4,}", decoded)
        tokens.extend(re.findall(r"[a-fA-F0-9]{32}", decoded))
        if any(sha256(token.lower().encode()).hexdigest() in BLOCKED_TOKEN_HASHES for token in tokens):
            raise ValueError(f"Historical demo identifier remains in release source: {relative}")
        if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", decoded):
            raise ValueError(f"Private key material found in release source: {relative}")
        files[relative] = content
    validate_document_links(files)
    return files


def validate_document_links(files):
    """Resolve relative runbook links against exported files, not the live tree."""
    for name, content in files.items():
        if not name.endswith(".md"):
            continue
        for raw in re.findall(r"\]\(([^)]+)\)", content.decode("utf-8-sig")):
            raw = raw.strip().strip("<>")
            parsed = urlsplit(raw)
            if parsed.scheme or raw.startswith(("#", "//")):
                continue
            target = posixpath.normpath(posixpath.join(posixpath.dirname(name), unquote(parsed.path)))
            if target not in files and not any(path.startswith(target.rstrip("/") + "/") for path in files):
                raise ValueError(f"Relative documentation link is absent from release: {name} -> {raw}")


def build_release(*, root=ROOT, output_directory=None, source_directory=None):
    root = Path(root).resolve()
    files = collect_files(root)
    version = tomllib.loads(files["pyproject.toml"].decode("utf-8-sig"))["project"]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Release version must be a numeric semantic version")
    output_directory = Path(output_directory or root / "dist").resolve()
    output = output_directory / f"policyweaver-{version}-source.zip"
    if output.exists() or output.is_symlink():
        raise FileExistsError("Release archive already exists; use a new output directory")
    if source_directory is not None:
        source_directory = Path(source_directory).absolute()
        if source_directory.exists() or source_directory.is_symlink():
            raise FileExistsError("Clean source directory must not already exist")
        if source_directory.resolve() == root or root.is_relative_to(source_directory.resolve()):
            raise ValueError("Clean source directory cannot contain the working repository")
    manifest = {name: sha256(content).hexdigest() for name, content in files.items()}
    payload = {**files, "RELEASE-MANIFEST.json": (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()}
    output_directory.mkdir(parents=True, exist_ok=True)
    if source_directory is not None:
        source_directory.mkdir(parents=True, exist_ok=False)
        for name, content in payload.items():
            path = source_directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as destination:
                destination.write(content)
    with ZipFile(output, "x", ZIP_DEFLATED) as archive:
        for name, content in sorted(payload.items()):
            info = ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, content)
    return {"artifact": str(output), "source_directory": str(source_directory) if source_directory else None,
            "files": len(files), "sha256": sha256(output.read_bytes()).hexdigest(),
            "demo_fixture_tests_excluded": sorted(EXCLUDED_DEMO_TESTS)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path)
    parser.add_argument("--source-directory", type=Path, help="Also export a new clean directory for Git review")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(build_release(output_directory=args.output_directory, source_directory=args.source_directory)))
        return 0
    except (OSError, ValueError) as error:
        parser.exit(2, f"Release failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
