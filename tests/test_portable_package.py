"""Executable clean-clone, packaging and bootstrap safety checks; no cloud calls."""
from hashlib import sha256
import json
import re
import shutil
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from scripts import bootstrap_policyweaver as bootstrap
from scripts import build_release as release


def repository(root):
    root.mkdir(parents=True)
    for directory in release.TREE_TYPES:
        (root / directory).mkdir(parents=True, exist_ok=True)
    for name in release.EXPLICIT_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# Fixture\n", encoding="utf-8")
    (root / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\n', encoding="utf-8")
    (root / "policyweaver/adapter_cli.py").write_text('print("fixture")\n', encoding="utf-8")
    (root / "tests/test_fixture.py").write_text("def test_fixture(): assert True\n", encoding="utf-8")
    (root / ".agents/skills/policyweaver-dataverse/SKILL.md").write_text("# Loader\n", encoding="utf-8")
    return root


def test_clean_export_has_only_allowed_source_and_verified_manifest(tmp_path):
    root = repository(tmp_path / "working source")
    private = [".env", "policyweaver.customer.config.json", "reports/source.json", "hydration/users.csv",
               ".policyweaver-private/journal.sqlite3", "role-privileges.csv", "tenant.xlsx",
               "policyweaver/credential.json", "policyweaver/private.key", "plugins/PolicyWeaver.ReadContext/key.snk",
               "scripts/remove_old_customer_roles.py", "tests/source-records.json"]
    for name in private:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("PRIVATE SENTINEL", encoding="utf-8")
    for name in release.EXCLUDED_DEMO_TESTS:
        (root / "tests" / name).write_text("import reports.private_fixture\n", encoding="utf-8")
    exported = tmp_path / "client source"
    result = release.build_release(root=root, output_directory=tmp_path / "artifact", source_directory=exported)
    with ZipFile(result["artifact"]) as archive:
        names = set(archive.namelist())
        assert not names.intersection(private)
        assert not names.intersection({"tests/" + name for name in release.EXCLUDED_DEMO_TESTS})
        assert ".agents/skills/policyweaver-dataverse/SKILL.md" in names
        manifest = json.loads(archive.read("RELEASE-MANIFEST.json"))
        assert set(manifest) == names - {"RELEASE-MANIFEST.json"}
        for name in names:
            assert (exported / name).read_bytes() == archive.read(name)
        for name, expected in manifest.items():
            assert sha256(archive.read(name)).hexdigest() == expected
        assert b"PRIVATE SENTINEL" not in b"".join(archive.read(name) for name in names)
    assert not (exported / ".git").exists()


def test_release_is_reproducible_and_refuses_existing_outputs(tmp_path):
    root = repository(tmp_path / "source")
    first = release.build_release(root=root, output_directory=tmp_path / "one")
    second = release.build_release(root=root, output_directory=tmp_path / "two")
    assert first["sha256"] == second["sha256"]
    with pytest.raises(FileExistsError):
        release.build_release(root=root, output_directory=tmp_path / "one")
    occupied = tmp_path / "existing"
    occupied.mkdir()
    sentinel = occupied / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    with pytest.raises(FileExistsError):
        release.build_release(root=root, output_directory=tmp_path / "three", source_directory=occupied)
    assert sentinel.read_text() == "keep"
    assert not (tmp_path / "three").exists()


def test_release_refuses_missing_required_files_and_source_symlink(tmp_path):
    root = repository(tmp_path / "source")
    target = root / "policyweaver/adapter_cli.py"
    target.unlink()
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET", encoding="utf-8")
    try:
        target.symlink_to(outside)
    except OSError:
        pytest.skip("Host cannot create symlinks")
    with pytest.raises(ValueError, match="regular workspace file"):
        release.collect_files(root)


def test_release_rejects_links_to_private_workspace_evidence(tmp_path):
    root = repository(tmp_path / "source")
    (root / "reports").mkdir()
    (root / "reports/customer.json").write_text("{}", encoding="utf-8")
    (root / "README.md").write_text("[Customer evidence](reports/customer.json)\n", encoding="utf-8")
    with pytest.raises(ValueError, match="absent from release"):
        release.collect_files(root)


def test_release_rejects_known_identifier_and_private_key_inside_source(tmp_path, monkeypatch):
    root = repository(tmp_path / "source")
    token = "customer-leak.example.test"
    monkeypatch.setattr(release, "BLOCKED_TOKEN_HASHES", {sha256(token.encode()).hexdigest()})
    path = root / "policyweaver/adapter_cli.py"
    path.write_text(f'url = "https://{token}"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Historical demo identifier"):
        release.collect_files(root)
    path.write_text("-----BEGIN " + "PRIVATE KEY-----", encoding="utf-8")
    with pytest.raises(ValueError, match="Private key material"):
        release.collect_files(root)


def test_bootstrap_plan_uses_exact_argv_and_constraints(tmp_path):
    root = repository(tmp_path / "source with spaces")
    plan = bootstrap.bootstrap_plan(root, "environment with spaces", with_tests=True, with_qualification=True)
    assert len(plan["commands"]) == 3
    assert plan["commands"][0] == [sys.executable, "-m", "venv", str(root / "environment with spaces")]
    assert plan["commands"][1][-3:] == [str(root / "requirements.lock"), "--editable", ".[adapter,test,qualification]"]
    assert plan["commands"][2][-2:] == ["pip", "check"]
    assert not plan["azure_operations"] and not plan["global_skill_installation"]
    assert not (root / "environment with spaces").exists()


def test_bootstrap_refuses_outside_root_and_unrelated_directory(tmp_path):
    root = repository(tmp_path / "source")
    for environment in ("..", ".", str(tmp_path / "global")):
        with pytest.raises(ValueError, match="subdirectory"):
            bootstrap.bootstrap_plan(root, environment)
    (root / ".venv").mkdir()
    (root / ".venv/keep.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError, match="not a complete"):
        bootstrap.bootstrap_plan(root)
    assert (root / ".venv/keep.txt").read_text() == "keep"


def test_bootstrap_stops_on_dependency_failure_without_postcheck(tmp_path, monkeypatch):
    root = repository(tmp_path / "source")
    monkeypatch.setattr(bootstrap, "ROOT", root)
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0 if len(calls) == 1 else 17)
    monkeypatch.setattr(bootstrap.subprocess, "run", run)
    assert bootstrap.main([]) == 17
    assert len(calls) == 2
    assert all(kwargs == {"cwd": root, "check": False} for _, kwargs in calls)


def test_bootstrap_plan_real_subprocess_does_not_create_environment(tmp_path):
    root = repository(tmp_path / "source with spaces")
    script = root / "scripts/bootstrap_policyweaver.py"
    script.write_bytes(Path(bootstrap.__file__).read_bytes())
    result = subprocess.run([sys.executable, str(script), "--plan", "--with-tests"],
                            cwd=tmp_path, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["repository"] == str(root.resolve())
    assert not (root / ".venv").exists()


def test_bootstrap_virtual_environment_command_creates_usable_local_python(tmp_path):
    root = repository(tmp_path / "source")
    plan = bootstrap.bootstrap_plan(root)
    # Exercise the generated venv path without installing or contacting package indexes.
    command = [*plan["commands"][0], "--without-pip"]
    created = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert created.returncode == 0, created.stderr
    query = subprocess.run([plan["python"], "-c", "import sys; print(sys.prefix)"],
                           capture_output=True, text=True, timeout=15)
    assert query.returncode == 0 and Path(query.stdout.strip()).resolve() == Path(plan["venv"])
    assert not bootstrap.bootstrap_plan(root)["creates_environment"]


def test_repo_discovery_link_resolves_to_canonical_skill():
    root = Path(__file__).resolve().parents[1]
    entry = root / ".agents/skills/policyweaver-dataverse/SKILL.md"
    link = re.search(r"\]\(([^)]+/SKILL\.md)\)", entry.read_text(encoding="utf-8")).group(1)
    target = (entry.parent / link).resolve()
    assert target == root / "skills/policyweaver-dataverse/SKILL.md"
    assert target.is_file()


def test_collector_cli_refuses_implicit_tenant(capsys):
    from policyweaver.cli import main
    with pytest.raises(SystemExit) as error:
        main(["collect"])
    assert error.value.code == 2
    assert "--environment" in capsys.readouterr().err


def test_gitignore_hides_private_runtime_but_keeps_onboarding_templates(tmp_path):
    git = shutil.which("git")
    if not git:
        pytest.skip("Git is not installed")
    root = Path(__file__).resolve().parents[1]
    (tmp_path / ".gitignore").write_bytes((root / ".gitignore").read_bytes())
    initialized = subprocess.run([git, "init", "--quiet", str(tmp_path)], capture_output=True, text=True, timeout=20)
    assert initialized.returncode == 0, initialized.stderr
    private = {".env", "policyweaver.customer.config.json", "reports/reader.json", "hydration/users.csv",
               ".policyweaver-client/state.json", "client-local/inventory.json", "tenant.xlsx",
               "role-privileges.csv", ".venv/Scripts/python.exe", "plugins/signing-key.snk"}
    public = {"policyweaver/onboarding.py", "scripts/bootstrap_policyweaver.py",
              "examples/client.env.example", "examples/client-onboarding.request.example.json",
              ".agents/skills/policyweaver-dataverse/SKILL.md"}
    checked = subprocess.run([git, "check-ignore", "-z", "--stdin"], cwd=tmp_path,
                             input=("\0".join(sorted(private | public)) + "\0").encode(), capture_output=True, timeout=20)
    assert checked.returncode == 0, checked.stderr
    assert set(checked.stdout.decode().rstrip("\0").split("\0")) == private
