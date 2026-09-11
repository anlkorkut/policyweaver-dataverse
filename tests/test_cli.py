from pathlib import Path

import dvaccess.cli as cli

CONFIG = """
environment: {name: t, dataverse_url: "https://x.crm.dynamics.com"}
auth: {tenant_id: t}
fabric: {workspace_id: w, item_id: i}
"""


def _config(tmp_path: Path) -> str:
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG, encoding="utf-8")
    return str(path)


def test_ctrl_c_exits_130_with_one_line_message(tmp_path, monkeypatch, caplog):
    def interrupted(cfg, args):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "cmd_extract", interrupted)
    assert cli.main(["--config", _config(tmp_path), "extract"]) == 130
    assert "nothing was changed" in caplog.text


def test_ctrl_c_during_apply_points_to_verify(tmp_path, monkeypatch, caplog):
    def interrupted(cfg, args, *, apply_changes):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_plan_or_apply", interrupted)
    assert cli.main(["--config", _config(tmp_path), "apply", "--yes"]) == 130
    assert "dvaccess verify" in caplog.text
