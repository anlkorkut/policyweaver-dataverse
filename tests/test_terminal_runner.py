"""Real subprocess checks: output streaming must retain logs and failure status."""
import json
import builtins
import io
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import time

import pytest

from scripts.run_adapter_terminal import command_for, stream_process
from scripts import run_adapter_terminal


def test_default_prepare_command_never_invokes_worker_watchdog_or_publish():
    command = command_for('python', Path('config with spaces.json'), 'prepare')
    assert command[-1] == 'prepare'
    assert '--progress' in command
    assert not {'worker', 'run', 'watchdog', 'withdraw', 'publish'}.intersection(command)
    assert 'config with spaces.json' in command


def test_publish_needs_generation_and_boundary():
    with pytest.raises(ValueError):
        command_for('python', Path('config.json'), 'publish')
    with pytest.raises(ValueError):
        command_for('python', Path('config.json'), 'publish', 123)
    command = command_for('python', Path('config.json'), 'publish', 123, Path('boundary with spaces.json'))
    assert command[-2:] == ['--boundary', 'boundary with spaces.json']


def test_withdraw_is_an_explicit_terminal_operation_without_a_generation():
    command = command_for('python', Path('manual config.json'), 'withdraw')
    assert command[-1] == 'withdraw'
    assert '--generation' not in command and '--boundary' not in command


def test_separate_streams_and_nonzero_exit_survive_wrapper(tmp_path, capsys):
    directory = tmp_path / 'logs with spaces'
    script = "import sys; print('{\"status\":\"failed\"}', flush=True); print('{\"event\":\"scan_started\"}', file=sys.stderr, flush=True); sys.exit(7)"
    code = stream_process([sys.executable, '-u', '-c', script], directory, cwd=tmp_path)
    assert code == 7
    assert json.loads((directory / 'result.json').read_text())['status'] == 'failed'
    assert json.loads((directory / 'progress.jsonl').read_text())['event'] == 'scan_started'
    assert json.loads((directory / 'execution.json').read_text())['exit_code'] == 7
    terminal = (directory / 'terminal.log').read_text()
    assert 'stdout:' in terminal and 'stderr:' in terminal
    visible = capsys.readouterr().out
    assert 'scan_started' in visible and 'exit=7' in visible


def test_existing_log_directory_is_not_overwritten(tmp_path):
    with pytest.raises(FileExistsError):
        stream_process([sys.executable, '-c', 'pass'], tmp_path)


def test_log_open_failure_never_starts_an_adapter(tmp_path, monkeypatch):
    started = []
    original_open = Path.open
    def open_log(path, *args, **kwargs):
        if path.name == 'progress.jsonl':
            raise OSError('synthetic log open failure')
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', open_log)
    monkeypatch.setattr(run_adapter_terminal.subprocess, 'Popen', lambda *a, **k: started.append(True))
    with pytest.raises(OSError):
        stream_process([sys.executable, '-c', 'pass'], tmp_path / 'logs')
    assert not started


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt])
def test_terminal_failure_or_interrupt_stops_real_child(tmp_path, monkeypatch, failure):
    children = []
    original_popen = subprocess.Popen
    original_print = builtins.print
    def launch(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        children.append(child)
        return child
    tripped = False
    def print_or_fail(*args, **kwargs):
        nonlocal tripped
        if args and str(args[0]).strip() == 'child-ready' and not tripped:
            tripped = True
            raise failure('synthetic terminal failure')
        return original_print(*args, **kwargs)
    monkeypatch.setattr(run_adapter_terminal.subprocess, 'Popen', launch)
    monkeypatch.setattr(builtins, 'print', print_or_fail)
    command = [sys.executable, '-u', '-c', "import time; print('child-ready', flush=True); time.sleep(30)"]
    directory = tmp_path / 'logs'
    try:
        if failure is KeyboardInterrupt:
            assert stream_process(command, directory, cwd=tmp_path) != 0
            assert json.loads((directory / 'execution.json').read_text())['interrupted'] is True
        else:
            with pytest.raises(OSError):
                stream_process(command, directory, cwd=tmp_path)
        assert tripped and len(children) == 1
        assert children[0].poll() is not None
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)


def test_cleanup_escalates_to_kill_after_bounded_terminate_wait(tmp_path, monkeypatch):
    class ResistantChild:
        stdout = io.StringIO('child-ready\n')
        stderr = io.StringIO('')
        returncode = None
        terminated = False
        killed = False
        waits = []
        def poll(self): return self.returncode
        def terminate(self): self.terminated = True
        def kill(self):
            self.killed = True
            self.returncode = -9
        def wait(self, timeout=None):
            self.waits.append(timeout)
            if not self.killed:
                raise subprocess.TimeoutExpired('synthetic-child', timeout)
            return self.returncode
    child = ResistantChild()
    monkeypatch.setattr(run_adapter_terminal.subprocess, 'Popen', lambda *a, **k: child)
    def failed_terminal(*args, **kwargs): raise OSError('terminal unavailable')
    monkeypatch.setattr(builtins, 'print', failed_terminal)
    with pytest.raises(OSError):
        stream_process(['synthetic-child'], tmp_path / 'logs')
    assert child.terminated and child.killed
    assert child.waits == [5, 5]


def test_preparation_guidance_quotes_actual_paths_and_repeated_reserve_cutoff(tmp_path):
    result = tmp_path / 'result.json'
    result.write_text(json.dumps({'status': 'prepared', 'generation': 123,
                                 'expires': 1790014327.940488}), encoding='utf-8')
    config = Path("C:/client's files/$env/config.json")
    guidance = run_adapter_terminal.preparation_guidance(
        result, config, 600, now=datetime(2026, 9, 21, 17, 59, tzinfo=timezone.utc))
    assert 'Prepared locally - no OneLake roles published by this operation.' in guidance
    assert 'Generation: 123' in guidance
    assert '2026-09-21T18:12:07.940488+00:00 UTC; local ' in guidance
    assert 'Publication cutoff: 2026-09-21T18:02:07.940488+00:00 UTC; local ' in guidance
    assert 'before each upload and policy update' in guidance
    assert 'not just publication start' in guidance
    assert "-Config '" + str(config).replace("'", "''") + "'" in guidance
    assert '-Generation 123' in guidance
    assert '-Operation DryRun' in guidance
    assert '-Operation BoundaryTemplate' in guidance
    assert 'UNVERIFIED template only; do not publish it unchanged' in guidance
    assert "-Boundary '<PATH_TO_FRESH_VERIFIED_BOUNDARY_JSON>'" in guidance
    assert 'real workspace/item access and SQL identity mode' in guidance
    assert run_adapter_terminal._powershell_literal("a'b $env:X `x") == "'a''b $env:X `x'"


@pytest.mark.parametrize('now', [
    datetime(2026, 9, 21, 18, 2, 7, 940488, tzinfo=timezone.utc),
    datetime(2026, 9, 21, 19, tzinfo=timezone.utc),
])
def test_preparation_guidance_never_recommends_stale_generation_publish(tmp_path, now):
    result = tmp_path / 'result.json'
    result.write_text(json.dumps({'status': 'prepared', 'generation': 123,
                                 'expires': 1790014327.940488}), encoding='utf-8')
    guidance = run_adapter_terminal.preparation_guidance(result, Path('stage10.json'), 600, now=now)
    assert 'Publication reserve is already exhausted' in guidance
    assert '-Operation Prepare' in guidance
    assert '-Operation Publish' not in guidance
    assert '-Operation DryRun' not in guidance


@pytest.mark.parametrize('raw', [
    '', 'banner\n{"status":"prepared"}', 'null', '[]',
    '{"status":"failed","generation":123,"expires":1790014327.940488}',
    '{"status":"prepared","expires":1790014327.940488}',
    '{"status":"prepared","generation":true,"expires":1790014327.940488}',
    '{"status":"prepared","generation":123,"expires":true}',
    '{"status":"prepared","generation":123,"expires":"1790014327"}',
    '{"status":"prepared","generation":123,"expires":NaN}',
    '{"status":"prepared","generation":123,"expires":1e200}',
])
def test_unusable_output_never_creates_preparation_success_guidance(tmp_path, raw):
    result = tmp_path / 'result.json'
    result.write_text(raw, encoding='utf-8')
    assert run_adapter_terminal.preparation_guidance(result, Path('config.json'), 600) is None


@pytest.mark.parametrize('operation,child_code,raw_kind,expect_guidance', [
    ('prepare', 0, 'prepared', True),
    ('prepare', 0, 'malformed', False),
    ('prepare', 7, 'prepared', False),
    ('status', 0, 'prepared', False),
])
def test_main_guidance_keeps_raw_result_exact_exit_and_only_one_child(
        tmp_path, monkeypatch, capsys, operation, child_code, raw_kind, expect_guidance):
    config = tmp_path / "client's config with spaces.json"
    config.write_text(json.dumps({
        'environment_url': 'https://test.crm.dynamics.com',
        'tenant_id': '11111111-1111-1111-1111-111111111111',
        'organization_id': '22222222-2222-2222-2222-222222222222',
        'workspace_id': '33333333-3333-3333-3333-333333333333',
        'tables': [{'name': 'account', 'columns': ['accountid']}],
    }), encoding='utf-8')
    raw = (json.dumps({'status': 'prepared', 'generation': 123, 'expires': time.time() + 2700},
                      indent=2) + '\n') if raw_kind == 'prepared' else 'unexpected non-JSON output\n'
    commands, children = [], []
    def controlled_command(python, config_path, child_operation, generation, boundary):
        commands.append((config_path, child_operation))
        return [python, '-u', '-c', 'import sys; sys.stdout.write(' + repr(raw)
                + '); sys.exit(' + str(child_code) + ')']
    real_popen = subprocess.Popen
    def counted_popen(*args, **kwargs):
        children.append(args[0])
        return real_popen(*args, **kwargs)
    monkeypatch.setattr(run_adapter_terminal, 'command_for', controlled_command)
    monkeypatch.setattr(run_adapter_terminal.subprocess, 'Popen', counted_popen)
    logs = tmp_path / 'terminal logs'
    code = run_adapter_terminal.main(['--config', str(config), '--operation', operation,
                                     '--log-directory', str(logs)])
    assert code == child_code
    assert commands == [(config.resolve(), operation)]
    assert len(children) == 1
    log = next(logs.iterdir())
    assert (log / 'result.json').read_text(encoding='utf-8') == raw
    assert json.loads((log / 'execution.json').read_text())['exit_code'] == child_code
    visible = capsys.readouterr().out
    marker = 'Prepared locally - no OneLake roles published by this operation.'
    assert (marker in visible) is expect_guidance
    assert (marker in (log / 'terminal.log').read_text(encoding='utf-8')) is expect_guidance


def test_optional_guidance_failure_preserves_successful_child_exit(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import policyweaver.config
    config = tmp_path / 'config.json'
    config.write_text('{}', encoding='utf-8')
    monkeypatch.setattr(policyweaver.config, 'load_config', lambda path: SimpleNamespace(
        tables=(), discover_readers=False, readers=(), serving_items={}, publication_budget_seconds=600))
    calls = []
    def completed_child(command, directory):
        calls.append(command)
        return 0
    def display_failure(*args, **kwargs):
        raise OSError('optional display unavailable')
    monkeypatch.setattr(run_adapter_terminal, 'stream_process', completed_child)
    monkeypatch.setattr(run_adapter_terminal, 'preparation_guidance', display_failure)
    assert run_adapter_terminal.main(['--config', str(config), '--log-directory', str(tmp_path / 'logs')]) == 0
    assert len(calls) == 1


def test_manual_guidance_separates_publication_deadline_from_role_retention(tmp_path):
    expires = 1790014327.940488
    result = tmp_path / 'result.json'
    result.write_text(json.dumps({'status': 'prepared', 'generation': 123, 'expires': expires,
        'summary': {'retention_mode': 'manual', 'publication_deadline_at': expires - 600,
                    'automatic_withdrawal_at': None}}), encoding='utf-8')
    guidance = run_adapter_terminal.preparation_guidance(result, Path('manual.json'), 600,
        now=datetime(2026, 9, 21, 17, 59, tzinfo=timezone.utc))
    assert 'Source freshness deadline:' in guidance
    assert 'Publication cutoff:' in guidance
    assert 'manual; no age-based automatic withdrawal after publication' in guidance
    assert 'Generation expiry:' not in guidance
    assert '-Operation Withdraw' in guidance and 'independently hosted watchdog' in guidance
    stale = run_adapter_terminal.preparation_guidance(result, Path('manual.json'), 600,
        now=datetime(2026, 9, 21, 19, tzinfo=timezone.utc))
    assert 'Publication reserve is already exhausted' in stale and '-Operation Publish' not in stale


@pytest.mark.parametrize('metadata', [
    {'retention_mode': 'manual'},
    {'retention_mode': 'manual', 'automatic_withdrawal_at': 1790014327.940488},
    {'retention_mode': 'unexpected'},
])
def test_manual_guidance_requires_explicit_consistent_retention_metadata(tmp_path, metadata):
    result = tmp_path / 'result.json'
    result.write_text(json.dumps({'status': 'prepared', 'generation': 123,
                                 'expires': 1790014327.940488, 'summary': metadata}), encoding='utf-8')
    assert run_adapter_terminal.preparation_guidance(result, Path('config.json'), 600) is None
