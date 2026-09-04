import json
from pathlib import Path

import pytest

from app.forensics.cli import main

SAMPLE = (
    Path(__file__).resolve().parents[3] / "data" / "samples" / "03_spf_fail_spoofed_bank.eml"
)


def test_cli_human_readable_runs_cleanly(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([str(SAMPLE)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "TVA FORENSIC REPORT" in captured.out
    assert "SPF" in captured.out


def test_cli_json_output_is_valid_json(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["--json", str(SAMPLE)])
    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["filename"] == "03_spf_fail_spoofed_bank.eml"
    assert payload["authentication"]["spf"]["result"] == "fail"


def test_cli_missing_file_returns_error_code(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["/nonexistent/path/does-not-exist.eml"])
    assert exit_code == 1
