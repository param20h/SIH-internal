from email import message_from_bytes
from email.message import Message
from pathlib import Path

import pytest

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "data" / "samples"


def _sample_files() -> list[Path]:
    return sorted(SAMPLES_DIR.glob("*.eml"))


def test_sample_corpus_has_twenty_files() -> None:
    assert len(_sample_files()) == 20


@pytest.mark.parametrize("sample_path", _sample_files(), ids=lambda p: p.name)
def test_sample_parses_as_valid_email(sample_path: Path) -> None:
    raw = sample_path.read_bytes()
    message = message_from_bytes(raw)
    assert isinstance(message, Message)
    assert message.get("From") is not None
    assert message.get("Subject") is not None


@pytest.mark.parametrize("sample_path", _sample_files(), ids=lambda p: p.name)
def test_sample_has_at_least_one_received_header(sample_path: Path) -> None:
    raw = sample_path.read_bytes()
    message = message_from_bytes(raw)
    assert len(message.get_all("Received", [])) >= 1
