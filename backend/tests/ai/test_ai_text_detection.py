from pathlib import Path

from app.ai.ai_text_detection import AiTextDetector


def test_missing_model_degrades_gracefully() -> None:
    detector = AiTextDetector("/nonexistent/model/dir")
    assert detector.is_available is False
    result = detector.score("some email body text")
    assert result.source == "unavailable"
    assert result.perplexity is None
    assert result.detail is not None


def test_missing_model_never_raises_on_empty_text() -> None:
    detector = AiTextDetector("/nonexistent/model/dir")
    result = detector.score("")
    assert result.source == "unavailable"


def test_partial_model_dir_degrades_gracefully(tmp_path: Path) -> None:
    model_dir = tmp_path / "partial"
    model_dir.mkdir()
    (model_dir / "tokenizer.json").write_text("{}")
    detector = AiTextDetector(str(model_dir))
    assert detector.is_available is False
