from pathlib import Path

from app.ai.phishing_classifier import PhishingClassifier


def test_missing_model_degrades_gracefully() -> None:
    classifier = PhishingClassifier("/nonexistent/model/dir")
    assert classifier.is_available is False
    result = classifier.classify("some email text")
    assert result.source == "unavailable"
    assert result.phishing_probability is None
    assert result.detail is not None


def test_missing_model_never_raises_on_empty_text() -> None:
    classifier = PhishingClassifier("/nonexistent/model/dir")
    result = classifier.classify("")
    assert result.source == "unavailable"


def test_partial_model_dir_degrades_gracefully(tmp_path: Path) -> None:
    # A directory that exists but is missing tokenizer.json or model.onnx
    # must not raise during construction.
    model_dir = tmp_path / "partial"
    model_dir.mkdir()
    (model_dir / "model.onnx").write_bytes(b"not a real onnx file")
    classifier = PhishingClassifier(str(model_dir))
    assert classifier.is_available is False
