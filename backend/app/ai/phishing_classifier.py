"""ONNX Runtime inference for the fine-tuned DistilBERT phishing classifier.

Gracefully degrades to "unavailable" when the exported model isn't
present -- the hard constraint that the deterministic layer works with
zero trained models present extends to every additive Phase 4 signal too.
See ml/README.md for how to train and export the model this loads. Uses
onnxruntime + tokenizers only (not torch/transformers) to keep the API
image lean, matching the ONNX-for-inference architecture decision.
"""

from pathlib import Path
from typing import Literal

import numpy as np
import onnxruntime as ort
from pydantic import BaseModel
from tokenizers import Tokenizer

MAX_LENGTH = 96


class PhishingClassification(BaseModel):
    source: Literal["onnx-model", "unavailable"]
    phishing_probability: float | None = None
    label: Literal["phishing", "ham"] | None = None
    detail: str | None = None


class PhishingClassifier:
    def __init__(self, model_dir: str) -> None:
        self._session: ort.InferenceSession | None = None
        self._tokenizer: Tokenizer | None = None

        model_path = Path(model_dir) / "model.onnx"
        tokenizer_path = Path(model_dir) / "tokenizer.json"
        if not model_path.exists() or not tokenizer_path.exists():
            return

        try:
            tokenizer = Tokenizer.from_file(str(tokenizer_path))
            pad_id = tokenizer.token_to_id("[PAD]") or 0
            tokenizer.enable_padding(pad_id=pad_id, pad_token="[PAD]", length=MAX_LENGTH)
            tokenizer.enable_truncation(max_length=MAX_LENGTH)
            self._session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
            self._tokenizer = tokenizer
        except Exception:
            self._session = None
            self._tokenizer = None

    @property
    def is_available(self) -> bool:
        return self._session is not None and self._tokenizer is not None

    def classify(self, text: str) -> PhishingClassification:
        if self._session is None or self._tokenizer is None:
            return PhishingClassification(
                source="unavailable",
                detail="phishing classifier model not present -- run ml/scripts/train_phishing_classifier.py",
            )
        try:
            encoding = self._tokenizer.encode(text)
            input_ids = np.array([encoding.ids], dtype=np.int64)
            attention_mask = np.array([encoding.attention_mask], dtype=np.int64)
            (logits,) = self._session.run(
                ["logits"], {"input_ids": input_ids, "attention_mask": attention_mask}
            )
            probs = _softmax(logits[0])
            phishing_probability = float(probs[1])
            label: Literal["phishing", "ham"] = "phishing" if phishing_probability >= 0.5 else "ham"
            return PhishingClassification(
                source="onnx-model", phishing_probability=phishing_probability, label=label
            )
        except Exception as exc:
            return PhishingClassification(source="unavailable", detail=f"inference failed: {exc!r}")


def _softmax(logits: np.ndarray) -> np.ndarray:
    shifted = logits - np.max(logits)
    exp = np.exp(shifted)
    result: np.ndarray = exp / exp.sum()
    return result
