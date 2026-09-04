"""Perplexity-based AI-generated-text scoring for the email body.

Computes perplexity via a single teacher-forced forward pass through a
DistilGPT-2 ONNX export: at each position, compare the model's predicted
next-token distribution against the actual next token. Lower perplexity
means the text was more "predictable" to the model, which correlates
(weakly and noisily) with machine-generated text.

Honesty note, surfaced in the API response and weighted accordingly in
scoring: this is a genuinely unreliable signal. Perplexity-based AI-text
detection has well-documented high false-positive and false-negative
rates in the wider literature -- formal, simple, or non-native-English
writing can score as "low perplexity" despite being entirely human, and
sophisticated LLM output can score as "high perplexity." This module
reports a raw score and a soft, low-confidence flag, never a confident
classification, and contributes only a small weight to the fused risk
score for exactly that reason.
"""

from pathlib import Path
from typing import Literal

import numpy as np
import onnxruntime as ort
from pydantic import BaseModel
from tokenizers import Tokenizer

MAX_LENGTH = 256
MIN_TOKENS_FOR_SCORING = 8
# Below this, text reads as unusually "predictable" to the reference
# model -- worth a second look, not a verdict. Uncalibrated against a
# labeled corpus; see the module docstring.
LOW_PERPLEXITY_THRESHOLD = 35.0


class AiTextScore(BaseModel):
    source: Literal["onnx-model", "unavailable", "text-too-short"]
    perplexity: float | None = None
    low_perplexity_flag: bool = False
    detail: str | None = None


class AiTextDetector:
    def __init__(self, model_dir: str) -> None:
        self._session: ort.InferenceSession | None = None
        self._tokenizer: Tokenizer | None = None

        model_path = Path(model_dir) / "model.onnx"
        tokenizer_path = Path(model_dir) / "tokenizer.json"
        if not model_path.exists() or not tokenizer_path.exists():
            return

        try:
            tokenizer = Tokenizer.from_file(str(tokenizer_path))
            tokenizer.enable_truncation(max_length=MAX_LENGTH)
            self._session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
            self._tokenizer = tokenizer
        except Exception:
            self._session = None
            self._tokenizer = None

    @property
    def is_available(self) -> bool:
        return self._session is not None and self._tokenizer is not None

    def score(self, text: str) -> AiTextScore:
        if self._session is None or self._tokenizer is None:
            return AiTextScore(
                source="unavailable",
                detail="AI-text model not present -- run ml/scripts/export_ai_text_model.py",
            )

        try:
            encoding = self._tokenizer.encode(text)
            ids = encoding.ids
            if len(ids) < MIN_TOKENS_FOR_SCORING:
                return AiTextScore(source="text-too-short")

            input_ids = np.array([ids], dtype=np.int64)
            attention_mask = np.ones_like(input_ids)
            (logits,) = self._session.run(
                ["logits"], {"input_ids": input_ids, "attention_mask": attention_mask}
            )
            perplexity = _teacher_forced_perplexity(logits[0], ids)
            flag = perplexity < LOW_PERPLEXITY_THRESHOLD
            return AiTextScore(source="onnx-model", perplexity=perplexity, low_perplexity_flag=flag)
        except Exception as exc:
            return AiTextScore(source="unavailable", detail=f"inference failed: {exc!r}")


def _teacher_forced_perplexity(logits: np.ndarray, token_ids: list[int]) -> float:
    """logits: [seq_len, vocab_size] predictions at each position.
    Predicts token[i+1] from logits[i] for every adjacent pair."""
    predicted_logits = logits[:-1, :]
    actual_next_tokens = token_ids[1:]

    shifted = predicted_logits - predicted_logits.max(axis=-1, keepdims=True)
    log_probs = shifted - np.log(np.exp(shifted).sum(axis=-1, keepdims=True))

    token_log_probs = log_probs[np.arange(len(actual_next_tokens)), actual_next_tokens]
    mean_nll = -float(token_log_probs.mean())
    return float(np.exp(mean_nll))
