"""Export DistilGPT-2 to ONNX for offline perplexity-based AI-generated-text
scoring.

Perplexity only needs the per-token logits from a single teacher-forced
forward pass over the input (comparing the model's predicted next-token
distribution at each position against the actual next token) -- not
autoregressive generation. That makes this a plain feed-forward ONNX
export, no KV-cache/generation-loop handling required, and lets the
backend score perplexity via onnxruntime alone, consistent with the
phishing classifier: no PyTorch/transformers needed at inference time.

Honesty note (also in ml/README.md and surfaced in the API): perplexity-
based AI-text detection is a genuinely weak, noisy signal in practice --
this is why it is scored as a low-weight, informational factor, never a
strong driver of the verdict, and its output is framed as "worth a
second look" rather than a confident classification.
"""

import os
from pathlib import Path

import torch
from transformers import GPT2LMHeadModel, GPT2TokenizerFast

MODEL_NAME = "distilgpt2"
MAX_LENGTH = 256
OUTPUT_DIR = Path(os.environ.get("TVA_MODEL_OUTPUT_DIR", "/data/models/ai_text_detector"))


class _LogitsOnly(torch.nn.Module):
    """Binds input_ids/attention_mask by keyword and returns only the logits
    tensor. GPT2LMHeadModel.forward's positional argument order has shifted
    across transformers versions (past_key_values now precedes
    attention_mask), so passing a plain positional tuple to
    torch.onnx.export silently misaligns arguments -- this wrapper makes
    the binding explicit and version-proof."""

    def __init__(self, model: GPT2LMHeadModel) -> None:
        super().__init__()
        self.model = model

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        return self.model(input_ids=input_ids, attention_mask=attention_mask).logits


def main() -> None:
    tokenizer = GPT2TokenizerFast.from_pretrained(MODEL_NAME)
    tokenizer.pad_token = tokenizer.eos_token
    model = GPT2LMHeadModel.from_pretrained(MODEL_NAME)
    model.eval()
    export_model = _LogitsOnly(model)
    export_model.eval()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    tokenizer.save_pretrained(OUTPUT_DIR)

    dummy = tokenizer("dummy input for tracing the export graph", return_tensors="pt")
    torch.onnx.export(
        export_model,
        (dummy["input_ids"], dummy["attention_mask"]),
        OUTPUT_DIR / "model.onnx",
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "sequence"},
            "attention_mask": {0: "batch", 1: "sequence"},
            "logits": {0: "batch", 1: "sequence"},
        },
        opset_version=14,
        dynamo=False,  # the new dynamo-based exporter needs onnxscript, not installed
    )
    print(f"exported ONNX model to {OUTPUT_DIR / 'model.onnx'}")


if __name__ == "__main__":
    main()
