"""Fine-tune DistilBERT for phishing/ham binary classification and export
to ONNX for lightweight inference in the backend.

Run ml/scripts/prepare_data.py first. Honestly reports precision/recall/F1
on a held-out test set the model never saw during training -- these numbers
are written to metrics.json alongside the exported model and are not
retouched; see ml/README.md for the as-trained results and their caveats.
"""

import json
import os
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from torch.utils.data import Dataset
from transformers import (
    DistilBertForSequenceClassification,
    DistilBertTokenizerFast,
    Trainer,
    TrainingArguments,
)

DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "prepared"
BASE_MODEL = "distilbert-base-uncased"
MAX_LENGTH = 96
OUTPUT_DIR = Path(os.environ.get("TVA_MODEL_OUTPUT_DIR", "/data/models/phishing_classifier"))


class _LogitsOnly(torch.nn.Module):
    """Binds input_ids/attention_mask by keyword and returns only the
    logits tensor for ONNX export -- a HF model's forward() positional
    argument order isn't a stable contract across transformers versions,
    so passing a plain positional tuple to torch.onnx.export risks
    silently misaligned arguments. Explicit keyword binding is version-proof."""

    def __init__(self, model: DistilBertForSequenceClassification) -> None:
        super().__init__()
        self.model = model

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        return self.model(input_ids=input_ids, attention_mask=attention_mask).logits


class TextDataset(Dataset):
    def __init__(self, texts: list[str], labels: list[int], tokenizer: DistilBertTokenizerFast):
        self.encodings = tokenizer(
            texts, truncation=True, padding="max_length", max_length=MAX_LENGTH
        )
        self.labels = labels

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        item = {k: torch.tensor(v[idx]) for k, v in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx])
        return item


def compute_metrics(eval_pred: tuple[np.ndarray, np.ndarray]) -> dict[str, float]:
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average="binary", zero_division=0
    )
    accuracy = accuracy_score(labels, predictions)
    return {"accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1}


def main() -> None:
    train_df = pd.read_csv(DATA_DIR / "train.csv")
    val_df = pd.read_csv(DATA_DIR / "val.csv")
    test_df = pd.read_csv(DATA_DIR / "test.csv")
    print(f"train={len(train_df)} val={len(val_df)} test={len(test_df)}")

    tokenizer = DistilBertTokenizerFast.from_pretrained(BASE_MODEL)
    model = DistilBertForSequenceClassification.from_pretrained(BASE_MODEL, num_labels=2)

    train_dataset = TextDataset(train_df["text"].tolist(), train_df["label"].tolist(), tokenizer)
    val_dataset = TextDataset(val_df["text"].tolist(), val_df["label"].tolist(), tokenizer)
    test_dataset = TextDataset(test_df["text"].tolist(), test_df["label"].tolist(), tokenizer)

    training_args = TrainingArguments(
        output_dir="/tmp/tva-training-checkpoints",
        num_train_epochs=2,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=16,
        eval_strategy="epoch",
        save_strategy="no",
        logging_steps=20,
        use_cpu=True,
        report_to=[],
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
    )

    trainer.train()

    test_metrics = trainer.evaluate(test_dataset)
    print("Held-out test set metrics:", test_metrics)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    tokenizer.save_pretrained(OUTPUT_DIR)

    model.eval()
    export_model = _LogitsOnly(model)
    export_model.eval()
    dummy_input = tokenizer("dummy input for tracing", return_tensors="pt", padding="max_length", max_length=MAX_LENGTH)
    torch.onnx.export(
        export_model,
        (dummy_input["input_ids"], dummy_input["attention_mask"]),
        OUTPUT_DIR / "model.onnx",
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch"},
            "attention_mask": {0: "batch"},
            "logits": {0: "batch"},
        },
        opset_version=14,
        dynamo=False,  # the new dynamo-based exporter needs onnxscript, not installed
    )
    print(f"exported ONNX model to {OUTPUT_DIR / 'model.onnx'}")

    metrics_report = {
        "base_model": BASE_MODEL,
        "max_length": MAX_LENGTH,
        "train_examples": len(train_df),
        "val_examples": len(val_df),
        "test_examples": len(test_df),
        "test_metrics": {k: float(v) for k, v in test_metrics.items()},
        "data_sources": {
            "phishing": "Nazario phishing corpus, phishing0.mbox (https://monkey.org/~jose/phishing/)",
            "ham": (
                "Apache SpamAssassin public corpus, three batches: 20030228_easy_ham, "
                "20030228_easy_ham_2, 20030228_hard_ham (sampled evenly across all three)"
            ),
        },
        "caveats": (
            "Trained on a small, class-balanced subsample (see prepare_data.py) for fast "
            "CPU fine-tuning, not the full multi-year corpus. Both sources are early-2000s "
            "mail, older and stylistically narrower than the full range of modern email. "
            "IMPORTANT, found by testing this model against text outside its training "
            "distribution (not just its own held-out split): an earlier version trained on "
            "a single ham batch scored 98%+ here but classified ordinary, hand-written "
            "modern business email as phishing with >97% confidence -- it had learned that "
            "batch's narrow stylistic fingerprint, not a real phishing-vs-legitimate "
            "distinction. Sampling ham from three separate SpamAssassin batches (this "
            "version) is a mitigation, not a fix -- see ml/README.md for whether it closed "
            "the gap, tested the same way. These test_metrics describe performance on a "
            "held-out split of similar-distribution data, never real-world generalization. "
            "Retrain on a larger, more recent, more topically diverse corpus (and validate "
            "against out-of-distribution examples, not just a held-out split of the same "
            "sources) before relying on this for production decisions."
        ),
    }
    (OUTPUT_DIR / "metrics.json").write_text(json.dumps(metrics_report, indent=2))
    print(f"wrote metrics to {OUTPUT_DIR / 'metrics.json'}")


if __name__ == "__main__":
    main()
