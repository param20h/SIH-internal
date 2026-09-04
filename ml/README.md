# ml/ — TVA's training pipeline

Trains and exports the two ONNX models Phase 4's AI layer uses for
inference (`backend/app/ai/phishing_classifier.py` and
`ai_text_detection.py`). This directory is **not** imported by the running
backend — the backend talks to `onnxruntime` + `tokenizers` only, so the
API/worker images stay free of PyTorch and `transformers`. Training happens
here, once, and the resulting model files are dropped into `data/models/`
(a volume shared with the backend containers).

Nothing in this directory is required for the deterministic layer
(Phases 1–3) to work. Per the project's hard constraints, the app runs
correctly with zero trained models present — the AI signals just report
`"unavailable"` and contribute nothing to the score until you run this.

## Quickstart

```bash
docker compose build ml
docker compose run --rm ml python scripts/prepare_data.py
docker compose run --rm ml python scripts/train_phishing_classifier.py
docker compose run --rm ml python scripts/export_ai_text_model.py
```

Models land in `data/models/phishing_classifier/` and
`data/models/ai_text_detector/`, which the `api`/`worker` containers
already mount. No restart needed — the backend loads them lazily on first
use (see `app/ai/pipeline.py`'s cached singletons).

## Phishing classifier: DistilBERT fine-tune

**Data**, both real public corpora used in phishing-detection research,
not synthetic:
- Phishing: [Jose Nazario's phishing corpus](https://monkey.org/~jose/phishing/),
  `phishing0.mbox` (~394 usable messages).
- Ham: [Apache SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/),
  sampled evenly across **three** separate batches — `20030228_easy_ham`,
  `20030228_easy_ham_2`, `20030228_hard_ham` — not just one. See "a real
  bug, found by testing" below for why that matters.

`prepare_data.py` downloads these, extracts subject+body text, and
subsamples to a class-balanced ~394/394 split (788 total, 70/15/15
train/val/test) — enough for a real, honestly-evaluated fine-tune that
finishes in minutes on CPU, not the hours a full multi-year-corpus
fine-tune would take.

**Training**: `distilbert-base-uncased`, 2 epochs, batch size 8, max
sequence length 96 tokens, via HuggingFace `Trainer`. Exported to ONNX
(opset 14) through an explicit keyword-argument wrapper (see "a second
real bug" below).

**Held-out test set metrics** (119 examples the model never saw during
training or validation, from `metrics.json` after the current model was
trained):

| Metric | Value |
|---|---|
| Accuracy | 98.3% |
| Precision | 100% |
| Recall | 96.7% |
| F1 | 98.3% |

These are real numbers from an actual run, not aspirational targets — and
they come with a specific, tested caveat below, not just a generic
disclaimer.

### A real bug, found by testing generalization, not just the held-out split

The first trained model scored 98%+ on its own held-out test set (drawn
from the same single ham batch, `20030228_easy_ham`, as training) — and
then classified this hand-written sentence as **99.8% phishing**:

> "Hi team, just a reminder that the quarterly report is due Friday. Let
> me know if you have any questions about the budget numbers."

Running it against TVA's own 20-sample corpus (`data/samples/`) confirmed
it wasn't a fluke: it flagged 18 of 20 samples as phishing at >97%
confidence, **including both samples deliberately built to be clean**
(`01_clean_newsletter.eml`, `02_clean_internal_memo.eml`). Wired into the
live scoring pipeline, this broke a Phase 1-3 test that expected a clean
sample to score 0 — the classifier alone added 25 points to an otherwise
spotless message.

The root cause: 394 ham examples from one narrow, dated source (2003
mailing-list mail, with its own consistent headers, signature
conventions, and vocabulary) is not enough diversity for the model to
learn "phishing vs. legitimate email" — it learned "this specific
batch's style vs. everything else," including ordinary modern business
writing.

**Fix**: sample ham from three separate SpamAssassin batches instead of
one (see `prepare_data.py`). Retrained under identical settings:

- Held-out test metrics barely moved (98.3% accuracy, this time 100%
  precision / 96.7% recall) — the held-out split alone would never have
  shown this was a problem, which is exactly the point.
- The same hand-written sentence above now scores **7.3% phishing**
  (correctly "ham").
- Against the 20-sample corpus: 18/20 now match the corpus's intended
  ground truth by content alone. The two "misses"
  (`14_forged_received_header_private_ip_public_path.eml`,
  `19_expired_dkim_signature.eml`) are messages whose malicious signal is
  entirely in the headers and relay chain, not the body text — a pure
  text classifier correctly has nothing distinctive to say about them,
  and TVA's deterministic layer (bogon-IP and expired-DKIM anomalies)
  independently flags both anyway. That's defense in depth working as
  designed, not a classifier failure.

Three ham batches is a mitigation, not a proof of full generalization —
see "Known limitations" below.

### A second real bug: silent argument misalignment in ONNX export

`torch.onnx.export(model, (input_ids, attention_mask), ...)` — passing
inputs as a plain positional tuple — silently produced a broken export
for `GPT2LMHeadModel`: the installed `transformers` version's
`forward()` now takes `past_key_values` as its second positional
argument (before `attention_mask`), so the tuple bound to the wrong
parameters and the traced graph computed something other than intended,
failing at export time with an `AttributeError` deep in cache-handling
code (`'Tensor' object has no attribute 'get_seq_length'`).

Positional argument order for a HuggingFace model's `forward()` is not a
stable contract across `transformers` versions. Both export scripts now
wrap the model in a small `torch.nn.Module` that binds `input_ids`/
`attention_mask` explicitly by keyword and returns only the logits
tensor — version-proof, and it also produces a cleaner export (`logits`
as the sole output rather than a full `ModelOutput` structure).

## AI-generated-text detector: DistilGPT-2 perplexity

`export_ai_text_model.py` exports `distilgpt2` to ONNX. No fine-tuning —
perplexity only needs the base model's next-token predictions from a
single teacher-forced forward pass (compare the predicted distribution at
each position against the actual next token), not autoregressive
generation, so there's nothing to train here.

**This is a deliberately weak signal, by design, not by accident.**
Perplexity-based AI-text detection has well-documented high false-positive
and false-negative rates in the wider literature: formal, terse, or
non-native-English writing can score as "low perplexity" despite being
entirely human, and fluent LLM output can score as "high perplexity."
`ai_text_detection.py` reports a raw perplexity value and a soft,
low-confidence flag — never a classification — and it carries the smallest
weight of any signal in `app/scoring/weights.yaml` for exactly this
reason. Treat it as "maybe worth a second look," never as evidence on its
own.

## Known limitations (honest, not hedged)

- **Era and topic narrowness.** Both the ham and phishing sources are
  early-2000s to mid-2010s email. Even after the three-batch fix, this is
  not validated against contemporary phishing kits, modern brand
  impersonation templates, or non-English phishing.
- **Small corpus.** ~394 examples per class is enough for a fast,
  honestly-evaluated CPU demo fine-tune, not a production-grade model.
  Precision/recall here describe performance on held-out data from the
  same sources, not a guarantee of real-world generalization — see the
  bug account above for a concrete instance of exactly that gap.
- **English-only**, effectively, given the source corpora.
- To retrain on something larger and more current: point
  `PHISHING_URL`/`HAM_URLS` in `prepare_data.py` at a bigger, more recent,
  more topically diverse corpus, raise `SAMPLES_PER_CLASS`, and budget
  proportionally more CPU training time (roughly linear in example count
  × epochs). Re-validate against out-of-distribution examples the way
  this file describes, not just a held-out split of the same sources --
  that's the check that actually would have caught the original bug.
