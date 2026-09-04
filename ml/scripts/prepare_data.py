"""Download and prepare the phishing classifier training data.

Sources (both real, public, commonly used in phishing-detection research):
  - Phishing: Jose Nazario's phishing corpus, phishing0.mbox
    https://monkey.org/~jose/phishing/ (see LICENSE.txt there)
  - Ham: Apache SpamAssassin public corpus -- THREE separate batches
    (20030228_easy_ham, 20030228_easy_ham_2, 20030228_hard_ham), not just
    one. https://spamassassin.apache.org/old/publiccorpus/

Sampling ham from three distinct SpamAssassin batches instead of one is a
deliberate fix, not just more data for its own sake: a first pass trained
on a single ham batch scored 98%+ on its own held-out split but then
classified hand-written, stylistically ordinary business email as
"phishing" with >97% confidence -- the model had learned that batch's
narrow stylistic fingerprint (specific mailing-list headers, signature
conventions) rather than a real phishing-vs-legitimate distinction. See
ml/README.md for the full account and how much this did (or didn't) fix
it -- reported honestly either way.

Still downloads a bounded set of archives rather than the full multi-year
corpus, and subsamples to a few hundred examples per class -- enough for
a fine-tune that finishes in minutes on CPU, not the hours a full-corpus
fine-tune would take.
"""

import bz2
import email
import io
import mailbox
import random
import tarfile
import urllib.request
from email.message import Message
from pathlib import Path

import pandas as pd

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
RAW_DIR = DATA_DIR / "raw"
PREPARED_DIR = DATA_DIR / "prepared"

PHISHING_URL = "https://monkey.org/~jose/phishing/phishing0.mbox"
HAM_URLS = [
    "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2",
    "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
]

SAMPLES_PER_CLASS = 500
RANDOM_SEED = 42


def _download(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        print(f"already downloaded: {dest}")
        return dest
    print(f"downloading {url} -> {dest}")
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
        dest.write_bytes(response.read())
    return dest


def _extract_text(msg: Message) -> str:
    subject = str(msg.get("Subject", ""))
    body_parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_parts.append(payload.decode("utf-8", errors="replace"))
                except Exception:
                    continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                body_parts.append(payload.decode("utf-8", errors="replace"))
            elif isinstance(msg.get_payload(), str):
                body_parts.append(msg.get_payload())
        except Exception:
            pass
    body = " ".join(body_parts)
    return f"{subject}\n\n{body}".strip()


def _load_phishing(raw_path: Path) -> list[str]:
    box = mailbox.mbox(str(raw_path))
    texts = []
    for msg in box:
        text = _extract_text(msg)
        if len(text) > 20:
            texts.append(text)
    return texts


def _load_ham(raw_path: Path) -> list[str]:
    texts = []
    with tarfile.open(raw_path, "r:bz2") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            fileobj = tar.extractfile(member)
            if fileobj is None:
                continue
            raw = fileobj.read()
            try:
                msg = email.message_from_bytes(raw)
            except Exception:
                continue
            text = _extract_text(msg)
            if len(text) > 20:
                texts.append(text)
    return texts


def main() -> None:
    random.seed(RANDOM_SEED)

    phishing_raw = _download(PHISHING_URL, RAW_DIR / "phishing0.mbox")
    phishing_texts = _load_phishing(phishing_raw)
    random.shuffle(phishing_texts)

    # Sample evenly across the three ham batches rather than filling the
    # quota from whichever appears first, so no single batch's stylistic
    # quirks dominate the class.
    per_source_quota = SAMPLES_PER_CLASS // len(HAM_URLS) + 1
    ham_texts: list[str] = []
    for url in HAM_URLS:
        ham_raw = _download(url, RAW_DIR / url.rsplit("/", 1)[-1])
        source_texts = _load_ham(ham_raw)
        random.shuffle(source_texts)
        ham_texts.extend(source_texts[:per_source_quota])
        print(f"  {url.rsplit('/', 1)[-1]}: {len(source_texts)} messages, took {min(per_source_quota, len(source_texts))}")
    random.shuffle(ham_texts)

    print(f"loaded {len(phishing_texts)} phishing, {len(ham_texts)} ham raw messages")

    n = min(SAMPLES_PER_CLASS, len(phishing_texts), len(ham_texts))
    phishing_texts = phishing_texts[:n]
    ham_texts = ham_texts[:n]
    print(f"balanced to {n} examples per class ({2 * n} total)")

    rows = [{"text": t, "label": 1} for t in phishing_texts] + [
        {"text": t, "label": 0} for t in ham_texts
    ]
    random.shuffle(rows)
    df = pd.DataFrame(rows)

    n_total = len(df)
    n_train = int(n_total * 0.7)
    n_val = int(n_total * 0.15)
    train_df = df.iloc[:n_train]
    val_df = df.iloc[n_train : n_train + n_val]
    test_df = df.iloc[n_train + n_val :]

    PREPARED_DIR.mkdir(parents=True, exist_ok=True)
    train_df.to_csv(PREPARED_DIR / "train.csv", index=False)
    val_df.to_csv(PREPARED_DIR / "val.csv", index=False)
    test_df.to_csv(PREPARED_DIR / "test.csv", index=False)
    print(f"wrote train={len(train_df)} val={len(val_df)} test={len(test_df)} to {PREPARED_DIR}")


if __name__ == "__main__":
    main()
