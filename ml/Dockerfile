FROM python:3.11-slim

WORKDIR /ml

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch>=2.4.0 \
    && pip install --no-cache-dir -e .

COPY scripts ./scripts

CMD ["python", "scripts/train_phishing_classifier.py"]
