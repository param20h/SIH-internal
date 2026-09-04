# ml/

Model training and ONNX export pipelines land here in Phase 4:

- Phishing classifier (DistilBERT fine-tune on Nazario + Enron/SpamAssassin)
- Lookalike-domain confusables/distance scoring
- AI-generated-text detector for email bodies

Nothing here is loaded by the deterministic forensics engine in
`backend/app/forensics/` — that layer must remain 100% functional with this
directory empty.
