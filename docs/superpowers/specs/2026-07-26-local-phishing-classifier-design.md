# Local Bilingual Phishing Classifier Design

## Goal

Add a reproducible English–Vietnamese phishing-email training pipeline and a
local `jhu-clsp/mmBERT-small` runtime classifier. The local classifier handles
confident cases; the existing Groq classifier handles uncertain cases or acts
as a fallback when the local artifact is unavailable.

## Non-goals

- The text classifier does not replace header, URL, attachment, threat-intel,
  or rule-based analysis.
- Public or synthetic Vietnamese evaluation does not establish production
  quality for real Vietnamese corporate email.
- Model weights and downloaded datasets are not committed to Git.
- The implementation does not assign an additional risk category to the local
  model. Local and Groq outputs remain one `ai_verdict`.

## Decisions

- Backbone: `jhu-clsp/mmBERT-small` (MIT, 140M parameters, multilingual,
  8,192-token pretraining context).
- Learned task: binary `legitimate` versus `phishing`.
- User-facing verdicts: two calibrated thresholds map probability to
  `legitimate`, `suspicious`, or `phishing`.
- Training length: 512 tokens by default so full fine-tuning can run on the
  available RTX 3050 Laptop GPU with 4 GB VRAM.
- Runtime length: up to 1,024 tokens. The formatter preserves the subject,
  sender, URL hosts, and balanced body head/tail when truncation is required.
- Runtime policy: local first, Groq only for the uncertain interval. In offline
  mode, local inference remains available and Groq is never called.

## Sources and Provenance

Default sources:

1. `difraud/difraud`, phishing subset, MIT license. Its official
   train/validation/test splits remain authoritative.
2. `Teddyha/phishing_benign_email_dataset`, MIT license. Its 200 curated
   records are training-only supplemental data.

Every normalized record contains:

```text
id, source, source_split, source_id, language, subject, sender, body,
label, content_sha256, group_id, synthetic
```

`group_id` ties an original record to translations or paraphrases. Group
membership cannot cross a split. Exact duplicates are removed using a
normalized-content SHA-256. Raw data stays under `data/raw/`; normalized JSONL
stays under `data/processed/`. Both directories are ignored by Git.

A dataset manifest records source revisions, licenses, record counts, label and
language distributions, rejected-record counts, generation settings, and file
checksums. The pipeline does not redistribute upstream raw datasets.

## Vietnamese Data

There is no sufficiently large, clearly licensed public Vietnamese phishing
email corpus suitable as the sole training source. The pipeline therefore uses
Groq to translate and culturally adapt a bounded portion of the English
training data.

Augmentation rules:

- Only records already assigned to the training split are augmented for
  training.
- Requests are batched and responses must pass a strict JSON schema.
- The phishing/legitimate label, URLs, domains, currency amounts, attachment
  names, and security intent must remain unchanged unless a field is explicitly
  localized.
- Generated records keep the original `group_id`.
- A content-addressed cache permits resume without paying for repeated calls.
- Rate, batch count, input records, prompt version, model, and failures are
  recorded without storing the API key.
- A separate Vietnamese synthetic evaluation set may be translated from the
  English test split. It remains test-only and is reported as a synthetic
  sanity check, not a production-quality estimate.

## Components

### Data and training package

`ml/` contains:

- `contracts.py`: record, manifest, metrics, thresholds, and artifact schemas.
- `text.py`: normalization, hashing, language-aware text formatting, and
  balanced truncation.
- `prepare_data.py`: source download, validation, deduplication, split
  preservation, and manifest creation.
- `augment_vietnamese.py`: Groq batching, schema validation, cache, retries,
  request cap, and resume.
- `train_baseline.py`: word/character TF-IDF plus calibrated logistic
  regression.
- `train_mmbert.py`: tokenizer/model setup, weighted binary loss, FP16,
  gradient accumulation, checkpoint resume, early stopping, and deterministic
  seeding.
- `evaluate.py`: per-language and combined metrics, confusion matrices, and
  prediction exports.
- `calibrate.py`: threshold selection on validation predictions.
- `promote.py`: quality-gate enforcement and atomic publication of the runtime
  artifact.

All commands provide `--help`, deterministic seed options, explicit input and
output paths, and a small `--smoke` mode.

### Runtime package

`email_analysis/local_ai_classifier.py` owns:

- optional dependency discovery;
- artifact manifest validation;
- lazy, process-local model loading;
- a load lock and an inference lock to avoid duplicate GPU loads and 4 GB VRAM
  contention;
- text formatting shared with training;
- probability inference and threshold mapping;
- stable error results when disabled, missing, or unavailable.

`email_analysis/ai_classifier.py` becomes the orchestrator while preserving:

```python
classify_email(
    email_data: dict,
    urls: list[dict] | None = None,
    rule_findings: list[str] | None = None,
) -> dict
```

The returned dictionary keeps the existing fields and adds non-breaking
metadata:

```text
provider, model, phishing_probability, fallback_used
```

The orchestration policy is:

1. If local AI is enabled and available, classify locally.
2. If the local verdict is `legitimate` or `phishing`, return it.
3. If it is `suspicious` and Groq fallback is enabled and online, call Groq.
4. If Groq succeeds, return its verdict with `fallback_used=true`.
5. If Groq fails, return the local suspicious verdict plus the fallback error.
6. If local AI is unavailable, retain the current Groq behavior.
7. If offline and local AI is unavailable, return `unknown` without a network
   attempt.

## Configuration

New environment settings:

```text
LOCAL_AI_ENABLED=true
LOCAL_AI_MODEL_DIR=artifacts/models/phishing-mmbert
LOCAL_AI_MAX_LENGTH=1024
AI_GROQ_FALLBACK=true
```

Low/high thresholds come from the promoted artifact and are not silently
overridden by environment variables. This ensures evaluation and runtime use
the same decision policy.

ML dependencies are optional:

- `requirements-ml-runtime.txt`: PyTorch, Transformers, Safetensors.
- `requirements-ml.txt`: runtime requirements plus Datasets, Accelerate,
  scikit-learn, and training/evaluation utilities.

Core CI and rule-only/Groq deployments do not install ML dependencies.

## Evaluation and Promotion

Metrics are reported for English, synthetic Vietnamese, and combined data:

- phishing precision, recall, and F1;
- macro F1;
- PR-AUC and ROC-AUC;
- false-positive rate;
- confusion matrix;
- latency and peak memory where available;
- calibration quality.

Threshold calibration maximizes phishing recall subject to a configurable
false-positive-rate ceiling. Default promotion gates are:

```text
English phishing recall >= 0.90
English false-positive rate <= 0.05
English macro F1 >= TF-IDF baseline macro F1
Synthetic Vietnamese phishing recall >= 0.85
```

If gates fail, metrics and checkpoints remain available for diagnosis, but
`promote.py` does not replace the active runtime artifact. Production rollout
therefore cannot happen solely because training completed.

The artifact directory contains:

```text
model weights, tokenizer, config, thresholds.json, metrics.json,
dataset-manifest.json, artifact-manifest.json
```

Publication uses a temporary directory, validates required files and
checksums, then atomically replaces the target directory.

## Error Handling and Security

- Network downloads and Groq augmentation use bounded timeouts, retries with
  backoff, and actionable errors.
- Malformed dataset rows and augmentation responses are quarantined with
  reasons rather than silently accepted.
- No API key, authorization header, or raw secret is logged or written to an
  artifact.
- Model loading never performs arbitrary-code execution; remote custom code is
  disabled.
- Runtime inference uses evaluation/inference mode and clamps probabilities to
  `[0, 1]`.
- The classifier does not make external requests in offline mode.
- Missing optional ML dependencies do not prevent the rest of the phishing
  pipeline from starting.

## Testing

Unit tests, without model downloads:

- normalization, hashing, deduplication, split/group isolation;
- balanced text truncation;
- augmentation cache and strict-response parsing;
- threshold mapping and boundary values;
- artifact manifest/checksum validation;
- local/Groq routing for confident, uncertain, offline, disabled, and failure
  states;
- backward compatibility of the existing classifier result schema.

Smoke tests:

- a tiny fixture dataset runs through preparation and TF-IDF training;
- a fake tokenizer/model exercises local inference;
- optional marked tests load a real promoted artifact when present.

Full verification continues to include Ruff, Black, mypy, pytest with warnings
as errors, Bandit, pip-audit, pip check, compileall, and the application
healthcheck.

## Rollout

1. Land the optional pipeline and runtime with local AI enabled but effective
   only when a valid artifact exists; otherwise it safely falls back to Groq.
2. Run smoke preparation, augmentation parsing, baseline, and model setup.
3. Run bounded Vietnamese augmentation.
4. Train and evaluate the full model.
5. Promote only if quality gates pass.
6. Enable local AI and monitor local verdict distribution, fallback rate,
   latency, and false positives.
7. Add real labeled Vietnamese corporate email over time and retrain with a
   time-based holdout.
