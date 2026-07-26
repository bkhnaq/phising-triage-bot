# Local Bilingual Phishing Classifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reproducible English–Vietnamese phishing-email ML pipeline and a safe local `jhu-clsp/mmBERT-small` runtime classifier with Groq fallback for uncertain or unavailable local predictions.

**Architecture:** Pure-Python contracts and text preparation form the shared boundary between training and runtime. Optional ML dependencies are isolated behind lazy imports, while `email_analysis.ai_classifier` keeps the current public API and chooses one final AI verdict from local inference or Groq. The offline training package prepares provenance-tracked data, creates Vietnamese augmentation, trains a baseline and mmBERT, calibrates thresholds, evaluates metrics, and atomically promotes only artifacts that pass quality gates.

**Tech Stack:** Python 3.13, dataclasses, JSON/JSONL, requests, pytest, scikit-learn, Hugging Face Datasets/Transformers/Accelerate, PyTorch, Safetensors, `jhu-clsp/mmBERT-small`.

## Global Constraints

- The learned labels are exactly `legitimate` and `phishing`; runtime output may also be `suspicious`.
- Training maximum length defaults to 512 tokens; runtime maximum length defaults to 1,024 tokens.
- Runtime returns one `ai_verdict`; local and Groq results are never scored as two separate signals.
- Official `difraud/difraud` splits stay authoritative; `Teddyha/phishing_benign_email_dataset` is training-only.
- Original records and synthetic variants share `group_id` and may never cross splits.
- Raw data, processed data, checkpoints, and promoted weights are not committed to Git.
- Groq augmentation is bounded, cached, resumable, schema-validated, and never records the API key.
- Hugging Face model loading always uses `trust_remote_code=False`.
- Missing local ML dependencies or artifacts cannot prevent the core application from starting.
- Offline mode never performs Groq requests.
- Promotion defaults are English phishing recall `>= 0.90`, English false-positive rate `<= 0.05`, English macro F1 `>=` TF-IDF baseline macro F1, and synthetic Vietnamese phishing recall `>= 0.85`.
- Existing uncommitted repository-audit changes are preserved and are not staged as part of local-AI commits unless the same file is required by this feature.

---

## File Structure

- `ml/contracts.py`: normalized record, threshold, metrics, dataset-manifest, and artifact-manifest validation.
- `ml/text.py`: text normalization, stable hashing, URL-host extraction, runtime/training formatting, and balanced truncation.
- `ml/prepare_data.py`: dataset adapters, row quarantine, exact deduplication, split/group isolation, JSONL output, and provenance manifest.
- `ml/augment_vietnamese.py`: bounded Groq batch generation, strict response parsing, content-addressed cache, retry, and augmentation manifest.
- `ml/train_baseline.py`: word/character TF-IDF logistic-regression baseline and prediction export.
- `ml/train_mmbert.py`: deterministic mmBERT fine-tuning, weighted loss, mixed precision, gradient accumulation, checkpoint resume, and prediction export.
- `ml/evaluate.py`: binary classification/calibration metrics by English, synthetic Vietnamese, and combined slices.
- `ml/calibrate.py`: low/high probability threshold selection on validation predictions.
- `ml/promote.py`: promotion-gate evaluation, required-file checksums, and atomic artifact publication.
- `email_analysis/local_ai_classifier.py`: optional-dependency discovery, artifact verification, lazy locked loading, and local inference.
- `email_analysis/ai_classifier.py`: backwards-compatible local-first/Groq-fallback orchestration.
- `config/settings.py`: local runtime switches and paths.
- `requirements-ml-runtime.txt`: isolated runtime dependencies.
- `requirements-ml.txt`: isolated training dependencies.
- `tests/ml/`: unit and smoke tests that do not download model weights.
- `tests/fixtures/ml/tiny_emails.jsonl`: deterministic balanced fixture for the preparation/baseline smoke path.
- `.env.example`, `.gitignore`, `README.md`: operator configuration and commands.

---

### Task 1: Shared contracts and text preparation

**Files:**
- Create: `ml/__init__.py`
- Create: `ml/contracts.py`
- Create: `ml/text.py`
- Create: `tests/ml/test_contracts.py`
- Create: `tests/ml/test_text.py`

**Interfaces:**
- Produces: `EmailRecord.from_mapping(data: Mapping[str, object]) -> EmailRecord`
- Produces: `DecisionThresholds.from_mapping(data: Mapping[str, object]) -> DecisionThresholds`
- Produces: `DecisionThresholds.verdict(probability: float) -> str`
- Produces: `normalize_text(value: object) -> str`
- Produces: `content_sha256(subject: str, sender: str, body: str) -> str`
- Produces: `format_email_text(email_data: Mapping[str, object], urls: Sequence[Mapping[str, object]] | None = None, max_chars: int = 12000) -> str`
- Produces: `balanced_truncate(text: str, max_chars: int, marker: str = "\n[...]\n") -> str`

- [ ] **Step 1: Write failing contract and threshold tests**

```python
def test_threshold_boundaries_are_stable() -> None:
    thresholds = DecisionThresholds(low=0.2, high=0.8)
    assert thresholds.verdict(0.199) == "legitimate"
    assert thresholds.verdict(0.2) == "suspicious"
    assert thresholds.verdict(0.799) == "suspicious"
    assert thresholds.verdict(0.8) == "phishing"


def test_email_record_rejects_unknown_label() -> None:
    with pytest.raises(ValueError, match="label"):
        EmailRecord.from_mapping(
            {
                "id": "x",
                "source": "fixture",
                "source_split": "train",
                "source_id": "1",
                "language": "en",
                "subject": "hello",
                "sender": "a@example.test",
                "body": "body",
                "label": "spam",
                "content_sha256": "0" * 64,
                "group_id": "g1",
                "synthetic": False,
            }
        )
```

- [ ] **Step 2: Run the tests and verify import failure**

Run: `.venv\Scripts\python.exe -m pytest -q tests/ml/test_contracts.py tests/ml/test_text.py`

Expected: FAIL because `ml.contracts` and `ml.text` do not exist.

- [ ] **Step 3: Implement immutable validated contracts**

```python
@dataclass(frozen=True, slots=True)
class DecisionThresholds:
    low: float
    high: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.low < self.high <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= low < high <= 1")

    def verdict(self, probability: float) -> str:
        probability = max(0.0, min(1.0, float(probability)))
        if probability < self.low:
            return "legitimate"
        if probability >= self.high:
            return "phishing"
        return "suspicious"
```

`EmailRecord` validates all required keys, labels, splits, a 64-character lowercase SHA-256 value, and serializes through `to_dict()`.

- [ ] **Step 4: Implement normalization, hashing, host preservation, and balanced truncation**

```python
def balanced_truncate(
    text: str, max_chars: int, marker: str = "\n[...]\n"
) -> str:
    if max_chars <= len(marker):
        raise ValueError("max_chars must be greater than marker length")
    if len(text) <= max_chars:
        return text
    remaining = max_chars - len(marker)
    head = (remaining + 1) // 2
    tail = remaining - head
    return f"{text[:head]}{marker}{text[-tail:]}"
```

`format_email_text` emits labeled `Subject`, `From`, `URL hosts`, and `Body` sections, strips HTML from fallback body content, normalizes whitespace, and applies balanced truncation to the body while always retaining metadata and URL hosts.

- [ ] **Step 5: Run focused tests**

Run: `.venv\Scripts\python.exe -m pytest -q tests/ml/test_contracts.py tests/ml/test_text.py`

Expected: PASS.

- [ ] **Step 6: Commit the shared core**

```powershell
git add ml/__init__.py ml/contracts.py ml/text.py tests/ml/test_contracts.py tests/ml/test_text.py
git commit -m "feat: add phishing ML contracts and text formatter"
```

---

### Task 2: Dataset preparation, provenance, and split isolation

**Files:**
- Create: `ml/prepare_data.py`
- Create: `tests/ml/test_prepare_data.py`
- Create: `tests/fixtures/ml/tiny_emails.jsonl`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `EmailRecord`, `content_sha256`, `normalize_text`
- Produces: `normalize_source_row(row: Mapping[str, object], adapter: str, split: str) -> EmailRecord`
- Produces: `deduplicate_records(records: Iterable[EmailRecord]) -> tuple[list[EmailRecord], list[dict[str, str]]]`
- Produces: `validate_group_splits(records: Iterable[EmailRecord]) -> None`
- Produces CLI: `python -m ml.prepare_data --source fixture --fixture PATH --output-dir PATH --smoke`

- [ ] **Step 1: Write failing normalization, deduplication, and isolation tests**

```python
def test_exact_duplicates_are_quarantined() -> None:
    kept, rejected = deduplicate_records([record("a", "train"), record("b", "train")])
    assert [item.id for item in kept] == ["a"]
    assert rejected == [{"id": "b", "reason": "duplicate_content", "duplicate_of": "a"}]


def test_group_cannot_cross_splits() -> None:
    with pytest.raises(ValueError, match="group_id"):
        validate_group_splits(
            [record("a", "train", group_id="g"), record("b", "test", group_id="g")]
        )
```

- [ ] **Step 2: Run tests and confirm missing implementation**

Run: `.venv\Scripts\python.exe -m pytest -q tests/ml/test_prepare_data.py`

Expected: FAIL on imports.

- [ ] **Step 3: Implement source adapters and quarantine behavior**

Adapters map dataset-specific fields to the normalized contract and make labels explicit through fixed maps. Malformed rows are appended to `rejected.jsonl` with `source`, `source_id`, and a sanitized reason; no raw secret or authorization data is written.

- [ ] **Step 4: Implement deterministic outputs and manifest**

Write `train.jsonl`, `validation.jsonl`, and `test.jsonl` sorted by stable record ID. Write `dataset-manifest.json` with source revisions, licenses, counts, label/language distributions, rejection counts, seed, creation time, generation settings, and SHA-256 checksums for every generated JSONL file.

- [ ] **Step 5: Implement the smoke fixture CLI**

```powershell
.venv\Scripts\python.exe -m ml.prepare_data `
  --source fixture `
  --fixture tests/fixtures/ml/tiny_emails.jsonl `
  --output-dir data/processed/smoke `
  --seed 42 `
  --smoke
```

Expected: exit 0 with deterministic train/validation/test files and manifest.

- [ ] **Step 6: Add generated-data ignore rules**

```gitignore
# Local ML data, checkpoints, and promoted artifacts
data/raw/
data/processed/
artifacts/
```

- [ ] **Step 7: Run focused tests and smoke command**

Run: `.venv\Scripts\python.exe -m pytest -q tests/ml/test_prepare_data.py`

Expected: PASS.

- [ ] **Step 8: Commit dataset preparation**

```powershell
git add .gitignore ml/prepare_data.py tests/ml/test_prepare_data.py tests/fixtures/ml/tiny_emails.jsonl
git commit -m "feat: add reproducible phishing dataset preparation"
```

---

### Task 3: Cached and bounded Vietnamese augmentation

**Files:**
- Create: `ml/augment_vietnamese.py`
- Create: `tests/ml/test_augment_vietnamese.py`

**Interfaces:**
- Consumes: normalized training/test JSONL records and `GROQ_API_KEY`
- Produces: `augmentation_cache_key(record: EmailRecord, model: str, prompt_version: str) -> str`
- Produces: `parse_augmentation_response(payload: object, expected: Sequence[EmailRecord]) -> list[EmailRecord]`
- Produces CLI: `python -m ml.augment_vietnamese --input PATH --output PATH --cache-dir PATH --max-records N --max-requests N`

- [ ] **Step 1: Write failing cache, schema, and label-preservation tests**

```python
def test_response_cannot_change_label_or_url() -> None:
    original = phishing_record(body="Open https://evil.test/login")
    payload = {
        "items": [
            {
                "source_id": original.id,
                "subject": "Thông báo",
                "sender": original.sender,
                "body": "Mở https://safe.test/login",
                "label": "legitimate",
            }
        ]
    }
    with pytest.raises(ValueError, match="label|URL"):
        parse_augmentation_response(payload, [original])
```

- [ ] **Step 2: Run tests and verify missing implementation**

Run: `.venv\Scripts\python.exe -m pytest -q tests/ml/test_augment_vietnamese.py`

Expected: FAIL on import.

- [ ] **Step 3: Implement strict parsing and synthetic record construction**

Accept exactly one item per expected source ID. Preserve `label`, `sender`, `group_id`, URLs/domains, currency tokens, attachment names, and security intent. Set `language="vi"`, `synthetic=True`, a new stable ID, and a recomputed content hash.

- [ ] **Step 4: Implement content-addressed cache and bounded requests**

Before each request, check `<cache-dir>/<sha256>.json`. Each request has a 30-second timeout, at most three attempts with bounded exponential backoff, `--batch-size`, `--max-records`, and `--max-requests`. The run manifest records prompt version, Groq model, counts, failures, and cache hits without the API key.

- [ ] **Step 5: Add strict JSON-only Vietnamese prompt**

The prompt instructs Groq to translate naturally between English and Vietnamese while returning:

```json
{"items":[{"source_id":"...","subject":"...","sender":"...","body":"...","label":"phishing"}]}
```

It explicitly forbids altering labels, URLs, domains, amounts, attachment names, credential/security intent, and the number/order of items.

- [ ] **Step 6: Run tests and offline parse smoke**

Run: `.venv\Scripts\python.exe -m pytest -q tests/ml/test_augment_vietnamese.py`

Expected: PASS without a network call.

- [ ] **Step 7: Commit augmentation**

```powershell
git add ml/augment_vietnamese.py tests/ml/test_augment_vietnamese.py
git commit -m "feat: add bounded Vietnamese email augmentation"
```

---

### Task 4: Baseline, calibration, and evaluation

**Files:**
- Create: `ml/train_baseline.py`
- Create: `ml/calibrate.py`
- Create: `ml/evaluate.py`
- Create: `tests/ml/test_baseline.py`
- Create: `tests/ml/test_calibrate_evaluate.py`

**Interfaces:**
- Consumes: normalized JSONL splits
- Produces: `select_thresholds(y_true: Sequence[int], probabilities: Sequence[float], max_fpr: float = 0.05) -> DecisionThresholds`
- Produces: `compute_metrics(y_true: Sequence[int], probabilities: Sequence[float], thresholds: DecisionThresholds) -> dict[str, object]`
- Produces CLI: `python -m ml.train_baseline --data-dir PATH --output-dir PATH --seed 42 --smoke`
- Produces CLI: `python -m ml.evaluate --predictions PATH --thresholds PATH --output PATH`

- [ ] **Step 1: Write failing threshold and metric tests**

```python
def test_calibration_respects_false_positive_ceiling() -> None:
    thresholds = select_thresholds(
        y_true=[0, 0, 1, 1],
        probabilities=[0.01, 0.20, 0.70, 0.95],
        max_fpr=0.0,
    )
    assert thresholds.high > 0.20
    assert thresholds.low < thresholds.high


def test_metrics_include_required_fields() -> None:
    metrics = compute_metrics(
        [0, 0, 1, 1], [0.05, 0.10, 0.80, 0.90], DecisionThresholds(0.2, 0.7)
    )
    assert set(metrics) >= {
        "phishing_precision",
        "phishing_recall",
        "phishing_f1",
        "macro_f1",
        "false_positive_rate",
        "confusion_matrix",
        "pr_auc",
        "roc_auc",
        "brier_score",
    }
```

- [ ] **Step 2: Run tests and verify missing implementation**

Run: `.venv\Scripts\python.exe -m pytest -q tests/ml/test_calibrate_evaluate.py tests/ml/test_baseline.py`

Expected: FAIL on imports.

- [ ] **Step 3: Implement deterministic threshold search**

Search sorted validation probabilities. Choose the high threshold with maximum phishing recall subject to the FPR ceiling, breaking ties by macro F1 and then higher threshold. Choose the low threshold below `high` that maximizes three-way coverage while retaining an uncertainty interval; persist `low`, `high`, calibration metrics, and validation checksum.

- [ ] **Step 4: Implement evaluation slices**

Evaluate English, synthetic Vietnamese, and combined records independently. Handle single-class smoke slices by returning `null` for undefined AUCs instead of warning or crashing.

- [ ] **Step 5: Implement the TF-IDF baseline**

Use a `FeatureUnion` of word TF-IDF `(1, 2)` and character TF-IDF `(3, 5)`, followed by class-balanced logistic regression with seed and bounded iterations. Export validation/test probabilities, `metrics.json`, `thresholds.json`, and the serialized baseline only under ignored artifacts.

- [ ] **Step 6: Run focused tests and tiny smoke training**

Run: `.venv\Scripts\python.exe -m pytest -q tests/ml/test_calibrate_evaluate.py tests/ml/test_baseline.py`

Run:

```powershell
.venv\Scripts\python.exe -m ml.train_baseline `
  --data-dir data/processed/smoke `
  --output-dir artifacts/baseline-smoke `
  --seed 42 `
  --smoke
```

Expected: tests pass and the command writes thresholds, predictions, and metrics.

- [ ] **Step 7: Commit baseline and evaluation**

```powershell
git add ml/train_baseline.py ml/calibrate.py ml/evaluate.py tests/ml/test_baseline.py tests/ml/test_calibrate_evaluate.py
git commit -m "feat: add phishing baseline calibration and metrics"
```

---

### Task 5: Artifact validation and safe promotion

**Files:**
- Modify: `ml/contracts.py`
- Create: `ml/promote.py`
- Create: `tests/ml/test_promote.py`

**Interfaces:**
- Produces: `build_artifact_manifest(directory: Path, model_id: str) -> dict[str, object]`
- Produces: `validate_artifact(directory: Path) -> ArtifactManifest`
- Produces: `evaluate_promotion_gates(metrics: Mapping[str, object], baseline_metrics: Mapping[str, object]) -> list[str]`
- Produces: `promote_artifact(candidate: Path, target: Path) -> None`

- [ ] **Step 1: Write failing checksum and gate tests**

```python
def test_tampered_artifact_is_rejected(tmp_path: Path) -> None:
    artifact = make_valid_artifact(tmp_path)
    (artifact / "thresholds.json").write_text('{"low":0.1,"high":0.9}', encoding="utf-8")
    with pytest.raises(ValueError, match="checksum"):
        validate_artifact(artifact)


def test_failed_quality_gate_does_not_replace_target(tmp_path: Path) -> None:
    target = make_valid_artifact(tmp_path / "active", marker="active")
    candidate = make_candidate(tmp_path / "candidate", english_recall=0.50)
    with pytest.raises(ValueError, match="recall"):
        promote_artifact(candidate, target)
    assert (target / "marker").read_text(encoding="utf-8") == "active"
```

- [ ] **Step 2: Run tests and confirm missing functions**

Run: `.venv\Scripts\python.exe -m pytest -q tests/ml/test_promote.py`

Expected: FAIL.

- [ ] **Step 3: Implement required-file and checksum validation**

Require model config, tokenizer files, weights (`model.safetensors` or sharded safetensors index), `thresholds.json`, `metrics.json`, `dataset-manifest.json`, and `artifact-manifest.json`. Resolve every manifest path under the artifact root and reject traversal, missing files, size changes, or SHA-256 mismatches.

- [ ] **Step 4: Implement promotion gates**

Return precise failures for English recall, English FPR, English macro F1 versus baseline, and synthetic Vietnamese recall. The CLI exits nonzero without modifying the active target if any gate fails.

- [ ] **Step 5: Implement atomic publication**

Copy the validated candidate to a temporary sibling directory, validate again, move the current target to a recoverable backup, atomically rename the temporary directory to the target, then remove the backup only after success. Restore the backup if the final rename fails.

- [ ] **Step 6: Run promotion tests**

Run: `.venv\Scripts\python.exe -m pytest -q tests/ml/test_promote.py`

Expected: PASS.

- [ ] **Step 7: Commit safe artifacts**

```powershell
git add ml/contracts.py ml/promote.py tests/ml/test_promote.py
git commit -m "feat: validate and safely promote local AI artifacts"
```

---

### Task 6: Local runtime classifier with optional dependencies

**Files:**
- Create: `email_analysis/local_ai_classifier.py`
- Create: `tests/test_local_ai_classifier.py`

**Interfaces:**
- Consumes: `format_email_text`, `DecisionThresholds`, `validate_artifact`
- Produces: `classify_email_local(email_data: dict, urls: list[dict] | None = None) -> dict`
- Produces: `reset_local_model_cache() -> None` for deterministic tests and process lifecycle
- Stable result fields: `verdict`, `confidence`, `reasons`, `risk_score`, `error`, `provider`, `model`, `phishing_probability`, `fallback_used`

- [ ] **Step 1: Write failing disabled, missing, threshold, and fake-model tests**

```python
def test_missing_artifact_returns_stable_unavailable_result(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(local, "LOCAL_AI_MODEL_DIR", str(tmp_path / "missing"))
    result = local.classify_email_local({"subject": "hello", "body_text": "world"})
    assert result["verdict"] == "unknown"
    assert result["provider"] == "local"
    assert result["error"] == "local model artifact not found"


def test_fake_model_maps_probability_through_artifact_thresholds(
    monkeypatch, fake_artifact
) -> None:
    install_fake_transformers(monkeypatch, probability=0.85)
    result = local.classify_email_local({"subject": "verify", "body_text": "login"})
    assert result["verdict"] == "phishing"
    assert result["phishing_probability"] == pytest.approx(0.85)
```

- [ ] **Step 2: Run tests and confirm module is absent**

Run: `.venv\Scripts\python.exe -m pytest -q tests/test_local_ai_classifier.py`

Expected: FAIL on import.

- [ ] **Step 3: Implement stable result construction and artifact discovery**

Disabled, missing, invalid, dependency-unavailable, and inference-failure paths return `unknown` with actionable sanitized errors. The module performs no `torch` or `transformers` import at application import time.

- [ ] **Step 4: Implement locked lazy loading**

Use one `threading.Lock` around initial tokenizer/model construction and a separate inference lock. Load tokenizer and sequence-classification model from the validated local directory only, with `local_files_only=True` and `trust_remote_code=False`; select CUDA only when available, call `eval()`, and cache model, tokenizer, device, thresholds, and artifact identity.

- [ ] **Step 5: Implement inference**

Format the email with the shared formatter, tokenize with truncation and configured maximum length, run in `torch.inference_mode()`, convert the phishing logit through sigmoid/softmax according to the two-label model config, clamp to `[0, 1]`, and map through artifact thresholds. Confidence is `p` for phishing, `1-p` for legitimate, and `max(p, 1-p)` for suspicious.

- [ ] **Step 6: Run runtime unit tests**

Run: `.venv\Scripts\python.exe -m pytest -q tests/test_local_ai_classifier.py`

Expected: PASS without installing or downloading Transformers.

- [ ] **Step 7: Commit local runtime**

```powershell
git add email_analysis/local_ai_classifier.py tests/test_local_ai_classifier.py
git commit -m "feat: add safe lazy local phishing classifier"
```

---

### Task 7: Backwards-compatible local-first/Groq routing

**Files:**
- Modify: `email_analysis/ai_classifier.py`
- Modify: `config/settings.py`
- Create: `tests/test_ai_classifier_routing.py`

**Interfaces:**
- Preserves: `classify_email(email_data: dict, urls: list[dict] | None = None, rule_findings: list[str] | None = None) -> dict`
- Extracts: `_classify_with_groq(email_data: dict, urls: list[dict], rule_findings: list[str]) -> dict`
- Consumes settings: `LOCAL_AI_ENABLED`, `LOCAL_AI_MODEL_DIR`, `LOCAL_AI_MAX_LENGTH`, `AI_GROQ_FALLBACK`

- [ ] **Step 1: Write the routing matrix as failing tests**

```python
@pytest.mark.parametrize("verdict", ["legitimate", "phishing"])
def test_confident_local_result_does_not_call_groq(monkeypatch, verdict) -> None:
    monkeypatch.setattr(ai, "classify_email_local", lambda *_args, **_kwargs: result(verdict))
    groq = Mock(side_effect=AssertionError("Groq must not be called"))
    monkeypatch.setattr(ai, "_classify_with_groq", groq)
    assert ai.classify_email({})["provider"] == "local"
    groq.assert_not_called()


def test_uncertain_local_result_falls_back_to_groq(monkeypatch) -> None:
    monkeypatch.setattr(ai, "classify_email_local", lambda *_args, **_kwargs: result("suspicious"))
    monkeypatch.setattr(ai, "_classify_with_groq", lambda *_args: result("phishing", provider="groq"))
    routed = ai.classify_email({})
    assert routed["provider"] == "groq"
    assert routed["fallback_used"] is True
```

Also cover local unavailable, local disabled, fallback disabled, Groq failure, no API key, and offline mode.

- [ ] **Step 2: Run routing tests and confirm failures**

Run: `.venv\Scripts\python.exe -m pytest -q tests/test_ai_classifier_routing.py`

Expected: FAIL because current code is Groq-only.

- [ ] **Step 3: Extend the stable result schema**

All results contain:

```python
{
    "verdict": "unknown",
    "confidence": 0.0,
    "reasons": [],
    "risk_score": 0,
    "error": None,
    "provider": "none",
    "model": None,
    "phishing_probability": None,
    "fallback_used": False,
}
```

Groq keeps its existing parsing and risk mapping while setting `provider="groq"` and `model=GROQ_MODEL`.

- [ ] **Step 4: Implement routing without double scoring**

Call local first when enabled. Return confident local results. Route only uncertain local results to Groq when fallback is enabled and online. If Groq fails, preserve the local suspicious result and attach the sanitized fallback error. If local is unavailable, use current Groq behavior. Offline with no usable local result returns unknown without any request.

- [ ] **Step 5: Add settings**

```python
LOCAL_AI_ENABLED = _get_bool("LOCAL_AI_ENABLED", True)
LOCAL_AI_MODEL_DIR = os.getenv(
    "LOCAL_AI_MODEL_DIR", "artifacts/models/phishing-mmbert"
)
LOCAL_AI_MAX_LENGTH = int(os.getenv("LOCAL_AI_MAX_LENGTH", "1024"))
AI_GROQ_FALLBACK = _get_bool("AI_GROQ_FALLBACK", True)
```

Validate `LOCAL_AI_MAX_LENGTH` as a positive integer and keep thresholds solely in the artifact.

- [ ] **Step 6: Run routing and existing suites**

Run: `.venv\Scripts\python.exe -m pytest -q tests/test_ai_classifier_routing.py tests/test_pipeline_helpers.py tests/test_risk_scoring_refactor.py`

Expected: PASS; the scoring engine still consumes exactly one routed `ai_verdict`.

- [ ] **Step 7: Commit orchestration**

```powershell
git add config/settings.py email_analysis/ai_classifier.py tests/test_ai_classifier_routing.py
git commit -m "feat: route phishing classification through local AI first"
```

---

### Task 8: mmBERT training entry point

**Files:**
- Create: `ml/train_mmbert.py`
- Create: `tests/ml/test_train_mmbert.py`
- Create: `requirements-ml-runtime.txt`
- Create: `requirements-ml.txt`

**Interfaces:**
- Consumes: normalized train/validation JSONL, `format_email_text`
- Produces: `build_training_arguments(output_dir: Path, smoke: bool, seed: int) -> TrainingArguments`
- Produces: `compute_class_weights(labels: Sequence[int]) -> tuple[float, float]`
- Produces CLI: `python -m ml.train_mmbert --data-dir PATH --output-dir PATH --model-id jhu-clsp/mmBERT-small --max-length 512`

- [ ] **Step 1: Write failing pure configuration tests**

```python
def test_class_weights_upweight_minority() -> None:
    legitimate, phishing = compute_class_weights([0, 0, 0, 1])
    assert phishing > legitimate


def test_smoke_configuration_is_bounded(tmp_path: Path) -> None:
    config = training_config(output_dir=tmp_path, smoke=True, seed=42)
    assert config.max_steps <= 2
    assert config.per_device_train_batch_size == 1
```

- [ ] **Step 2: Run tests before installing ML dependencies**

Run: `.venv\Scripts\python.exe -m pytest -q tests/ml/test_train_mmbert.py`

Expected: FAIL because the module is missing, then pass after pure helpers are added while optional imports remain inside the command path.

- [ ] **Step 3: Add isolated dependency files**

`requirements-ml-runtime.txt` pins compatible major ranges for PyTorch, Transformers, and Safetensors. `requirements-ml.txt` includes the runtime file plus Datasets, Accelerate, scikit-learn, and evaluation/training utilities. Neither file is included from core requirements.

- [ ] **Step 4: Implement deterministic dataset/tokenizer setup**

Load local JSONL splits, format with the shared formatter, map binary labels to IDs, and tokenize to 512 by default. Set Python, NumPy, and Torch seeds. Load `jhu-clsp/mmBERT-small` with `num_labels=2`, explicit `id2label`/`label2id`, `trust_remote_code=False`, and Safetensors.

- [ ] **Step 5: Implement 4 GB VRAM-safe training**

Default to per-device batch size 1, gradient accumulation 16, FP16 on CUDA, gradient checkpointing, class-weighted cross entropy, epoch evaluation/saving, early stopping, best-model restoration, bounded retained checkpoints, and resume-from-checkpoint support. `--smoke` limits examples and steps.

- [ ] **Step 6: Export candidate artifact inputs**

Save model/tokenizer, validation/test predictions, training metadata, latency, available peak CUDA memory, dataset manifest copy, and then call calibration/evaluation helpers to write `thresholds.json` and `metrics.json`.

- [ ] **Step 7: Run pure tests**

Run: `.venv\Scripts\python.exe -m pytest -q tests/ml/test_train_mmbert.py`

Expected: PASS without a model download.

- [ ] **Step 8: Commit training entry point**

```powershell
git add ml/train_mmbert.py tests/ml/test_train_mmbert.py requirements-ml-runtime.txt requirements-ml.txt
git commit -m "feat: add reproducible mmBERT phishing training"
```

---

### Task 9: Operator documentation and end-to-end verification

**Files:**
- Modify: `.env.example`
- Modify: `README.md`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Documents local-first runtime, optional installs, smoke workflow, full workflow, augmentation cost controls, quality gates, offline behavior, and artifact status checks.

- [ ] **Step 1: Add environment examples**

```dotenv
# Local bilingual phishing classifier
LOCAL_AI_ENABLED=true
LOCAL_AI_MODEL_DIR=artifacts/models/phishing-mmbert
LOCAL_AI_MAX_LENGTH=1024
AI_GROQ_FALLBACK=true
```

- [ ] **Step 2: Add reproducible operator commands**

Document core-only install, ML runtime install, full training install, fixture smoke preparation, bounded Vietnamese augmentation, baseline training, mmBERT training, evaluation, promotion, and a local inference check. State clearly that cloning the code does not include trained weights and that Groq is called only for uncertain/unavailable local results according to settings.

- [ ] **Step 3: Keep core CI independent from model downloads**

Extend lint/format/type/security paths to include `ml` and run pure `tests/ml` tests. Do not install `requirements-ml.txt` in core CI; tests must skip or inject fake optional dependencies.

- [ ] **Step 4: Run all core verification**

Run:

```powershell
.venv\Scripts\python.exe -m pytest -q -W error tests
.venv\Scripts\ruff.exe check .
.venv\Scripts\black.exe --check api bot config email_analysis ml report scoring threat_intel main.py
.venv\Scripts\mypy.exe api bot config email_analysis ml report scoring threat_intel --ignore-missing-imports --disable-error-code=import-untyped
.venv\Scripts\bandit.exe -r api bot config email_analysis ml report scoring threat_intel -lll
.venv\Scripts\python.exe -m pip check
.venv\Scripts\python.exe -m compileall -q api bot config email_analysis ml report scoring threat_intel main.py
.venv\Scripts\python.exe main.py --healthcheck
```

Expected: every command exits 0.

- [ ] **Step 5: Install optional ML dependencies and run smoke workflow**

Run:

```powershell
.venv\Scripts\python.exe -m pip install -r requirements-ml.txt
.venv\Scripts\python.exe -m ml.prepare_data --source fixture --fixture tests/fixtures/ml/tiny_emails.jsonl --output-dir data/processed/smoke --seed 42 --smoke
.venv\Scripts\python.exe -m ml.train_baseline --data-dir data/processed/smoke --output-dir artifacts/baseline-smoke --seed 42 --smoke
.venv\Scripts\python.exe -m ml.train_mmbert --data-dir data/processed/smoke --output-dir artifacts/mmbert-smoke --seed 42 --smoke
```

Expected: commands exit 0; model smoke downloads only the selected backbone and performs at most two optimizer steps.

- [ ] **Step 6: Run bounded real-data preparation and augmentation**

Prepare the pinned public datasets with revisions recorded in the manifest. Generate a small cached Vietnamese training subset first, inspect validation statistics and malformed-response quarantine, then continue up to the configured request/record cap. Generate synthetic Vietnamese evaluation only from the English test split.

- [ ] **Step 7: Train, evaluate, and attempt promotion**

Run the full baseline and mmBERT jobs with checkpoint resume. Execute `ml.promote` against `artifacts/models/phishing-mmbert`; promotion succeeds only when all four gates pass. If a gate fails, retain candidate metrics/checkpoints and leave the active runtime artifact untouched.

- [ ] **Step 8: Verify actual runtime status**

Start a clean Python process with local AI enabled and classify one benign and one phishing fixture. Confirm the result provider is `local` for confident predictions, or record the exact quality/artifact gate that prevents claiming local AI is ready.

- [ ] **Step 9: Review the exact diff and commit documentation/CI**

```powershell
git diff --check
git status --short
git add .env.example README.md .github/workflows/ci.yml
git commit -m "docs: add local phishing AI operations"
```

---

## Self-Review Record

- Spec coverage: every data, augmentation, runtime, routing, configuration, evaluation, promotion, security, testing, and rollout requirement maps to Tasks 1–9.
- Generated files remain ignored; optional dependencies remain outside core requirements and core CI.
- Training and runtime share `ml.text.format_email_text`; runtime thresholds originate only from the promoted artifact.
- Type consistency: the runtime and orchestrator use the same nine result keys, and the scorer receives one final routed dictionary.
- Safety consistency: offline mode blocks Groq, model loading is local-only with remote code disabled, augmentation is capped/cached, and promotion validates checksums before atomic replacement.
- Completion criterion: code/tests alone do not count as a ready local AI; a validated promoted artifact and clean runtime smoke result are required.
