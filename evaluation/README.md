# Offline regression evaluation

This directory contains a safe, deterministic corpus that runs through the
production `PhishingPipeline`. It never calls live AI, DNS, WHOIS, landing-page,
QR, VirusTotal, OTX, AbuseIPDB, or passive-DNS services. Provider outcomes are
explicit fixtures. Corpus infrastructure uses RFC 2606/documentation domains;
the URL-shortener case names a known shortener but never resolves or contacts it.

## Corpus

`dataset.json` contains 35 ground-truth samples: 15 phishing, 15 benign, and 5
ambiguous/edge cases. Ambiguous cases are excluded only from binary confusion
metrics. They remain subject to classification ranges, severity, detector,
confidence, environment, arithmetic, critical-gate, and export-safety checks.

Each sample declares:

- a stable ID, description, binary/ambiguous label, and attack class;
- allowed verdicts and a minimum/maximum severity;
- expected and forbidden normalized findings;
- expected analysis environment and analyst notes;
- an RFC 822 email specification or a checked-in raw `.eml` fixture;
- optional deterministic AI, QR, VT, and OTX outcomes.

## Commands

Run the quality gate and create both reports:

```powershell
python -m evaluation.runner --quality-gate
```

Refresh the accepted baseline only after reviewing a deliberate behavior change:

```powershell
python -m evaluation.runner --quality-gate --write-baseline evaluation/baseline.json
```

The default outputs are `artifacts/evaluation/results.json` and
`artifacts/evaluation/report.md`. `baseline.json` is the reviewed machine-readable
reference used to reject metric degradation. `before_after.json` records the
first-run error analysis and the generalized fix that removed it.

## Metric interpretation

The report includes binary confusion metrics, one-vs-rest attack-class metrics,
severity range accuracy, annotated finding-level metrics, confidence buckets,
score distributions, FP/FN details with top score causes, critical invariants,
and per-sample results. These synthetic results are regression guarantees, not an
estimate of production prevalence or real-world model calibration.
