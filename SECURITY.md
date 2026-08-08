# Security Policy

## Reporting a Vulnerability

Please report suspected security vulnerabilities through GitHub Security Advisories (private vulnerability reporting) for this repository.

Include:
- A clear description of the issue
- Reproduction steps or proof of concept
- Affected component(s) and impact

## Response Timeline

- Initial acknowledgement: within 3 business days
- Triage/update: within 7 business days
- Remediation target: based on severity and complexity

Please do not disclose vulnerabilities publicly until a fix is available.

## Supported Use

This project supports defensive phishing triage, security education, and controlled testing. It performs static analysis of email content and metadata; it does not detonate malware, execute attachments, or replace an approved incident-response process.

Use high-risk findings as investigation leads. Validate them with a qualified analyst and, when appropriate, an approved isolated sandbox.

## Handling Suspicious Samples

Keep repository samples inert: use reserved `.test` domains and documentation IP ranges only. Do not commit active phishing links, live payloads, credentials, customer email, model artifacts, datasets, or `.env` files.

Unknown attachments should be handled only in an approved sandbox. Secrets, uploads, logs, caches, and local model/data artifacts are excluded from the Docker build context and must remain outside Git.
