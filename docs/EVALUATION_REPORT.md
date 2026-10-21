# TrustVault — Threat Detection & Privacy Shield Evaluation Report

This report presents empirical benchmark evaluation results for the two intelligent security engines in TrustVault:
1. **Explainable Threat Detection Engine** (`src/lib/security-alerts.ts`)
2. **AI Privacy Shield Sensitive Data Detector** (`src/lib/privacy-shield.ts`)

---

## 1. Explainable Threat Detection Evaluation

### Methodology & Test Corpus
The evaluation was executed using `scripts/evaluate-threat-detection.ts`. A synthetic audit event corpus of operational scenarios was constructed to represent both normal daily workflows and specific attack patterns:

| Scenario ID | Attack Vector | Expected Detection |
|-------------|---------------|-------------------|
| SC-01 | Single mistyped password followed by valid sign-in | Benign (No Alert) |
| SC-02 | Credential stuffing (6 failed logins in 5 min) | `repeated_login_failures` (High) |
| SC-03 | Standard document reading & preview | Benign (No Alert) |
| SC-04 | IDOR probing (6 denied attempts on confidential document) | `repeated_denied_access` (High) |
| SC-05 | Mass data exfiltration burst (12 downloads in 3 min) | `bulk_download_burst` (Medium) |
| SC-06 | Multi-document enumeration probing across distinct files | `multi_document_probing` (Critical) |
| SC-07 | Multi-user benign concurrent access | Benign (No Alert) |

### Results & Confusion Matrix

```
                      ACTUAL ATTACK    ACTUAL BENIGN
PREDICTED ATTACK           4 (TP)           0 (FP)
PREDICTED BENIGN           0 (FN)           3 (TN)
```

- **True Positives (TP)**: 4 / 4
- **False Positives (FP)**: 0 / 3
- **True Negatives (TN)**: 3 / 3
- **False Negatives (FN)**: 0 / 4
- **Precision**: 100.0%
- **Recall**: 100.0%
- **F1-Score**: 100.0%
- **Accuracy**: 100.0%

### Technical Analysis & Limitations
- **Transparency**: Rule thresholds are deterministic and explainable without black-box drift.
- **Limitation**: Sliding windows are evaluated on stored audit events. In high-throughput distributed deployments, events should be piped to an event streaming broker (e.g. Apache Kafka or Redis Streams).

---

## 2. AI Privacy Shield Evaluation

### Methodology & Test Corpus
The evaluation was executed using `scripts/evaluate-privacy-shield.ts`. A labeled test corpus of enterprise document text was scanned for sensitive entities alongside negative controls:

| Test Sample | Target Entities | Negative Controls |
|-------------|-----------------|-------------------|
| Tax and HR Record | US SSN (`123-45-6789`), Phone (`(555) 234-5678`) | Standard numbers |
| Payment Record | Visa Credit Card (`4532015112830366`) | Non-Luhn 13-digit numbers |
| Cloud Config | AWS Key (`AKIAIOSFODNN7EXAMPLE`) | Public identifiers |
| Support Ticket | Email (`security-lead@trustvault.internal`) | Standard punctuation |
| Env File | Password (`SuperSecretP@ssword2026!`) | Safe variable names |
| Order Confirmation | None | 13-digit sequence ID |
| Shipping Receipt | None | Tracking number |

### Results & Metrics

```
                      ACTUAL ENTITY    ACTUAL BENIGN
PREDICTED ENTITY           6 (TP)           0 (FP)
PREDICTED BENIGN           0 (FN)           2 (TN)
```

- **True Positives (TP)**: 6 / 6
- **False Positives (FP)**: 0
- **False Negatives (FN)**: 0
- **Precision**: 100.0%
- **Recall**: 100.0%
- **F1-Score**: 100.0%
- **Execution Latency**: 3ms

### Key Architectural Strengths
1. **Luhn Algorithm Validation**: Avoids false alarms on 13-19 digit order or tracking numbers by verifying card checksum validity.
2. **Reverse Redaction Buffer**: Replacements are calculated and applied from end to start, preventing character offset drift during multi-entity redaction.
3. **Owner-in-the-Loop**: The platform never overwrites original source assets and requires explicit owner approval before minting a redacted copy.
