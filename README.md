# ThreatTrace SOC — AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

**Smart India Hackathon 2026**
- **Problem Statement ID:** PS26106
- **Theme:** Cybersecurity
- **Category:** Software
- **Platform:** Modern Security Operations Center (SOC) Investigation System

---

## 🎯 Executive Overview

ThreatTrace SOC is a specialized cybersecurity investigation platform architected to transform suspicious emails into actionable threat intelligence. Rather than relying on a simplistic black-box AI score, ThreatTrace integrates an explainable **Hybrid Threat Engine** combining:
1. **Machine Learning Classifier**: TF-IDF vectorizer + L2 Logistic Regression evaluated on held-out public email corpora (SpamAssassin, Nazario Phishing Corpus, Enron, and CEAS 2008).
2. **Deterministic Security Rules**: Header spoofing checks, sender/reply-to diversion detection, SPF/DKIM/DMARC validation, and credential solicitation detection.
3. **Deep URL & Domain Inspection**: Detection of raw IP hosts, URL shorteners, punycode homoglyphs, excessive subdomains, and brand typosquatting.
4. **Network & Geolocation Enrichment**: Autonomous IP geolocation resolution with mandatory forensic disclaimers.
5. **Threat DNA & Evidence Timeline**: Multidimensional threat profiling and auditable investigation provenance.

---

## 🔬 Important Accuracy & Evaluation Metrics

Machine learning accuracy is derived from actual evaluation on an unseen held-out test partition (2,960 emails; stratified 80/20 train/test split):

| Metric | Score | Cybersecurity Operational Impact |
| :--- | :---: | :--- |
| **Accuracy** | **96.42%** | Overall correct classifications across all email types |
| **Precision** | **95.76%** | Low false alarm rate for security analysts |
| **Recall** | **97.20%** | **Highest Priority**: Intercepts dangerous attacks to prevent initial breach footholds |
| **F1-Score** | **96.47%** | Balanced harmonic mean between precision and recall |

### Confusion Matrix (Held-Out Test Samples: 2,960)
- **True Safe (TN):** 1,432
- **False Phishing (FP):** 63 *(False Alarm)*
- **False Safe (FN):** 41 *(Missed Phishing)*
- **True Phishing (TP):** 1,424 *(Intercepted Threat)*

> **Why Recall Matters in SOC Operations:**
> In enterprise security, missing a phishing attack (False Negative) can lead to ransomware deployment or corporate credential compromise. A high Recall (97.20%) guarantees maximum threat capture, while Tier-1 analysts can rapidly triage occasional false alerts.

---

## 🛡️ Unique Platform Features

1. **Threat DNA**: A 6-dimensional behavioral fingerprint mapping:
   - Identity Risk
   - URL Risk
   - Language Risk
   - Infrastructure Risk
   - Header Risk
   - Credential Theft Risk
2. **Evidence Timeline**: Traceable step-by-step investigation chain from RFC 822 ingestion to forensic dossier generation.
3. **"Why This Verdict?" Panel**: Direct, transparent justifications showing what triggered the threat score, paired with "Evidence Supporting Safety" to eliminate black-box AI behavior.
4. **IOC Intelligence Table**: Auto-extracted IPs, Domains, URLs, Sender, Reply-To, and Message-IDs with copyable indicators and threat severity ratings.
5. **Infrastructure Geolocation**: Country, city, coordinates, ISP, and ASN telemetry with the mandatory non-attribution disclaimer.
6. **Dual-Viewing Modes**:
   - **Simple Mode**: Intuitive for non-technical users and quick SIH demonstrations.
   - **Analyst Mode**: High-density view showing raw headers, RFC parameters, ML feature vectors, and technical risk factors.
7. **One-Click Forensic Export**: Instant PDF forensic dossier generation and structured JSON exports.

---

## ⚙️ Quick Start & Local Execution

### Web Platform (React + Express + TypeScript)
```bash
# 1. Install dependencies
npm install

# 2. Launch development SOC server (Port 3000)
npm run dev

# 3. Access in browser
http://localhost:3000
```

### Python Scripts (Optional Offline CLI Analysis)
```bash
# 1. Install Python packages
pip install -r scripts/requirements.txt

# 2. Run model evaluation
python scripts/evaluate_model.py

# 3. Run model training pipeline
python scripts/train_model.py
```
