# 🛡️ Phishing Intelligence Platform v5.0

A professional threat analysis platform for email forensics, URL inspection, DNS analysis, and real-time intelligence — built for security teams and researchers.

**Live Demo:** https://enterprise-phishing-detector-yex9.onrender.com

---

## What it does

Analyzes suspicious emails and URLs across 6 analysis modules and 70+ threat signals to produce a 0–100 threat score and a detailed verdict.

---

## ML Model

The email classifier uses a real trained machine learning model — not keyword matching.

- **Dataset:** UCI/Kaggle Spam Dataset (5,572 labeled emails)
- **Algorithm:** TF-IDF vectorization + Logistic Regression
- **Accuracy:** 98% on test set
- **Mean F1:** 0.925 across 5-fold cross-validation
- **Training script:** `train_model.py`

---

## Features

- **Email Analysis** — Detects spoofed senders, brand impersonation, urgency tactics
- **URL Intelligence** — WHOIS, domain age, SSL inspection, redirect chains, DNS, content analysis
- **QR Code Scanner** — Extract and analyze URLs from QR code images
- **Email Header Analyzer** — SPF, DKIM, DMARC verification
- **PDF Report Export** — Professional forensics reports
- **Scan History** — Persistent history with stats and search
- **Live Threat Feed** — Real-time phishing URLs from OpenPhish and URLhaus
- **Browser Extension** — Right-click any link to analyze it
- **Threat Intelligence APIs** — VirusTotal, Google Safe Browsing, AbuseIPDB

---

## Tech Stack

- **Backend:** Python 3.11, Flask
- **ML:** scikit-learn, TF-IDF, Logistic Regression
- **Security:** python-whois, dnspython, SSL analysis
- **Frontend:** HTML5, CSS3, JavaScript
- **Deployment:** Render

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/analyze` | Email threat analysis |
| POST | `/analyze-url` | Deep URL analysis |
| POST | `/quick-url-check` | Fast URL verdict |
| POST | `/bulk-url-check` | Scan up to 10 URLs |
| POST | `/analyze-headers` | Email header forensics |
| GET  | `/threat-feed` | Live phishing feed |
| POST | `/api/full-threat-check` | All three threat APIs |
| GET  | `/api/status` | Integration status |

---

## Quick Start

```bash
git clone https://github.com/TheGhostPacket/enterprise-phishing-detector.git
cd enterprise-phishing-detector
pip install -r requirements.txt
python3 train_model.py
python3 app.py
```

---

## Author

**The Ghost Packet** — Cybersecurity Portfolio Project  
For educational purposes · MIT License
