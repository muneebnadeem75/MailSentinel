# MailSentinel

## Hybrid Phishing Email Detection & Threat Analysis System

MailSentinel is a full-stack cybersecurity application designed to analyse Gmail messages and identify potential phishing threats.

The system combines rule-based security analysis with a machine learning classifier to evaluate suspicious email characteristics and produce an overall risk score and verdict.

---

## Overview

Phishing emails remain a major cybersecurity threat because attackers frequently use spoofed identities, malicious links, authentication failures and social-engineering techniques to deceive users.

MailSentinel provides a user-facing security dashboard that analyses email characteristics and presents the results in an understandable format.

The application integrates with Gmail using Google OAuth 2.0 and retrieves email information for security analysis.

---

## Key Features

- Gmail integration using Google OAuth 2.0
- Automated email security analysis
- SPF / DKIM / DMARC authentication checks
- Sender identity and spoofing analysis
- Domain legitimacy checks
- Reply-To header analysis
- Suspicious URL and link analysis
- Phishing-language detection
- Machine learning-based email classification
- Combined risk scoring
- Safe / Suspicious / Threat verdicts
- Email search and filtering
- Inbox and flagged email views
- Move emails to spam and restore them
- Automated security scan logs
- PDF-based security reports
- Manual email analysis support through the backend

---

## Detection Engine

MailSentinel uses a hybrid detection approach combining rule-based security checks with machine learning.

### Rule-Based Analysis

The security engine evaluates multiple indicators commonly associated with phishing emails, including:

- SPF, DKIM and DMARC authentication
- Sender identity
- Domain legitimacy
- Reply-To inconsistencies
- Phishing-related language
- Suspicious links and URLs

Each security check contributes to the overall risk assessment.

### Machine Learning

The machine learning component uses:

- TF-IDF text features
- Random Forest classification
- Binary classification of phishing and legitimate emails
- Synthetic labelled training data

The trained model is integrated into the MailSentinel detection pipeline and contributes to the overall email risk assessment.

> **Note:** The machine learning component was developed and evaluated using synthetic data as part of an academic project. Results should therefore be considered development validation rather than real-world production accuracy.

---

## Risk Scoring

MailSentinel combines rule-based indicators and the machine learning result into an overall risk score.

The application presents the result using three primary classifications:

| Verdict | Meaning |
|---|---|
| **SAFE** | No significant phishing indicators detected |
| **SUSPICIOUS** | Potentially concerning indicators detected |
| **THREAT** | Strong indicators of a phishing or malicious email |

The dashboard displays the resulting score and individual security checks to provide transparency into the analysis.

---

## System Architecture

```text
                    ┌─────────────────────┐
                    │       Gmail         │
                    │      Gmail API      │
                    └──────────┬──────────┘
                               │
                         Google OAuth 2.0
                               │
                               ▼
┌─────────────────────────────────────────────────┐
│                 Django Backend                  │
│                                                 │
│  ┌───────────────┐      ┌───────────────────┐   │
│  │ Gmail Service │─────▶│ Security Engine   │   │
│  └───────────────┘      └─────────┬─────────┘   │
│                                   │             │
│                     ┌─────────────┴──────────┐  │
│                     │                        │  │
│              Rule-Based Checks        ML Classifier
│                     │                        │  │
│                     └─────────────┬──────────┘  │
│                                   │             │
│                              Risk Score         │
│                                   │             │
│                         ┌─────────▼─────────┐   │
│                         │ Threat Analysis   │   │
│                         └─────────┬─────────┘   │
│                                   │             │
│                         PDF Security Report     │
└───────────────────────────┬─────────────────────┘
                            │
                            │ REST API
                            ▼
                  ┌─────────────────────┐
                  │    React Frontend   │
                  │                     │
                  │  Security Dashboard │
                  │  Email Analysis     │
                  │  Scan Logs          │
                  │  Risk Indicators    │
                  └─────────────────────┘
Technology Stack
Frontend
React
JavaScript
HTML5
CSS3
React Router
Google OAuth integration
Backend
Python
Django
Django REST Framework
Google Gmail API
Google OAuth 2.0
ReportLab
Machine Learning
Scikit-learn
TF-IDF
Random Forest
NumPy
Joblib
Security & Analysis
SPF
DKIM
DMARC
DNS analysis
URL analysis
Email header analysis
Phishing pattern detection
Project Structure
MailSentinel/
│
├── mailsentinel_backend/
│   ├── gmail/
│   │   ├── migrations/
│   │   ├── ml_check.py
│   │   ├── models.py
│   │   ├── pdf_report.py
│   │   ├── security.py
│   │   ├── tests.py
│   │   ├── urls.py
│   │   └── views.py
│   │
│   ├── mailsentinel_backend/
│   │   ├── settings.py
│   │   ├── urls.py
│   │   ├── asgi.py
│   │   └── wsgi.py
│   │
│   ├── ml/
│   │   ├── data_generator.py
│   │   ├── phishing_model.pkl
│   │   ├── predictor.py
│   │   └── train.py
│   │
│   ├── .env.example
│   ├── manage.py
│   └── requirements.txt
│
├── mailsentinel_frontend/
│   ├── public/
│   ├── src/
│   │   ├── assets/
│   │   ├── pages/
│   │   ├── styles/
│   │   ├── App.js
│   │   └── index.js
│   ├── package.json
│   └── package-lock.json
│
├── .gitignore
└── README.md
Security Considerations

MailSentinel was designed with security and credential protection in mind.

Sensitive configuration is stored outside the source code using environment variables.

The repository excludes sensitive and local development files such as:

OAuth client secrets
Environment files
Django database files
Virtual environments
Node modules
Python cache files
Local development credentials

A .env.example file is provided to demonstrate the required environment variables without exposing actual secrets.

PDF Security Reports

MailSentinel can generate PDF security reports containing information about the analysed email and its security assessment.

The reports provide a structured representation of the analysis that can be used for further investigation or documentation.

Dashboard

The MailSentinel dashboard provides a central interface for reviewing emails and their security analysis.

Key dashboard functionality includes:

Inbox and flagged email views
Search functionality
Security risk scores
Individual security checks
Scan logs
Email content inspection
Spam management
PDF report generation
Academic Project

MailSentinel was developed as a final-year cybersecurity project exploring the combination of rule-based phishing detection, machine learning and user-facing threat analysis.

The project focuses on making phishing analysis more understandable to users while providing detailed security indicators behind the final risk assessment.

Disclaimer

MailSentinel is an academic cybersecurity project developed for research, learning and demonstration purposes.

The machine learning component uses synthetic training data and should not be interpreted as a production-grade phishing detection system or as a replacement for established email security solutions.