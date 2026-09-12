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
- Domain legitimacy analysis
- Reply-To header analysis
- URL and link analysis
- Phishing language and pattern detection
- Machine learning-based email classification
- Combined security risk scoring
- Safe, Suspicious and Danger verdicts
- Email inbox and flagged email views
- Email search functionality
- Scan All functionality
- Scan logs
- Mark as spam / unmark as spam
- PDF security report generation
- Manual email analysis through the forensic profiler
- SHA-256 hashing for uploaded email evidence
- Security-focused credential and configuration handling

---

## System Architecture

```text
                         Gmail Account
                              |
                              | Google OAuth 2.0
                              v
                    +----------------------+
                    |    MailSentinel      |
                    |      Backend         |
                    |      Django          |
                    +----------+-----------+
                               |
                +--------------+--------------+
                |                             |
                v                             v
       +------------------+          +------------------+
       | Rule-Based       |          | Machine Learning |
       | Security Analysis|          | Classifier       |
       +--------+---------+          +--------+---------+
                |                             |
                | SPF / DKIM / DMARC          | TF-IDF
                | Sender Analysis             | Random Forest
                | Domain Analysis             | Classification
                | Reply-To Analysis           |
                | URL Analysis                |
                | Phishing Patterns           |
                +--------------+--------------+
                               |
                               v
                       +---------------+
                       |  Risk Scoring |
                       |   & Verdict   |
                       +-------+-------+
                               |
                               v
                    +----------------------+
                    |   REST API / Django  |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |    React Frontend    |
                    |                      |
                    | Security Dashboard   |
                    | Email Analysis       |
                    | Scan Logs            |
                    | Risk Indicators      |
                    +----------+-----------+
                               |
                               v
                       PDF Security Report
```

---

## Technology Stack

### Frontend

- React
- JavaScript
- HTML5
- CSS3
- React Router
- Google OAuth integration

### Backend

- Python
- Django
- Django REST Framework
- Google Gmail API
- Google OAuth 2.0
- ReportLab

### Machine Learning

- Scikit-learn
- TF-IDF
- Random Forest
- NumPy
- Joblib

### Security & Analysis

- SPF
- DKIM
- DMARC
- DNS analysis
- URL analysis
- Email header analysis
- Phishing pattern detection

---

## Detection Engine

MailSentinel uses a hybrid detection approach combining multiple security indicators with machine learning.

The rule-based analysis examines characteristics such as:

- Email authentication results
- Sender identity
- Domain legitimacy
- Reply-To headers
- Suspicious URLs
- Phishing language and patterns

The machine learning component provides an additional classification signal based on the email content.

The results from the different analysis components are combined to calculate an overall risk score and determine the final verdict.

---

## Machine Learning Component

The machine learning component uses supervised learning for binary email classification.

### Machine Learning Pipeline

```text
Email Text
    |
    v
Text Preprocessing
    |
    v
TF-IDF Feature Extraction
    |
    v
Random Forest Classifier
    |
    v
Phishing / Legitimate Prediction
    |
    v
Classification Probability
    |
    v
MailSentinel Risk Analysis
```

The model is trained using labelled synthetic email data containing phishing and legitimate examples.

The trained model is stored as:

```text
phishing_model.pkl
```

The machine learning component is intended as a development and research component of the hybrid detection system. Its results should not be interpreted as real-world phishing detection accuracy.

---

## Security Analysis

MailSentinel analyses multiple characteristics of an email to identify potential threats.

### Email Authentication

The system examines:

- SPF
- DKIM
- DMARC

Authentication results provide indicators that can help identify suspicious or unauthorised email activity.

### Sender Analysis

The system analyses sender information to identify potential spoofing and suspicious sender characteristics.

### Domain Analysis

The sender domain is evaluated for legitimacy and potentially suspicious characteristics.

### Reply-To Analysis

The Reply-To header is analysed for inconsistencies or suspicious destinations.

### URL Analysis

Links contained within emails are analysed for potentially suspicious characteristics.

### Phishing Language Detection

Email content is examined for patterns commonly associated with phishing and social engineering.

---

## Risk Scoring

MailSentinel combines the results of the security checks and machine learning classifier into an overall risk score.

The score is used to provide an understandable security verdict:

```text
                 Email
                   |
                   v
        +----------------------+
        | Security Checks      |
        +----------------------+
                   |
                   v
        +----------------------+
        | ML Classification    |
        +----------------------+
                   |
                   v
        +----------------------+
        | Combined Risk Score  |
        +----------------------+
                   |
          +--------+--------+
          |        |        |
          v        v        v
        Safe   Suspicious  Danger
```

This approach allows technical security indicators to be presented through a simple user-facing result.

---

## Dashboard

The MailSentinel dashboard provides a central interface for reviewing emails and their security analysis.

Key dashboard functionality includes:

- Inbox and flagged email views
- Email search
- Automated scanning
- Risk score display
- Security check results
- Machine learning classification
- Scan logs
- Threat indicators
- Email content inspection
- Spam management
- PDF report generation

---

## PDF Security Reports

MailSentinel can generate structured PDF security reports containing information about the analysed email and its security assessment.

The reports provide a structured representation of the analysis that can be used for further investigation or documentation.

PDF report generation is implemented using ReportLab.

---

## Forensic Profiler

The application also supports manual email analysis through the forensic profiler.

The forensic analysis workflow can include:

```text
Email Evidence
      |
      v
Manual Upload
      |
      v
Email Processing
      |
      v
Security Analysis
      |
      v
SHA-256 Hash
      |
      v
Threat Assessment
      |
      v
Analysis Results
```

This provides an additional workflow for analysing email evidence outside the normal Gmail inbox workflow.

---

## Project Structure

```text
MailSentinel/
│
├── mailsentinel_backend/
│   │
│   ├── gmail/
│   │   ├── migrations/
│   │   ├── __init__.py
│   │   ├── admin.py
│   │   ├── apps.py
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
│   │
│   ├── public/
│   ├── src/
│   │   ├── assets/
│   │   ├── pages/
│   │   ├── styles/
│   │   ├── App.js
│   │   ├── App.css
│   │   ├── index.css
│   │   └── index.js
│   │
│   ├── package.json
│   └── package-lock.json
│
├── .gitignore
└── README.md
```

---

## Backend API

The Django backend provides endpoints for authentication, email retrieval, analysis and reporting.

Main endpoints include:

```text
/auth/google/
/auth/callback/
/auth/logout/
/emails/
/email/<id>/
/mark-spam/<id>/
/unmark-spam/<id>/
/clear-cache/
/report/<id>/
```

---

## Gmail Integration

MailSentinel integrates with Gmail using Google OAuth 2.0.

The OAuth workflow allows the application to obtain authorised access to the required Gmail resources without storing the user's Gmail password.

The application uses the Gmail API to retrieve email information for security analysis and supports email management functionality such as marking messages as spam.

---

## Configuration

Sensitive configuration is kept outside the source code using environment variables.

A `.env.example` file is provided to demonstrate the required configuration without exposing actual secrets.

Example configuration:

```text
DJANGO_SECRET_KEY=your-secret-key
DJANGO_DEBUG=True
```

Actual credentials and environment files should never be committed to the repository.

---

## Security Considerations

MailSentinel was designed with security and credential protection in mind.

The repository excludes sensitive and local development files such as:

- OAuth client secrets
- Environment files
- Django database files
- Virtual environments
- Node modules
- Python cache files
- Local development credentials

The `.gitignore` file is used to prevent sensitive and unnecessary development files from being committed.

No real OAuth client secret or local database is included in this repository.

---

## Development Notes

MailSentinel was developed as a final-year cybersecurity project with a focus on phishing detection, security analysis, machine learning and user-facing threat reporting.

The machine learning dataset used during development is synthetic. Therefore, model performance should be interpreted as development validation rather than evidence of production-level phishing detection accuracy.

The project demonstrates the integration of:

```text
Cybersecurity Analysis
        +
Machine Learning
        +
Web Development
        +
Gmail API
        +
OAuth 2.0
        +
Threat Reporting
```

---

## Project Purpose

The purpose of MailSentinel is to explore how traditional email security indicators and machine learning can be combined into a single user-facing phishing analysis system.

The project focuses on presenting technical email security information in a format that can be understood by both technical and non-technical users.

---

## Author

**Muhammad Muneeb Nadeem**

Final Year BSc (Hons) Digital Forensics & Cyber Security

Technological University Dublin
