# 🛡️ PhishGuard – Advanced Phishing URL Detection System

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Streamlit App](https://img.shields.io/badge/Streamlit-App-red.svg)](https://streamlit.io/)

PhishGuard is an advanced, modular, and explainable phishing URL detection engine featuring an interactive Streamlit web dashboard, heuristic risk scoring, automated unit tests, and batch scanning capabilities.

---

## 🚀 Key Features

1. **URL Validation & Normalization**: Standardizes protocols, domains, and paths.
2. **IP & Domain Analysis**: Detects raw IP address hosting and excessive subdomain nesting.
3. **Typosquatting Detection**: Identifies brand impersonation attempts targeting major platforms (PayPal, Google, Microsoft, Apple, etc.).
4. **Keyword & Obfuscation Checks**: Scans for high-risk phishing keywords (`login`, `verify`, `secure`, `update`) and credential-hiding symbols (`@`).
5. **Weighted Risk Scoring (0–100)**: Quantifies threat severity deterministically.
6. **Explainable Findings**: Provides granular justifications and weights for every security check triggered.
7. **Risk Classification**: Automatically categorizes URLs into **Low**, **Medium**, **High**, and **Critical** risk levels.
8. **Reporting & Exports**: Exports analysis summaries to CSV and JSON formats.
9. **Automated Unit Tests**: Complete test suite using Python's `unittest`.
10. **Interactive Web Dashboard**: Streamlit interface for single URL inspection and batch CSV analysis.

---

## 📁 Repository Structure

```text
phishguard/
├── phishguard/
│   ├── __init__.py         # Package initialization
│   ├── analyzer.py         # Core heuristic detection engine
│   └── reporter.py         # CSV & JSON report export utilities
├── tests/
│   └── test_analyzer.py    # Unit test suite
├── app.py                  # Streamlit Interactive Web Dashboard
├── requirements.txt        # Project dependencies
├── .gitignore              # Git ignore rules
└── README.md               # Project documentation
```

---

## ⚙️ Installation & Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/phishguard.git
   cd phishguard
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Streamlit Web Dashboard**
   ```bash
   streamlit run app.py
   ```

4. **Run Unit Tests**
   ```bash
   python -m unittest discover tests
   ```

---

## 👨‍💻 Author & Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/yourusername/phishguard/issues).
