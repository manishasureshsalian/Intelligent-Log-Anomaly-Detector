# 🛡️ Intelligent Server Log Anomaly Detector

An end-to-end data engineering and unsupervised machine learning pipeline designed to parse unstructured server logs and automatically identify security threats, infrastructure anomalies, and system failures in real time.

## 🚀 Key Features
- **Data Engineering Pipeline:** Uses Advanced Regular Expressions (RegEx) to clean, parse, and structure chaotic text log rows into an analytical Pandas DataFrame.
- **AI Anomaly Detection:** Implements an unsupervised **Isolation Forest** model from Scikit-Learn to detect statistical outliers (like brute-force login attempts or server crashes) without requiring predefined manual rules.
- **Interactive DevOps Dashboard:** Built using Streamlit to offer system administrators a comprehensive visualization room containing threat telemetry metrics, interactive datagrids, and system risk scores.

## 🛠️ Tech Stack
- **Language:** Python 3.13
- **Data Analytics:** Pandas, NumPy
- **Machine Learning:** Scikit-Learn (Isolation Forest)
- **Web UI Framework:** Streamlit

## 📋 Installation & Setup

1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR-GITHUB-USERNAME/Intelligent-Log-Anomaly-Detector.git](https://github.com/YOUR-GITHUB-USERNAME/Intelligent-Log-Anomaly-Detector.git)
   cd Intelligent-Log-Anomaly-Detector