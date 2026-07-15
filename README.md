# 🛡️ APKGuard AI v2.0
**Generative AI-Based Automated Analysis and Risk Scoring of Fraudulent APKs**

![Open Source](https://img.shields.io/badge/Open%20Source-100%25-green)
![Python](https://img.shields.io/badge/Backend-Python%20FastAPI-blue)
![React](https://img.shields.io/badge/Frontend-React%20%2B%20Vite-cyan)
![AI](https://img.shields.io/badge/AI%20Engine-LLaMA%203.3%2070B-orange)
![ML](https://img.shields.io/badge/ML%20Engine-scikit--learn-yellow)

> **PSB CyberShield Hackathon 2026** | **Bank of India × IIT Hyderabad**  
> **Problem Statement 1:** Fraudulent APK Analysis & Risk Scoring  
> **Team:** null Pointers  

---

<img width="1442" height="2200" alt="image" src="https://github.com/user-attachments/assets/04377b3d-5204-4274-a970-eefb8a7c7cd9" />


---

## 🚀 Executive Summary

A large portion of banking fraud in India begins with fake Android apps distributed via WhatsApp or SMS. **APKGuard AI** is a full-stack, enterprise-ready web platform that allows SOC analysts to upload suspicious APKs and receive a complete forensic threat report in under 30 seconds. 

By combining static bytecode analysis, live runtime instrumentation, generative AI interpretation, and ML-based clustering, APKGuard AI neutralizes zero-day banking trojans before they impact customers.

### 🏆 KPI Benchmarks
* **72** AV Engines Scanned
* **200+** Security Checks Run
* **<30s** Average Scan Time
* **96.4%** F1 Score (ML Classifier)

---

## 🔥 v2.0 Major Improvements

This repository represents **v2.0**, introducing six major enterprise-grade capabilities:

1. **Decoupled Scoring Engine:** Static and dynamic scores use mutually exclusive data sources (Androguard + Frida) combined via a weighted average formula to prevent indicator double-counting.
2. **K-Means ML Clustering:** A 5-feature vector classified using K-Means (k=2), achieving 96% accuracy across a 50-sample holdout dataset (Confusion Matrix live in dashboard).
3. **LLM Smali Deobfuscation:** Extracts raw Smali bytecode from crypto/network methods and uses **Groq LLaMA 3.3 70B** to translate it into readable Python pseudocode with MITRE technique mapping.
4. **Zero-Day Logic Gate:** Automatically flags `POSSIBLE ZERO-DAY` payloads that evade all 72 VirusTotal engines but score ≥ 60 on our internal behavioral engine.
5. **One-Click YARA Export:** Generates deployment-ready `.yar` rules client-side (<5ms) compatible with CrowdStrike, Wazuh, and Velociraptor.
6. **WhatsApp/SMS URL Scanner:** Direct mitigation for the primary delivery vector, scoring phishing URLs against suspicious TLDs, brand impersonation patterns, and the OpenPhish feed.

---

## 🛠️ Technology Stack

| Layer | Component | Technology |
| :--- | :--- | :--- |
| **Frontend** | Security Dashboard | React + Vite |
| **Backend API** | Analysis Orchestration | Python FastAPI |
| **AI Engine** | Threat Narrative & Smali | Groq LLaMA 3.3 70B |
| **Static Analysis** | APK Decompilation | Androguard |
| **Dynamic Analysis** | Runtime Instrumentation | Frida 17.x |
| **ML Classifier** | K-Means Clustering | scikit-learn |
| **Reporting** | PDF Generation | reportlab |

---

## ⚙️ Local Setup & Installation

To run APKGuard AI locally, you will need to start both the Python backend and the React frontend.

### 1. Backend Setup (FastAPI)
```bash
# Clone the repository
git clone [https://github.com/POTHAMM/APKGuard-Ai.git](https://github.com/POTHAMM/APKGuard-Ai.git)
cd APKGuard-Ai/backend

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Add your API Keys (Groq, VirusTotal) to an environment file
cp .env.example .env

# Start the FastAPI server
uvicorn main:app --reload --port 8000

### 2. Frontend Setup (React + Vite)
Open a **new** terminal window:
```bash
cd ../frontend
npm install
npm run dev

👥 The Team (null Pointers)
Prathamkumar Kalidas Solanki - Computer Science & Engineering, Karnavati University

Vatsa Jamar - Vellore Institute of Technology

Anusha Lodha - Parul Institute of Engineering and Technology

Disclaimer: This tool is intended for authorized malware analysis, incident response triage, and educational purposes only.
