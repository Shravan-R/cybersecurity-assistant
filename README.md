<p align="center">
  <img src="https://img.shields.io/badge/Cybersec%20Assistant-AI%20Security%20Automation-4b0082?style=for-the-badge&logo=shield" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/URL%20Scan-VirusTotal-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/Text%20Analysis-GPT--powered-purple?style=flat-square" />
  <img src="https://img.shields.io/badge/Password%20Check-HIBP%20k--Anon-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/Automation-n8n-ff5f00?style=flat-square&logo=n8n" />
</p>

<h1 align="center">🛡️ Cybersec Assistant — AI-Powered Cybersecurity Automation System</h1>

A full-stack **AI-driven cybersecurity assistant** that analyzes URLs, passwords, and text messages using **VirusTotal**, **OpenAI**, **HIBP**, and a custom **Decision Agent**.  
It automatically triggers workflows via **n8n**, sends **Slack/email alerts**, logs events into a **database**, and maintains a persistent **memory system** for pattern recognition.

Perfect for security research, SOC automation, red/blue team tooling, and projects for cybersecurity portfolios.

---

# 🌟 Features

### 🔍 Multi-Type Threat Analysis
- **URL scanning** via VirusTotal  
- **Password security** via entropy + HIBP k-anonymity + common passwords  
- **Text analysis** via GPT phishing/malicious detection  

### 🧠 Agentic Decision Engine
- Combines analyzer results  
- Produces threats scores (0–100)  
- Selects: `alert`, `log`, `ignore`  
- Provides human-readable reasoning  

### 📢 Automated Responders
- **n8n webhook** → workflows  
- **Slack alerts**  
- **Email alerts**  
- **SQLite logging**  

### 🧬 Memory System
- Short-term memory (last 30 events)  
- Long-term insights:
  - average risk  
  - malicious URL frequency  
  - password weakness patterns  
- Optional embedding similarity search  

### 📊 Streamlit Dashboard
- Live analyzer  
- Threat trend charts  
- Memory viewer  
- Event history table  
- Similar phishing/event search

  # 📁 Project Structure

---cybersec-assistant/
│
├── main.py # FastAPI backend
├── config/settings.py # Environment config
│
├── ai_agent/ # Analyzer + decision agents
│ ├── url_analyzer.py
│ ├── password_checker.py
│ ├── text_detector.py
│ └── agent_decision.py
│
├── responders/ # Automation responders
│ ├── n8n_webhook.py
│ ├── email_alert.py
│ ├── slack_alert.py
│ └── db_logger.py
│
├── memory/ # Persistent AI memory
│ └── knowledge_store.py
│
├── ui/ # Streamlit Dashboard
│ ├── app.py
│ └── components.py
│
├── tests/ # Unit tests
│ ├── test_agent_decision.py
│ ├── test_url_analyzer.py
│ ├── test_password_checker.py
│ └── test_text_detector.py
│
└── docs/ # Documentation
├── architecture.md
├── api_endpoints.md
├── how_it_works.md
└── screenshots/



# 🚀 Getting Started

## 1️⃣ Create Virtual Environment

### Windows:
```bash
python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
```

Create .env:


OPENAI_API_KEY=sk-...
VT_API_KEY=VT-...
HIBP_API_KEY=

COMMON_PASSWORDS_FILE=./data/common-10000.txt

N8N_WEBHOOK_URL=http://localhost:5678/webhook/cybersec-assistant-webhook

SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASS=app_password
EMAIL_FROM=you@gmail.com
ALERT_EMAIL_TO=recipient@example.com

DATABASE_URL=sqlite:///./events.db
MEMORY_PATH=./memory_store.json

HOST=0.0.0.0
PORT=8000



### Run the Backend (FastAPI)

uvicorn main:app --reload
API will be live at:
http://localhost:8000

### Run the Dashboard (Streamlit)
streamlit run ui/app.py

Dashboard at:

http://localhost:8501

 ### 📸Screenshots (Add in docs/screenshots/)

Dashboard Home

Analyzer tools

Event logs

Risk trend chart

Memory viewer

n8n workflow

Architecture diagram

🏗️ Architecture

Full diagrams inside:

📄 docs/architecture.md
📄 docs/how_it_works.md

### Testing
pytest -q


❤️ Contributors

Pull requests and feature ideas are welcome!

⭐ Show Support

If this project helps you, consider starring the repo — it helps visibility!

🔐 Disclaimer

This tool is for research and educational purposes only.
Do not scan URLs or data you do not own or have permission to analyze.


---




