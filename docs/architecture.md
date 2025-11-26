# 🛡️ Cybersec Assistant — System Architecture

This document explains the architecture of the Cybersec Assistant, an agentic AI-powered cybersecurity analysis and automation system.

---

# 🔷 High-Level Overview

User Input
↓
Analyzer Agent (URL/Password/Text)
↓
Decision Agent (Threat Score + Reasoning)
↓
Responder Layer (n8n, Slack, Email, DB)
↓
Memory Module (Short-term + Long-term patterns)
↓
Dashboard (Streamlit UI)



---

# 🧩 Components Overview

## 1. **Analyzer Agents**
These modules scan different input types:

### ✔ URL Analyzer
- Uses **VirusTotal v3 API**
- Polling + rate-limit safe
- Computes normalized risk score (0–100)

### ✔ Password Analyzer
- Uses HIBP k-anonymity (free)
- Entropy calculation
- Common password detection
- Risk scoring logic

### ✔ Text Analyzer
- GPT-based phishing/malware classifier
- Returns label, reason, and risk score

---

## 2. **Decision Agent**
The “brain” of the system.

Responsibilities:
- Combine the analyzers’ output
- Apply reasoning rules (LLM or heuristics)
- Generate:
  - `action` → `alert`, `log`, or `ignore`
  - `combined_score` (0–100)
  - Natural-language explanation

---

## 3. **Responder Layer**
Triggered when `action == alert`.

Includes:
- **n8n Workflow Webhook**
  - Slack notifications
  - Email alerts
  - Log to Google Sheets / DB
- **Slack Messaging**
- **Email Sender**
- **SQLite Event Logger**

Uses background tasks so API stays fast.

---

## 4. **Memory System**
Persistent memory that helps the agent evolve.

### **Short-term (30 events)**
- Last incidents (quick lookup)

### **Long-term**
- Total events
- Average threat score
- Malicious URL frequency
- Password strength patterns
- Embedding-based similarity search (optional)

File-backed (`memory_store.json`).

---

## 5. **UI Dashboard (Streamlit)**
Visual interface showing:
- Live analysis tools
- Event logs
- Threat score trend charts
- Memory insights
- Similar phishing detection

---

# 🧭 Full Architecture Diagram (Mermaid)

```mermaid
flowchart TD

User[User Input] --> API[FastAPI Backend]

API --> Analyzer[Analyzer Agents]
Analyzer --> Decision[Decision Agent]

Decision -->|action=alert| Responder[Responders (n8n / Slack / Email / DB)]
Decision --> Memory[Memory Store]

Memory --> UI[Streamlit Dashboard]
Responder --> UI
DB[(SQLite DB)] --> UI


🏗️ Deployment Overview

Backend: FastAPI + Uvicorn

Frontend: Streamlit

Automation: n8n

Database: SQLite (can upgrade to PostgreSQL)

Memory: JSON file (upgradeable to Redis / Vector DB)

📌 Notes for Resume / Pitch

Use this paragraph in your resume:

Designed and built an agentic AI cyberdefense system integrating VirusTotal, OpenAI LLMs, n8n automation, and a multi-layer responder architecture. Implemented a memory system enabling evolving threat patterns and similarity detection. Delivered a full dashboard, API suite, and modular security agents.






