
Paste:

```markdown
# ⚙️ How the Cybersec Assistant Works

This document explains the internal flow step-by-step.

---

# 1️⃣ Step 1 — User Input

User provides:
- URL  
- Password  
- Text message  

Either through:
- REST API  
- Streamlit Dashboard  
- JSON payload via `/agent/route`

---

# 2️⃣ Step 2 — Analyzer Agent

Three analyzers run depending on the input type:

## URL Analyzer
1. URL → Base64 → VirusTotal API  
2. Poll analysis ID  
3. Parse engine verdicts  
4. Compute normalized risk score  
5. Return structured output

## Password Analyzer
1. Compute SHA1  
2. Query HIBP k-anonymity (free)  
3. Check entropy and common-password list  
4. Build risk score

## Text Analyzer
1. Send text to OpenAI  
2. Classify:
   - phishing  
   - malware  
   - spam  
   - safe  
3. Generate reasoning

---

# 3️⃣ Step 3 — Decision Agent

Based on analyzer results:
- Combine risk_score + context  
- Apply thresholds:
  - `>70` → alert  
  - `30–70` → log  
  - `<30` → ignore  
- Add LLM reasoning (optional)  
- Build final decision JSON

---

# 4️⃣ Step 4 — Responder Layer

If `action = alert`, we execute responders:

### ✔ n8n Webhook  
Triggers a workflow:
- Slack alert  
- Email alert  
- Row added to Google Sheet / DB  

### ✔ Slack Webhook  
Sends a formatted security alert.

### ✔ Email responder  
Sends structured email with incident summary.

### ✔ DB Logger  
Stores incident with timestamp and JSON payload.

---

# 5️⃣ Step 5 — Memory System

Two levels:

## Short-Term Memory
- Stores last 30 events
- Used for quick lookup
- Supports similarity search

## Long-Term Memory
- Tracks:
  - total events  
  - average risk  
  - malicious URL frequency  
  - password weaknesses  

All persisted to `memory_store.json`.

---

# 6️⃣ Step 6 — Dashboard

Streamlit UI displays:
- Real-time analysis
- Event logs
- Trend charts
- Memory insights
- Similar past events (embedding search)

---

# 🏁 Summary

This system behaves like a full **AI SOC Assistant**:
- Multi-modal analysis
- Autonomous decision-making
- Automated responders
- Evolving memory
- Real-time dashboard
- Production-ready API

---

# End of How It Works Document
