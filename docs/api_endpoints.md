```markdown
# 🌐 Cybersec Assistant — API Reference


---

# 🔎 **1. Health Check**

### `GET /`
**Response:**
```json
{"message": "Cybersec Assistant running"}
POST /analyze/url

Request:

{
  "url": "http://example.com"
}


Response (example):

{
  "malicious_votes": 1,
  "suspicious_votes": 0,
  "risk_score": 30
}

🔎 3. Password Analysis
POST /analyze/password

Request:

{
  "password": "mypassword"
}


Response:

{
  "entropy_bits": 34.5,
  "pwned_count": 0,
  "compromised": false,
  "strength": "reasonable",
  "risk_score": 40
}

🔎 4. Text Analysis
POST /analyze/text

Request:

{
  "text": "Click here to verify your account..."
}

🔎 5. Multi-Agent Decision Route
POST /agent/route

This is the main endpoint.
It triggers:

Analyzer agent

Decision agent

Database logging

Memory update

Responders (Slack, Email, n8n)

URL Example

Request:

{
  "type": "url",
  "url": "http://malicious.test"
}


Response:

{
  "type": "url",
  "combined_score": 85,
  "action": "alert",
  "reason": "High malicious score",
  "analyzer": {...}
}

🔐 Authentication

Currently none (development only).
Production recommendations:

Bearer tokens

API gateway

Rate limit