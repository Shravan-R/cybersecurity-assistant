# main.py
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
import uvicorn
from typing import Any

from config.settings import settings

# AI agents
from ai_agent.url_analyzer import UrlAnalyzer
from ai_agent.password_checker import PasswordChecker
from ai_agent.text_detector import TextDetector
from ai_agent.agent_decision import AgentDecision

# Responders
from responders.db_logger import DBLogger
from responders.n8n_webhook import N8NResponder
from responders.slack_alert import SlackAlert
from responders.email_alert import EmailAlert

# Memory
from memory.knowledge_store import KnowledgeStore

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cybersec-assistant")

# ---------- FastAPI app ----------
app = FastAPI(title="Cybersec Assistant API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Instantiate components ----------
url_analyzer = UrlAnalyzer()
password_checker = PasswordChecker()
text_detector = TextDetector()
decision_agent = AgentDecision()

db_logger = DBLogger(settings.DATABASE_URL)
n8n_responder = N8NResponder(settings.N8N_WEBHOOK_URL)

slack_responder = SlackAlert(getattr(settings, "SLACK_WEBHOOK_URL", None))
email_responder = EmailAlert(
    smtp_host=getattr(settings, "SMTP_HOST", None) or "",
    smtp_port=getattr(settings, "SMTP_PORT", 587),
    smtp_user=getattr(settings, "SMTP_USER", None),
    smtp_pass=getattr(settings, "SMTP_PASS", None),
    from_addr=getattr(settings, "EMAIL_FROM", None),
)

memory_store = KnowledgeStore(getattr(settings, "MEMORY_PATH", "./memory_store.json"))

# ---------- Pydantic request models ----------
class URLIn(BaseModel):
    url: str

class PasswordIn(BaseModel):
    password: str

class TextIn(BaseModel):
    text: str

# ---------- Background responders ----------
def _bg_send_responders(decision: dict) -> None:
    """
    Synchronous background worker that calls responders.
    It will:
      - post to Slack (sync)
      - send email (sync)
      - call n8n webhook (async, run via new event loop)
    """
    try:
        # Slack
        try:
            if getattr(slack_responder, "webhook_url", None):
                slack_text = f"Cybersec Alert — type={decision.get('type')} action={decision.get('action')} score={decision.get('combined_score')} reason={decision.get('reason')}"
                slack_responder.post_message(slack_text)
        except Exception as e:
            logger.warning("Slack responder failed: %s", e)

        # Email
        try:
            if getattr(email_responder, "smtp_host", None):
                if decision.get("action") == "alert":
                    to = getattr(settings, "ALERT_EMAIL_TO", None)
                    if to:
                        subject = f"[Cybersec Assistant] {decision.get('type')} {decision.get('action')}"
                        body = str(decision)
                        email_responder.send_email(to, subject, body)
        except Exception as e:
            logger.warning("Email responder failed: %s", e)

        # n8n webhook (async)
        try:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            res = loop.run_until_complete(n8n_responder.trigger_workflow(decision))
            logger.info("n8n responder result: %s", res)
            loop.close()
        except Exception as e:
            logger.warning("n8n responder failed: %s", e)

    except Exception as e:
        logger.exception("Background responders encountered an error: %s", e)


# ---------- Root ----------
@app.get("/")
def root():
    return {"message": "Cybersec Assistant running"}


# ---------- Analyzer endpoints ----------
@app.post("/analyze/url")
async def analyze_url(payload: URLIn):
    try:
        # safe fallback if no VT key is configured may be implemented in analyzer
        result = await url_analyzer.scan_url(payload.url)
        return result
    except Exception as e:
        logger.exception("analyze_url error")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/password")
def analyze_password(payload: PasswordIn):
    try:
        result = password_checker.check_password(payload.password)
        return result
    except Exception as e:
        logger.exception("analyze_password error")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/text")
async def analyze_text(payload: TextIn):
    try:
        result = await text_detector.analyze_text(payload.text)
        return result
    except Exception as e:
        logger.exception("analyze_text error")
        raise HTTPException(status_code=500, detail=str(e))


# ---------- Agent routing endpoint ----------
@app.post("/agent/route")
async def agent_route(body: dict, background_tasks: BackgroundTasks):
    """
    Accepts JSON with 'type' in ('url','password','text') and corresponding field.
    Example:
      {"type":"url","url":"http://example.com"}
    """
    try:
        decision: dict = await decision_agent.route_and_decide(body)

        # 1) log to DB (best-effort)
        try:
            db_logger.log_event(decision)
        except Exception as e:
            logger.warning("DB logging failed: %s", e)

        # 2) remember in memory (best-effort)
        try:
            if hasattr(memory_store, "remember_event"):
                memory_store.remember_event(decision)
        except Exception as e:
            logger.warning("Memory store failed: %s", e)

        # 3) trigger responders asynchronously if alert
        if decision.get("action") == "alert":
            background_tasks.add_task(_bg_send_responders, decision)

        return decision
    except Exception as e:
        logger.exception("agent_route error")
        raise HTTPException(status_code=500, detail=str(e))


# ---------- Events endpoints (DB-backed) ----------
@app.get("/events")
def get_events(limit: int = 20):
    try:
        events = db_logger.get_last_events(limit)
        return events
    except Exception as e:
        logger.exception("get_events error")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/events/{event_id}")
def get_event(event_id: int):
    try:
        ev = db_logger.get_event(event_id)
        if not ev:
            raise HTTPException(status_code=404, detail="Event not found")
        return ev
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("get_event error")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/events/{event_id}")
def delete_event(event_id: int):
    try:
        ok = db_logger.delete_event(event_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Event not found")
        return {"deleted": event_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("delete_event error")
        raise HTTPException(status_code=500, detail=str(e))


# ---------- Memory endpoints ----------
@app.get("/memory")
def read_memory():
    try:
        if hasattr(memory_store, "read"):
            return memory_store.read()
        # fallback: return last events if read not implemented
        return {"last_events": memory_store.last_events(10) if hasattr(memory_store, "last_events") else []}
    except Exception as e:
        logger.exception("read_memory error")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/memory")
def write_memory(payload: dict):
    try:
        if hasattr(memory_store, "write"):
            memory_store.write(payload)
            return {"status": "stored", "data": payload}
        raise HTTPException(status_code=501, detail="Memory write not implemented")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("write_memory error")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/memory")
def clear_memory():
    try:
        if hasattr(memory_store, "clear"):
            memory_store.clear()
            return {"status": "memory cleared"}
        raise HTTPException(status_code=501, detail="Memory clear not implemented")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("clear_memory error")
        raise HTTPException(status_code=500, detail=str(e))


# ---------- Run ----------
if __name__ == "__main__":
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=True)
