# main.py
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import logging

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

# ---------- Setup logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cybersec-assistant")

# ---------- FastAPI app ----------
app = FastAPI(title="Cybersec Assistant API")

# allow CORS for localhost/dev (adjust origins in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- instantiate global components ----------
url_analyzer = UrlAnalyzer()
password_checker = PasswordChecker()
text_detector = TextDetector()
decision_agent = AgentDecision()

db_logger = DBLogger(settings.DATABASE_URL)
# n8n responder expects an async trigger_workflow method
n8n_responder = N8NResponder(settings.N8N_WEBHOOK_URL)

# optional: Slack / Email (configure via env)
slack_responder = SlackAlert(getattr(settings, "SLACK_WEBHOOK_URL", None))
email_responder = EmailAlert(
    smtp_host=getattr(settings, "SMTP_HOST", None) or "",
    smtp_port=getattr(settings, "SMTP_PORT", 587),
    smtp_user=getattr(settings, "SMTP_USER", None),
    smtp_pass=getattr(settings, "SMTP_PASS", None),
    from_addr=getattr(settings, "EMAIL_FROM", None),
)

# memory store (file-backed)
memory = KnowledgeStore(file_path=getattr(settings, "MEMORY_PATH", "./memory_store.json"))

# ---------- Request models ----------
class URLIn(BaseModel):
    url: str

class PasswordIn(BaseModel):
    password: str

class TextIn(BaseModel):
    text: str

# ---------- Helper: Background task to call responders ----------
def _bg_send_responders(decision: dict):
    """
    synchronous wrapper executed in background thread by FastAPI.
    Calls synchronous responders (Slack, Email) and also awaits async ones by running an event loop.
    """
    try:
        # log to Slack (synchronous requests-based SlackAlert)
        try:
            if getattr(slack_responder, "webhook_url", None):
                slack_text = f"Cybersec Alert: type={decision.get('type')} action={decision.get('action')} score={decision.get('combined_score')} reason={decision.get('reason')}"
                slack_responder.post_message(slack_text)
        except Exception as e:
            logger.warning("Slack responder failed: %s", e)

        # send email if desired (synchronous)
        try:
            if getattr(email_responder, "smtp_host", None):
                # you can set rules for when to email (e.g., action == alert)
                if decision.get("action") == "alert":
                    to = getattr(settings, "ALERT_EMAIL_TO", None)
                    if to:
                        subject = f"[Cybersec Assistant] {decision.get('type')} {decision.get('action')}"
                        body = str(decision)
                        email_responder.send_email(to, subject, body)
        except Exception as e:
            logger.warning("Email responder failed: %s", e)

        # call async n8n responder by running an event loop
        try:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(n8n_responder.trigger_workflow(decision))
            logger.info("n8n responder result: %s", result)
            loop.close()
        except Exception as e:
            logger.warning("n8n responder failed: %s", e)

    except Exception as e:
        logger.exception("Background responders encountered an error: %s", e)


# ---------- Endpoints ----------
@app.get("/")
def root():
    return {"message": "Cybersec Assistant running"}

@app.post("/analyze/url")
async def analyze_url(payload: URLIn):
    try:
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

@app.post("/agent/route")
async def agent_route(body: dict, background_tasks: BackgroundTasks):
    """
    Accepts JSON with 'type' in ('url','password','text') and corresponding field.
    Example: {"type":"url","url":"http://example.com"}
    """
    try:
        decision = await decision_agent.route_and_decide(body)
        # 1) log to DB
        try:
            db_logger.log_event(decision)
        except Exception as e:
            logger.warning("DB log failed: %s", e)

        # 2) remember in memory
        try:
            memory.remember_event(decision)
        except Exception as e:
            logger.warning("Memory store failed: %s", e)

        # 3) if action == alert, trigger responders asynchronously in the background
        if decision.get("action") == "alert":
            background_tasks.add_task(_bg_send_responders, decision)

        # return the decision immediately
        return decision
    except Exception as e:
        logger.exception("agent_route error")
        raise HTTPException(status_code=500, detail=str(e))


# ---------- Run ----------
if __name__ == "__main__":
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=True)
