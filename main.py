# main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from config.settings import settings
from ai_agent.url_analyzer import UrlAnalyzer
from ai_agent.password_checker import PasswordChecker
from ai_agent.text_detector import TextDetector
from ai_agent.agent_decision import AgentDecision
from responders.db_logger import DBLogger
from responders.n8n_webhook import N8NResponder

app = FastAPI(title="Cybersec Assistant API")

url_analyzer = UrlAnalyzer()
password_checker = PasswordChecker()
text_detector = TextDetector()
decision_agent = AgentDecision()
db_logger = DBLogger(settings.DATABASE_URL)
n8n_responder = N8NResponder(settings.N8N_WEBHOOK_URL)

class URLIn(BaseModel):
    url: str

class PasswordIn(BaseModel):
    password: str

class TextIn(BaseModel):
    text: str

@app.get("/")
def root():
    return {"message": "Cybersec Assistant running"}

@app.post("/analyze/url")
async def analyze_url(payload: URLIn):
    try:
        result = await url_analyzer.scan_url(payload.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/password")
async def analyze_password(payload: PasswordIn):
    try:
        result = password_checker.check_password(payload.password)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/text")
async def analyze_text(payload: TextIn):
    try:
        result = await text_detector.analyze_text(payload.text)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/agent/route")
async def agent_route(body: dict):
    """
    Accepts any input with keys: 'type' in ('url','password','text') and corresponding field.
    Example:
      {"type":"url","url":"http://example.com"}
    """
    try:
        decision = await decision_agent.route_and_decide(body)
        # log & optionally trigger responder
        db_logger.log_event(decision)
        if decision.get("action") == "alert":
            n8n_responder.trigger_workflow(decision)
        return decision
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=True)
