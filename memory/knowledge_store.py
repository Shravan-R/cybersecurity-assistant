# memory/knowledge_store.py
"""
KnowledgeStore: A hybrid short-term + long-term memory layer for the Cybersec Assistant.

Purpose:
- Store recent events (last N)
- Aggregate patterns over time (risk averages, frequent malicious URLs, common password weaknesses)
- Provide similarity lookup via embeddings (optional)
- Update stored knowledge after each incident (simple learning)

This makes your agent look agentic + evolving over time.
"""

import json
import os
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from config.settings import settings

try:
    import openai
    openai.api_key = settings.OPENAI_API_KEY
    OPENAI_AVAILABLE = True
except Exception:
    OPENAI_AVAILABLE = False


class KnowledgeStore:
    """
    File-backed memory system.
    Structure in memory_store.json:
    {
        "short_term": [ {event}, {event}, ... ],
        "long_term": {
            "total_events": int,
            "avg_risk_score": float,
            "top_malicious_urls": {url: count},
            "password_weakness": { "very_weak": count, "weak": count, ... }
        }
    }
    """

    def __init__(self, file_path: str = "./memory_store.json", short_term_limit: int = 30):
        self.file_path = Path(file_path)
        self.short_term_limit = short_term_limit

        if not self.file_path.exists():
            self._init_store()

        self._load()

    # ---------------------------------------------------------
    # Initialization
    # ---------------------------------------------------------
    def _init_store(self):
        data = {
            "short_term": [],
            "long_term": {
                "total_events": 0,
                "avg_risk_score": 0.0,
                "top_malicious_urls": {},
                "password_weakness": {
                    "very_weak": 0,
                    "weak": 0,
                    "reasonable": 0,
                    "strong": 0
                }
            }
        }
        self._save_data(data)

    def _load(self):
        with open(self.file_path, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def _save(self):
        self._save_data(self.data)

    def _save_data(self, data: dict):
        with open(self.file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    # ---------------------------------------------------------
    # ADD EVENT TO MEMORY
    # ---------------------------------------------------------
    def remember_event(self, event: Dict[str, Any]):
        """
        Called after Decision Agent choice.
        Stores event in short-term memory and updates long-term stats.
        """
        # ---- Short-term memory ----
        self.data["short_term"].append(event)
        if len(self.data["short_term"]) > self.short_term_limit:
            self.data["short_term"] = self.data["short_term"][-self.short_term_limit:]

        # ---- Long-term memory ----
        self._update_long_term(event)

        # save to disk
        self._save()

    # ---------------------------------------------------------
    # Long-Term Memory Updating
    # ---------------------------------------------------------
    def _update_long_term(self, event: Dict[str, Any]):
        lt = self.data["long_term"]

        # update count
        lt["total_events"] += 1

        # update avg risk score
        score = int(event.get("combined_score", 0))
        prev_avg = lt["avg_risk_score"]
        n = lt["total_events"]
        lt["avg_risk_score"] = ((prev_avg * (n - 1)) + score) / n

        # update malicious URLs
        if event.get("type") == "url":
            url = event.get("input")
            if url:
                lt["top_malicious_urls"][url] = lt["top_malicious_urls"].get(url, 0) + 1

        # update password stats
        if event.get("type") == "password":
            analy = event.get("analyzer", {})
            strength = analy.get("strength", "unknown")
            if strength in lt["password_weakness"]:
                lt["password_weakness"][strength] += 1

    # ---------------------------------------------------------
    # RECALL
    # ---------------------------------------------------------
    def last_events(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Return last N events."""
        return self.data["short_term"][-limit:]

    def summary(self) -> Dict[str, Any]:
        """Return long-term statistics."""
        return self.data["long_term"]

    # ---------------------------------------------------------
    # OPTIONAL — Embedding similarity search
    # ---------------------------------------------------------
    def find_similar_events(self, query_text: str, top_k: int = 3):
        """
        Uses OpenAI embeddings to match previous text-based events.
        If no OpenAI key, returns empty list.
        """
        if not OPENAI_AVAILABLE:
            return {"error": "OpenAI embeddings unavailable"}

        # gather text-based events only
        text_events = [ev for ev in self.data["short_term"] if ev.get("type") == "text"]
        if not text_events:
            return []

        # embed query
        query_vec = self._embed(query_text)

        # score events by cosine similarity
        scored = []
        for ev in text_events:
            analyzer = ev.get("analyzer", {})
            txt = analyzer.get("reason") or ""
            emb = self._embed(txt)
            score = self._cosine_similarity(query_vec, emb)
            scored.append({"event": ev, "score": score})

        # sort by similarity
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]

    # ---------------------------------------------------------
    # Helpers for embeddings
    # ---------------------------------------------------------
    def _embed(self, text: str) -> List[float]:
        res = openai.Embedding.create(model="text-embedding-3-small", input=text)
        return res["data"][0]["embedding"]

    def _cosine_similarity(self, a: List[float], b: List[float]):
        import math
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)
