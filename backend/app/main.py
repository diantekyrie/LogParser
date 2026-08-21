from __future__ import annotations

from dotenv import load_dotenv

load_dotenv()  # picks up backend/.env (gitignored) for OPENAI_API_KEY / ANTHROPIC_API_KEY

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.db import init_db

app = FastAPI(title="ParseCat", description="Device log diagnosis API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/api/health")
def health():
    return {"status": "ok"}
