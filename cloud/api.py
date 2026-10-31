# cloud/api.py
# FastAPI service: receives CloudTrail logs and serves them to other modules.
# Run:  uvicorn cloud.api:app --port 8000
from fastapi import FastAPI, Query
from pydantic import BaseModel

from cloud import database

app = FastAPI(
    title="Cloud Log API",
    version="1.0",
    description="Collects AWS CloudTrail events (ConsoleLogin, AssumeRole) and serves them.",
)


class LogBatch(BaseModel):
    """Same shape as a CloudTrail log file: {"Records": [ ... ]}"""
    Records: list[dict]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/logs")
def ingest_logs(batch: LogBatch):
    """Store a batch of CloudTrail records. Returns how many were new."""
    return database.insert_records(batch.Records)


@app.get("/logs")
def list_logs(
    event_name: str | None = None,
    outcome: str | None = None,
    source_ip: str | None = None,
    user_name: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Search stored events. start/end look like 2026-09-01T10:00:00Z."""
    events = database.query_events(
        event_name=event_name, outcome=outcome, source_ip=source_ip,
        user_name=user_name, start=start, end=end, limit=limit, offset=offset,
    )
    return {"count": len(events), "events": events}


@app.get("/stats")
def stats():
    return database.get_stats()
