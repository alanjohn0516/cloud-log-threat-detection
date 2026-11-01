# cloud/api.py
# FastAPI service: receives CloudTrail logs and serves them to other modules.
# Run:  uvicorn cloud.api:app --port 8000
from fastapi import Depends, FastAPI, Query
from pydantic import BaseModel

from cloud import database
from cloud.auth import require_api_key

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


@app.post("/logs", dependencies=[Depends(require_api_key)])
def ingest_logs(batch: LogBatch):
    """Store a batch of CloudTrail records. Returns how many were new."""
    return database.insert_records(batch.Records)


@app.get("/logs", dependencies=[Depends(require_api_key)])
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


@app.get("/stats", dependencies=[Depends(require_api_key)])
def stats():
    return database.get_stats()


# ---------------------------------------------------------------- Step 7
import json

from fastapi import HTTPException

from security import alert_store, pipeline


@app.post("/detect", dependencies=[Depends(require_api_key)])
def run_detection(policy: str = "ml", threshold: float = Query(0.5, ge=0.0, le=1.0)):
    """Run the full pipeline (features, ML + rules, incidents) on the stored logs
    and save the resulting alerts."""
    events = database.load_events_df()
    if events.empty:
        raise HTTPException(status_code=400, detail="No logs stored yet")
    try:
        alerts, _ = pipeline.detect(events, policy=policy, threshold=threshold)
    except FileNotFoundError as err:
        raise HTTPException(status_code=503, detail=str(err))
    except ValueError as err:
        raise HTTPException(status_code=422, detail=str(err))
    alert_store.save_alerts(alerts)
    return {
        "policy": policy,
        "events_analysed": int(len(events)),
        "alerts_raised": int(len(alerts)),
        "by_severity": {k: int(v) for k, v in alerts["severity"].value_counts().items()},
    }


@app.get("/alerts", dependencies=[Depends(require_api_key)])
def list_alerts(severity: str | None = None, attack_type: str | None = None,
                limit: int = Query(500, ge=1, le=5000)):
    """Alerts produced by the last detection run."""
    df = alert_store.load_alerts()
    if severity:
        df = df[df["severity"] == severity.upper()]
    if attack_type:
        df = df[df["attack_type"] == attack_type]
    df = df.drop(columns=["event_ids"]).head(limit)
    return {"count": int(len(df)), "alerts": json.loads(df.to_json(orient="records"))}
