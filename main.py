from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from sqlalchemy import desc

from models.schema import EventIn, HostActionRequest
from models.db_models import Base, Event, Incident, Asset
from database import engine, get_db
from websocket_manager import manager
from response_action import isolate_host, restore_host

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SentinelX Backend")


# ---------------- EVENTS ----------------

@app.post("/events")
async def ingest_event(event: EventIn, db: Session = Depends(get_db)):
    db_event = Event(
        id=event.event_id,
        timestamp=event.timestamp,
        source_type=event.source_type,
        host_id=event.host_id,
        user_id=event.user_id,
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        src_port=event.src_port,
        dst_port=event.dst_port,
        protocol=event.protocol,
        event_type=event.event_type,
        severity=event.severity,
        features=event.features,
        raw_data=event.raw_data,
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    # Push straight to any connected dashboards (Rohan's frontend)
    await manager.broadcast({"type": "event", "data": event.dict(default=str)})

    return {"status": "ok", "event_id": str(event.event_id)}


@app.get("/events")
def list_events(limit: int = 100, db: Session = Depends(get_db)):
    return db.query(Event).order_by(desc(Event.timestamp)).limit(limit).all()


# ---------------- INCIDENTS ----------------
# Note: Incident rows are expected to be written by the correlation/risk-engine
# teammate (using the same Incident model above). This just exposes them.

@app.get("/incidents")
def list_incidents(limit: int = 50, db: Session = Depends(get_db)):
    return db.query(Incident).order_by(desc(Incident.created_at)).limit(limit).all()


# ---------------- ASSETS ----------------

@app.get("/assets")
def list_assets(db: Session = Depends(get_db)):
    return db.query(Asset).all()


# ---------------- RESPONSE ACTIONS ----------------

@app.post("/actions/isolate")
async def isolate(request: HostActionRequest, db: Session = Depends(get_db)):
    result = isolate_host(request.container_name)

    if result.get("status") == "isolated":
        asset = db.query(Asset).filter(Asset.hostname == request.container_name).first()
        if asset:
            asset.status = "isolated"
            db.commit()
        await manager.broadcast({"type": "action", "data": result})

    return result


@app.post("/actions/restore")
async def restore(request: HostActionRequest, db: Session = Depends(get_db)):
    if not request.network_name:
        return {"status": "error", "detail": "network_name is required to restore"}

    result = restore_host(request.container_name, request.network_name)

    if result.get("status") == "restored":
        asset = db.query(Asset).filter(Asset.hostname == request.container_name).first()
        if asset:
            asset.status = "normal"
            db.commit()
        await manager.broadcast({"type": "action", "data": result})

    return result


# ---------------- WEBSOCKET ----------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # dashboard doesn't need to send anything — this just keeps the connection open
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
