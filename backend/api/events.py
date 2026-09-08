from fastapi import APIRouter, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.api.schemas import BaselineRequest, EventCreate
from backend.database.connection import SessionLocal
from backend.models.event import Event
from backend.services.detection_service import detection_service


router = APIRouter(
    prefix="/events",
    tags=["Events"],
)


@router.post("/baseline")
def train_baseline(request: BaselineRequest):
    try:
        events = [
            event.model_dump()
            for event in request.events
        ]

        detection_service.train_baseline(events)

        return {
            "status": "trained",
            "baseline_events": len(events),
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@router.post("")
def ingest_event(event: EventCreate):
    if not detection_service.is_trained:
        raise HTTPException(
            status_code=503,
            detail="Detection engine is not trained. Submit baseline events first.",
        )

    event_data = event.model_dump()

    try:
        detection_result = detection_service.detect(event_data)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    db: Session = SessionLocal()

    try:
        database_event = Event(
            event_id=event_data["event_id"],
            source_type=event_data["source_type"],
            host_id=event_data["host_id"],
            user_id=event_data.get("user_id"),
            src_ip=event_data.get("src_ip"),
            dst_ip=event_data.get("dst_ip"),
            src_port=event_data.get("src_port"),
            dst_port=event_data.get("dst_port"),
            protocol=event_data.get("protocol"),
            event_type=event_data["event_type"],
            severity=event_data.get("severity"),
            features=detection_result["features"],
            raw_data=event_data.get("raw_data"),
            anomaly_score=detection_result["anomaly_score"],
            rule_score=detection_result["rule_score"],
            detected=int(detection_result["detected"]),
        )

        db.add(database_event)
        db.commit()
        db.refresh(database_event)

        return {
            "status": "processed",
            "detection": detection_result,
        }

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail=f"Event {event_data['event_id']} already exists",
        )

    finally:
        db.close()
