import uuid
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Body
from datetime import datetime

from ..models import (
    AuditSession,
    AuditOperation,
    OperationRecordingRequest,
    RecordingFrame,
    RecordingSession,
    RecordingSessionRequest,
    AuditAlert,
    AuditAlertQuery,
    AlertRule,
    AuditQuery,
    AuditStats,
)
from ..core.audit_storage import audit_storage
from ..core.audit_detector import audit_detector

router = APIRouter(prefix="/audit", tags=["Audit"])


def _make_operation(
    session_id: str,
    user_id: str,
    user_name: str,
    operation_type: str,
    target: Optional[str] = None,
    target_id: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
    page: str = "",
    component: str = "",
    client_ip: str = "",
    user_agent: str = "",
) -> AuditOperation:
    return AuditOperation(
        id=f"op-{uuid.uuid4().hex[:16]}",
        session_id=session_id,
        user_id=user_id,
        user_name=user_name,
        operation_type=operation_type,
        timestamp=datetime.now().isoformat(),
        target=target,
        target_id=target_id,
        detail=detail or {},
        client_ip=client_ip,
        user_agent=user_agent,
        page=page,
        component=component,
        result="success",
    )


@router.post("/sessions", response_model=AuditSession, status_code=201)
async def create_session(
    user_id: str = Body(..., embed=True),
    user_name: str = Body(..., embed=True),
    client_ip: str = Body("", embed=True),
    user_agent: str = Body("", embed=True),
):
    session = AuditSession(
        session_id=f"sess-{uuid.uuid4().hex[:16]}",
        user_id=user_id,
        user_name=user_name,
        client_ip=client_ip,
        user_agent=user_agent,
        start_time=datetime.now().isoformat(),
        status="active",
    )
    return audit_storage.create_session(session)


@router.put("/sessions/{session_id}/end", response_model=AuditSession)
async def end_session(session_id: str):
    session = audit_storage.end_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.get("/sessions", response_model=List[AuditSession])
async def list_sessions(user_id: Optional[str] = None, limit: int = 100):
    return audit_storage.list_sessions(user_id=user_id, limit=limit)


@router.get("/sessions/{session_id}", response_model=AuditSession)
async def get_session(session_id: str):
    session = audit_storage.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.post("/operations", status_code=201)
async def record_operations(req: OperationRecordingRequest):
    saved_ops: List[AuditOperation] = []
    all_alerts: List[AuditAlert] = []

    for op in req.operations:
        if not op.id:
            op.id = f"op-{uuid.uuid4().hex[:16]}"
        if not op.timestamp:
            op.timestamp = datetime.now().isoformat()
        saved = audit_storage.save_operation(op)
        saved_ops.append(saved)
        alerts = audit_detector.process_operation(saved)
        all_alerts.extend(alerts)

    session = audit_storage.get_session(req.session_id)
    if session:
        session.operation_count += len(saved_ops)
        sessions = audit_storage._load_sessions()
        for i, s in enumerate(sessions):
            if s["session_id"] == req.session_id:
                sessions[i]["operation_count"] = session.operation_count
                break
        audit_storage._save_sessions(sessions)

    return {
        "saved": len(saved_ops),
        "operations": [op.model_dump() for op in saved_ops],
        "alerts_triggered": len(all_alerts),
        "alerts": [a.model_dump() for a in all_alerts],
    }


@router.post("/operations/query")
async def query_operations(query: AuditQuery):
    return audit_storage.query_operations(query)


@router.post("/recordings/frames", status_code=201)
async def save_recording_frames(req: RecordingSessionRequest):
    session = audit_storage.save_recording_frames(req)
    return session.model_dump()


@router.get("/recordings/sessions", response_model=List[RecordingSession])
async def list_recording_sessions(user_id: Optional[str] = None, limit: int = 50):
    return audit_storage.list_recording_sessions(user_id=user_id, limit=limit)


@router.get("/recordings/sessions/{session_id}", response_model=RecordingSession)
async def get_recording_session(session_id: str):
    session = audit_storage.get_recording_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Recording session not found")
    return session


@router.get("/recordings/sessions/{session_id}/frames")
async def get_recording_frames(
    session_id: str,
    start_index: int = 0,
    end_index: Optional[int] = None,
    keyframes_only: bool = False,
):
    frames = audit_storage.get_recording_frames(session_id, start_index, end_index)
    if keyframes_only:
        frames = [f for f in frames if f.is_keyframe]
    return {
        "total": len(frames),
        "frames": [f.model_dump() for f in frames],
    }


@router.get("/recordings/sessions/{session_id}/playback")
async def get_playback_data(session_id: str):
    session = audit_storage.get_recording_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Recording session not found")
    frames = audit_storage.get_recording_frames(session_id)
    op_query = AuditQuery(session_id=session_id, limit=10000)
    operations_result = audit_storage.query_operations(op_query)
    return {
        "session": session.model_dump(),
        "frames": [f.model_dump() for f in frames],
        "operations": operations_result.get("items", []),
    }


@router.get("/recordings/sessions/{session_id}/jump")
async def jump_to_frame(
    session_id: str,
    target_timestamp: int,
):
    frames = audit_storage.get_recording_frames(session_id)
    if not frames:
        raise HTTPException(status_code=404, detail="No frames found")

    target_frame = None
    target_index = 0
    for i, frame in enumerate(frames):
        if frame.timestamp >= target_timestamp:
            target_frame = frame
            target_index = i
            break
    if not target_frame:
        target_frame = frames[-1]
        target_index = len(frames) - 1

    prev_keyframe_idx = 0
    for i in range(target_index, -1, -1):
        if frames[i].is_keyframe:
            prev_keyframe_idx = i
            break

    frames_from_keyframe = [f.model_dump() for f in frames[prev_keyframe_idx:target_index + 1]]

    return {
        "target_index": target_index,
        "target_frame": target_frame.model_dump(),
        "keyframe_index": prev_keyframe_idx,
        "frames_from_keyframe": frames_from_keyframe,
    }


@router.post("/alerts/query")
async def query_alerts(query: AuditAlertQuery):
    return audit_storage.query_alerts(query)


@router.get("/alerts", response_model=List[AuditAlert])
async def list_alerts(
    alert_type: Optional[str] = None,
    severity: Optional[str] = None,
    user_id: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    limit: int = 100,
):
    query = AuditAlertQuery(
        alert_type=alert_type,
        severity=severity,
        user_id=user_id,
        acknowledged=acknowledged,
        limit=limit,
    )
    result = audit_storage.query_alerts(query)
    return [AuditAlert(**a) for a in result.get("items", [])]


@router.get("/alerts/{alert_id}", response_model=AuditAlert)
async def get_alert(alert_id: str):
    query = AuditAlertQuery(limit=1000)
    result = audit_storage.query_alerts(query)
    for item in result.get("items", []):
        if item.get("alert_id") == alert_id:
            return AuditAlert(**item)
    raise HTTPException(status_code=404, detail="Alert not found")


@router.put("/alerts/{alert_id}/acknowledge", response_model=AuditAlert)
async def acknowledge_alert(
    alert_id: str,
    user: str = Body(..., embed=True),
    notes: Optional[str] = Body(None, embed=True),
):
    alert = audit_storage.acknowledge_alert(alert_id, user, notes)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.get("/rules", response_model=List[AlertRule])
async def list_rules():
    return audit_storage.get_rules()


@router.put("/rules", response_model=AlertRule)
async def update_rule(rule: AlertRule):
    return audit_storage.update_rule(rule)


@router.get("/stats", response_model=AuditStats)
async def get_stats(days: int = 7):
    return audit_storage.compute_stats(days=days)


@router.get("/integrity/verify")
async def verify_integrity(date: Optional[str] = None):
    result = audit_storage.verify_integrity(date)
    return result
