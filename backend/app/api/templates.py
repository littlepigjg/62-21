import uuid
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Header
from datetime import datetime

from ..models import TemplateCreateRequest, TemplateUpdateRequest, AuditOperation
from ..core.template import template_manager, ScriptTemplate
from ..core.audit_storage import audit_storage
from ..core.audit_detector import audit_detector

router = APIRouter(prefix="/templates", tags=["Templates"])


def _record_audit_operation(
    operation_type: str,
    detail: dict,
    target: Optional[str] = None,
    target_id: Optional[str] = None,
    x_audit_session: Optional[str] = None,
    x_audit_user_id: Optional[str] = None,
    x_audit_user_name: Optional[str] = None,
) -> None:
    try:
        session_id = x_audit_session or f"api-sess-{uuid.uuid4().hex[:12]}"
        user_id = x_audit_user_id or "system"
        user_name = x_audit_user_name or "system"

        op = AuditOperation(
            id=f"op-{uuid.uuid4().hex[:16]}",
            session_id=session_id,
            user_id=user_id,
            user_name=user_name,
            operation_type=operation_type,
            timestamp=datetime.now().isoformat(),
            target=target,
            target_id=target_id,
            detail=detail,
            page="api",
            component="templates",
            result="success",
        )
        saved_op = audit_storage.save_operation(op)
        audit_detector.process_operation(saved_op)
    except Exception:
        pass


def _template_to_response(t: ScriptTemplate) -> dict:
    return t.to_dict()


@router.get("")
async def list_templates(tag: Optional[str] = Query(None), keyword: Optional[str] = Query(None)):
    templates = template_manager.list_templates(tag=tag, keyword=keyword)
    return [_template_to_response(t) for t in templates]


@router.get("/tags")
async def list_tags():
    return template_manager.get_all_tags()


@router.get("/{template_id}")
async def get_template(template_id: str):
    t = template_manager.get_template(template_id)
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    return _template_to_response(t)


@router.post("", status_code=201)
async def create_template(
    req: TemplateCreateRequest,
    x_audit_session: Optional[str] = Header(None),
    x_audit_user_id: Optional[str] = Header(None),
    x_audit_user_name: Optional[str] = Header(None),
):
    t = template_manager.create_template(
        name=req.name,
        script_content=req.script_content,
        description=req.description or "",
        interpreter=req.interpreter,
        tags=req.tags,
    )

    _record_audit_operation(
        operation_type="template_create",
        detail={
            "name": req.name,
            "description": req.description,
            "interpreter": req.interpreter,
            "tags": req.tags,
            "script_content_length": len(req.script_content),
        },
        target="template",
        target_id=t.id,
        x_audit_session=x_audit_session,
        x_audit_user_id=x_audit_user_id,
        x_audit_user_name=x_audit_user_name,
    )

    return _template_to_response(t)


@router.put("/{template_id}")
async def update_template(
    template_id: str,
    req: TemplateUpdateRequest,
    x_audit_session: Optional[str] = Header(None),
    x_audit_user_id: Optional[str] = Header(None),
    x_audit_user_name: Optional[str] = Header(None),
):
    update_kwargs = req.model_dump(exclude_unset=True)
    t = template_manager.update_template(template_id, **update_kwargs)
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")

    _record_audit_operation(
        operation_type="template_update",
        detail=update_kwargs,
        target="template",
        target_id=template_id,
        x_audit_session=x_audit_session,
        x_audit_user_id=x_audit_user_id,
        x_audit_user_name=x_audit_user_name,
    )

    return _template_to_response(t)


@router.delete("/{template_id}")
async def delete_template(
    template_id: str,
    x_audit_session: Optional[str] = Header(None),
    x_audit_user_id: Optional[str] = Header(None),
    x_audit_user_name: Optional[str] = Header(None),
):
    t = template_manager.get_template(template_id)
    if not template_manager.delete_template(template_id):
        raise HTTPException(status_code=404, detail="Template not found")

    _record_audit_operation(
        operation_type="template_delete",
        detail={
            "template_name": t.name if t else "",
        },
        target="template",
        target_id=template_id,
        x_audit_session=x_audit_session,
        x_audit_user_id=x_audit_user_id,
        x_audit_user_name=x_audit_user_name,
    )

    return {"message": "Template deleted successfully"}
