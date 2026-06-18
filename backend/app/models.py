from typing import List, Optional, Dict, Any, Literal
from datetime import datetime
from pydantic import BaseModel, Field


OperationType = Literal[
    "command_execute",
    "script_execute",
    "server_select",
    "server_deselect",
    "server_create",
    "server_update",
    "server_delete",
    "server_test",
    "template_create",
    "template_update",
    "template_delete",
    "template_execute",
    "tab_switch",
    "login",
    "logout",
    "session_start",
    "session_end",
    "page_view",
    "custom",
]

AlertType = Literal[
    "massive_deletion",
    "frequent_server_switch",
    "suspicious_command",
    "abnormal_execution_count",
    "off_hours_operation",
    "privilege_escalation_attempt",
    "tampering_detected",
]

AlertSeverity = Literal["low", "medium", "high", "critical"]


class AuditSession(BaseModel):
    session_id: str
    user_id: str
    user_name: str
    client_ip: str = ""
    user_agent: str = ""
    start_time: str = Field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None
    duration_ms: int = 0
    operation_count: int = 0
    status: str = "active"


class AuditOperation(BaseModel):
    id: str
    session_id: str
    user_id: str
    user_name: str
    operation_type: OperationType
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    target: Optional[str] = None
    target_id: Optional[str] = None
    detail: Dict[str, Any] = Field(default_factory=dict)
    client_ip: str = ""
    user_agent: str = ""
    page: str = ""
    component: str = ""
    result: str = "success"
    error_message: Optional[str] = None
    previous_hash: Optional[str] = None
    current_hash: str = ""


class OperationRecordingRequest(BaseModel):
    session_id: str
    operations: List[AuditOperation]


class RecordingFrame(BaseModel):
    frame_id: str
    timestamp: int
    type: str
    data: Dict[str, Any] = Field(default_factory=dict)
    is_keyframe: bool = False


class RecordingSession(BaseModel):
    session_id: str
    user_id: str
    user_name: str
    start_time: str
    end_time: Optional[str] = None
    total_frames: int = 0
    keyframe_indices: List[int] = Field(default_factory=list)
    duration_ms: int = 0


class RecordingSessionRequest(BaseModel):
    session_id: str
    user_id: str
    user_name: str
    frames: List[RecordingFrame]


class AlertRule(BaseModel):
    rule_id: str
    name: str
    alert_type: AlertType
    severity: AlertSeverity
    enabled: bool = True
    description: str = ""
    parameters: Dict[str, Any] = Field(default_factory=dict)


class AuditAlert(BaseModel):
    alert_id: str
    rule_id: str
    rule_name: str
    alert_type: AlertType
    severity: AlertSeverity
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    description: str = ""
    evidence: Dict[str, Any] = Field(default_factory=dict)
    operation_ids: List[str] = Field(default_factory=list)
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[str] = None
    notes: Optional[str] = None


class AuditAlertQuery(BaseModel):
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    alert_type: Optional[AlertType] = None
    severity: Optional[AlertSeverity] = None
    user_id: Optional[str] = None
    acknowledged: Optional[bool] = None
    limit: int = 100


class AuditQuery(BaseModel):
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    operation_type: Optional[OperationType] = None
    session_id: Optional[str] = None
    target: Optional[str] = None
    result: Optional[str] = None
    keyword: Optional[str] = None
    limit: int = 500
    offset: int = 0


class AuditStats(BaseModel):
    total_sessions: int = 0
    total_operations: int = 0
    total_alerts: int = 0
    operations_by_type: Dict[str, int] = Field(default_factory=dict)
    operations_by_user: Dict[str, int] = Field(default_factory=dict)
    alerts_by_severity: Dict[str, int] = Field(default_factory=dict)
    alerts_by_type: Dict[str, int] = Field(default_factory=dict)
    daily_operations: Dict[str, int] = Field(default_factory=dict)


class CommandExecuteRequest(BaseModel):
    server_ids: List[str]
    command: str
    timeout: int = 300
    env: Dict[str, str] = Field(default_factory=dict)


class ScriptExecuteRequest(BaseModel):
    server_ids: List[str]
    script_content: str
    script_name: Optional[str] = "script.sh"
    interpreter: str = "bash"
    args: List[str] = Field(default_factory=list)
    timeout: int = 300


class TemplateCreateRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    script_content: str
    interpreter: str = "bash"
    tags: List[str] = Field(default_factory=list)


class TemplateUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    script_content: Optional[str] = None
    interpreter: Optional[str] = None
    tags: Optional[List[str]] = None


class ExecutionOutput(BaseModel):
    server_id: str
    server_name: str
    task_id: str
    stream: str
    content: str
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


class ExecutionResult(BaseModel):
    task_id: str
    server_id: str
    server_name: str
    command: str
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    start_time: str
    end_time: Optional[str] = None
    status: str = "running"


class LogEntry(BaseModel):
    task_id: str
    server_id: str
    server_name: str
    command: str
    script_name: Optional[str] = None
    exit_code: Optional[int] = None
    start_time: str
    end_time: Optional[str] = None
    status: str
    output: str = ""
