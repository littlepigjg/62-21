import uuid
from datetime import datetime, date
from typing import List, Optional, Dict, Any, Deque
from collections import deque, defaultdict
from threading import Lock

from .audit_storage import audit_storage
from ..models import (
    AuditOperation,
    AuditAlert,
    AlertRule,
    AlertSeverity,
)


class AuditDetector:
    def __init__(self):
        self._lock = Lock()
        self._user_ops: Dict[str, Deque[AuditOperation]] = defaultdict(lambda: deque(maxlen=500))
        self._session_ops: Dict[str, Deque[AuditOperation]] = defaultdict(lambda: deque(maxlen=500))
        self._rules: List[AlertRule] = []
        self._reload_rules()

    def _reload_rules(self) -> None:
        self._rules = audit_storage.get_rules()

    def _ts_to_dt(self, ts: str) -> datetime:
        try:
            return datetime.fromisoformat(ts)
        except Exception:
            return datetime.now()

    def _within_window(self, op_ts: str, window_seconds: int, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now()
        try:
            op_dt = datetime.fromisoformat(op_ts)
            return (now - op_dt).total_seconds() <= window_seconds
        except Exception:
            return False

    def _create_alert(
        self,
        rule: AlertRule,
        ops: List[AuditOperation],
        extra_evidence: Optional[Dict[str, Any]] = None,
    ) -> AuditAlert:
        evidence: Dict[str, Any] = {
            "operation_count": len(ops),
            "operation_ids": [op.id for op in ops],
            "operations_summary": [
                {
                    "id": op.id,
                    "type": op.operation_type,
                    "timestamp": op.timestamp,
                    "target": op.target,
                    "detail": op.detail,
                }
                for op in ops[:10]
            ],
        }
        if extra_evidence:
            evidence.update(extra_evidence)

        sample = ops[0]
        return AuditAlert(
            alert_id=f"alert-{uuid.uuid4().hex[:16]}",
            rule_id=rule.rule_id,
            rule_name=rule.name,
            alert_type=rule.alert_type,
            severity=rule.severity,
            session_id=sample.session_id,
            user_id=sample.user_id,
            user_name=sample.user_name,
            timestamp=datetime.now().isoformat(),
            description=rule.description,
            evidence=evidence,
            operation_ids=[op.id for op in ops],
        )

    def process_operation(self, op: AuditOperation) -> List[AuditAlert]:
        alerts: List[AuditAlert] = []
        self._reload_rules()

        with self._lock:
            self._user_ops[op.user_id].append(op)
            self._session_ops[op.session_id].append(op)

            for rule in self._rules:
                if not rule.enabled:
                    continue
                detected = False
                triggered_ops: List[AuditOperation] = []
                extra: Dict[str, Any] = {}

                if rule.alert_type == "massive_deletion":
                    detected, triggered_ops = self._check_massive_deletion(op, rule)
                elif rule.alert_type == "frequent_server_switch":
                    detected, triggered_ops = self._check_frequent_server_switch(op, rule)
                elif rule.alert_type == "abnormal_execution_count":
                    detected, triggered_ops = self._check_abnormal_execution_count(op, rule)
                elif rule.alert_type == "suspicious_command":
                    detected, triggered_ops, extra = self._check_suspicious_command(op, rule)
                elif rule.alert_type == "off_hours_operation":
                    detected, triggered_ops = self._check_off_hours_operation(op, rule)
                elif rule.alert_type == "privilege_escalation_attempt":
                    detected, triggered_ops, extra = self._check_privilege_escalation(op, rule)

                if detected and triggered_ops:
                    alert = self._create_alert(rule, triggered_ops, extra or None)
                    audit_storage.save_alert(alert)
                    alerts.append(alert)

        return alerts

    def _check_massive_deletion(self, op: AuditOperation, rule: AlertRule) -> tuple[bool, List[AuditOperation]]:
        window = int(rule.parameters.get("window_seconds", 300))
        threshold = int(rule.parameters.get("threshold", 5))

        deletion_types = {"server_delete", "template_delete"}
        if op.operation_type not in deletion_types:
            return False, []

        ops: List[AuditOperation] = []
        for cached_op in list(self._user_ops[op.user_id]):
            if cached_op.operation_type in deletion_types and self._within_window(cached_op.timestamp, window):
                ops.append(cached_op)

        if len(ops) >= threshold:
            return True, ops
        return False, []

    def _check_frequent_server_switch(self, op: AuditOperation, rule: AlertRule) -> tuple[bool, List[AuditOperation]]:
        window = int(rule.parameters.get("window_seconds", 60))
        threshold = int(rule.parameters.get("threshold", 10))

        switch_types = {"server_select", "server_deselect"}
        if op.operation_type not in switch_types:
            return False, []

        ops: List[AuditOperation] = []
        for cached_op in list(self._session_ops[op.session_id]):
            if cached_op.operation_type in switch_types and self._within_window(cached_op.timestamp, window):
                ops.append(cached_op)

        if len(ops) >= threshold:
            return True, ops
        return False, []

    def _check_abnormal_execution_count(self, op: AuditOperation, rule: AlertRule) -> tuple[bool, List[AuditOperation]]:
        window = int(rule.parameters.get("window_seconds", 600))
        threshold = int(rule.parameters.get("threshold", 50))

        exec_types = {"command_execute", "script_execute", "template_execute"}
        if op.operation_type not in exec_types:
            return False, []

        ops: List[AuditOperation] = []
        for cached_op in list(self._user_ops[op.user_id]):
            if cached_op.operation_type in exec_types and self._within_window(cached_op.timestamp, window):
                ops.append(cached_op)

        if len(ops) >= threshold:
            return True, ops
        return False, []

    def _check_suspicious_command(self, op: AuditOperation, rule: AlertRule) -> tuple[bool, List[AuditOperation], Dict[str, Any]]:
        patterns: List[str] = rule.parameters.get("patterns", [])
        if op.operation_type not in ("command_execute", "script_execute", "template_execute"):
            return False, [], {}

        command = ""
        if isinstance(op.detail, dict):
            command = str(op.detail.get("command", "") or op.detail.get("script_content", "")).lower()

        matched_patterns: List[str] = []
        for pattern in patterns:
            if pattern.lower() in command:
                matched_patterns.append(pattern)

        if matched_patterns:
            return True, [op], {"matched_patterns": matched_patterns, "command": command}
        return False, [], {}

    def _check_off_hours_operation(self, op: AuditOperation, rule: AlertRule) -> tuple[bool, List[AuditOperation]]:
        start_hour = int(rule.parameters.get("start_hour", 22))
        end_hour = int(rule.parameters.get("end_hour", 8))

        sensitive_types = {
            "server_delete", "template_delete", "server_update", "template_update",
            "command_execute", "script_execute", "template_execute",
        }
        if op.operation_type not in sensitive_types:
            return False, []

        try:
            op_dt = datetime.fromisoformat(op.timestamp)
            hour = op_dt.hour
            is_off_hours = (hour >= start_hour) or (hour < end_hour)
            if is_off_hours:
                return True, [op]
        except Exception:
            pass

        return False, []

    def _check_privilege_escalation(self, op: AuditOperation, rule: AlertRule) -> tuple[bool, List[AuditOperation], Dict[str, Any]]:
        patterns: List[str] = rule.parameters.get("patterns", [])
        if op.operation_type not in ("command_execute", "script_execute", "template_execute"):
            return False, [], {}

        command = ""
        if isinstance(op.detail, dict):
            command = str(op.detail.get("command", "") or op.detail.get("script_content", "")).lower()

        matched_patterns: List[str] = []
        for pattern in patterns:
            if pattern.lower() in command:
                matched_patterns.append(pattern)

        if matched_patterns:
            return True, [op], {"matched_patterns": matched_patterns, "command": command}
        return False, [], {}


audit_detector = AuditDetector()
