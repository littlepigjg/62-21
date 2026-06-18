import os
import json
import hashlib
import uuid
import base64
import asyncio
import logging
from pathlib import Path
from datetime import datetime, date, timedelta
from typing import List, Optional, Dict, Any, Tuple
from threading import Lock
from contextlib import contextmanager

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTOGRAPHY = True
except Exception:
    _HAS_CRYPTOGRAPHY = False

logger = logging.getLogger("audit_storage")

from ..config import BASE_DIR
from ..models import (
    AuditSession,
    AuditOperation,
    RecordingSession,
    RecordingFrame,
    AuditAlert,
    AlertRule,
    AuditQuery,
    AuditStats,
    AuditAlertQuery,
    AlertSeverity,
)


AUDIT_DIR = BASE_DIR / "audit_data"
AUDIT_OPS_DIR = AUDIT_DIR / "operations"
AUDIT_SESSIONS_DIR = AUDIT_DIR / "sessions"
AUDIT_RECORDINGS_DIR = AUDIT_DIR / "recordings"
AUDIT_ALERTS_DIR = AUDIT_DIR / "alerts"
AUDIT_RULES_FILE = AUDIT_DIR / "rules.json"
AUDIT_HASH_CHAIN_FILE = AUDIT_DIR / "hash_chain.json"

for d in [AUDIT_DIR, AUDIT_OPS_DIR, AUDIT_SESSIONS_DIR, AUDIT_RECORDINGS_DIR, AUDIT_ALERTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)


_ENCRYPTION_KEY = None
_write_lock = Lock()
_AESGCM_NONCE_LEN = 12
_encryption_warned = False


def _get_encryption_key() -> bytes:
    global _ENCRYPTION_KEY
    if _ENCRYPTION_KEY is None:
        key_env = os.environ.get(
            "AUDIT_ENCRYPTION_KEY",
            "remote-ssh-audit-default-key-change-in-production!",
        )
        _ENCRYPTION_KEY = hashlib.sha256(key_env.encode("utf-8")).digest()
    return _ENCRYPTION_KEY


def _legacy_xor(data: bytes) -> bytes:
    key = _get_encryption_key()
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def _encrypt(data: str) -> str:
    global _encryption_warned
    data_bytes = data.encode("utf-8")
    if _HAS_CRYPTOGRAPHY:
        nonce = os.urandom(_AESGCM_NONCE_LEN)
        ct = AESGCM(_get_encryption_key()).encrypt(nonce, data_bytes, None)
        return "agcm:" + base64.b64encode(nonce + ct).decode("ascii")
    if not _encryption_warned:
        logger.warning(
            "cryptography 库未安装，审计数据降级为 XOR 加密，不满足等保/SOX 合规，请安装 cryptography 依赖"
        )
        _encryption_warned = True
    return "xor:" + base64.b64encode(_legacy_xor(data_bytes)).decode("ascii")


def _decrypt(encrypted: str) -> str:
    if encrypted.startswith("agcm:"):
        raw = base64.b64decode(encrypted[5:].encode("ascii"))
        nonce, ct = raw[:_AESGCM_NONCE_LEN], raw[_AESGCM_NONCE_LEN:]
        return AESGCM(_get_encryption_key()).decrypt(nonce, ct, None).decode("utf-8")
    if encrypted.startswith("xor:"):
        return _legacy_xor(base64.b64decode(encrypted[4:].encode("ascii"))).decode("utf-8")
    return _legacy_xor(base64.b64decode(encrypted.encode("ascii"))).decode("utf-8")


def _simple_encrypt(data: str) -> str:
    return _encrypt(data)


def _simple_decrypt(encrypted: str) -> str:
    return _decrypt(encrypted)


def _compute_hash(operation: AuditOperation, prev_hash: Optional[str]) -> str:
    payload = json.dumps({
        "id": operation.id,
        "session_id": operation.session_id,
        "user_id": operation.user_id,
        "operation_type": operation.operation_type,
        "timestamp": operation.timestamp,
        "target": operation.target,
        "target_id": operation.target_id,
        "detail": operation.detail,
        "result": operation.result,
        "prev_hash": prev_hash or "",
    }, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _load_hash_chain() -> Dict[str, Any]:
    if AUDIT_HASH_CHAIN_FILE.exists():
        try:
            content = AUDIT_HASH_CHAIN_FILE.read_text(encoding="utf-8")
            return json.loads(content)
        except Exception:
            pass
    return {"last_hash": None, "total_operations": 0, "last_date": None}


def _save_hash_chain(data: Dict[str, Any]) -> None:
    AUDIT_HASH_CHAIN_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _ops_file_for_date(d: Optional[date] = None) -> Path:
    d = d or date.today()
    return AUDIT_OPS_DIR / f"ops_{d.isoformat()}.jsonl.enc"


def _sessions_file() -> Path:
    return AUDIT_SESSIONS_DIR / "sessions.json"


def _alerts_file_for_date(d: Optional[date] = None) -> Path:
    d = d or date.today()
    return AUDIT_ALERTS_DIR / f"alerts_{d.isoformat()}.jsonl"


class AuditStorage:

    def __init__(self):
        self._ensure_rules_defaults()

    def _ensure_rules_defaults(self) -> None:
        if not AUDIT_RULES_FILE.exists():
            default_rules = [
                AlertRule(
                    rule_id="massive_deletion",
                    name="短时间大量删除任务",
                    alert_type="massive_deletion",
                    severity="high",
                    description="5分钟内删除超过5个服务器或模板",
                    parameters={"window_seconds": 300, "threshold": 5},
                ).model_dump(),
                AlertRule(
                    rule_id="frequent_server_switch",
                    name="频繁切换服务器",
                    alert_type="frequent_server_switch",
                    severity="medium",
                    description="1分钟内切换服务器选择超过10次",
                    parameters={"window_seconds": 60, "threshold": 10},
                ).model_dump(),
                AlertRule(
                    rule_id="abnormal_execution_count",
                    name="异常命令执行次数",
                    alert_type="abnormal_execution_count",
                    severity="high",
                    description="10分钟内执行命令超过50次",
                    parameters={"window_seconds": 600, "threshold": 50},
                ).model_dump(),
                AlertRule(
                    rule_id="suspicious_command",
                    name="可疑命令检测",
                    alert_type="suspicious_command",
                    severity="critical",
                    description="执行包含 rm -rf /, mkfs, dd if=/dev/zero 等危险命令",
                    parameters={"patterns": ["rm -rf /", "mkfs", "dd if=/dev/zero", "shutdown", "reboot", ":(){ :|:& };:", "chmod 777 /etc"]},
                ).model_dump(),
                AlertRule(
                    rule_id="off_hours_operation",
                    name="非工作时间操作",
                    alert_type="off_hours_operation",
                    severity="low",
                    description="非工作时间段（22:00-08:00）进行敏感操作",
                    parameters={"start_hour": 22, "end_hour": 8},
                ).model_dump(),
                AlertRule(
                    rule_id="privilege_escalation_attempt",
                    name="权限提升尝试",
                    alert_type="privilege_escalation_attempt",
                    severity="critical",
                    description="执行 sudo su, chmod 4755, passwd 等提权相关命令",
                    parameters={"patterns": ["sudo su", "su root", "chmod 4755", "passwd", "visudo", "usermod -aG", "sudo -s"]},
                ).model_dump(),
                AlertRule(
                    rule_id="tampering_detected",
                    name="数据篡改检测",
                    alert_type="tampering_detected",
                    severity="critical",
                    description="审计数据完整性校验发现哈希不匹配或链断裂",
                    parameters={"trigger": "integrity_verify"},
                ).model_dump(),
            ]
            AUDIT_RULES_FILE.write_text(
                json.dumps(default_rules, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

    def create_session(self, session: AuditSession) -> AuditSession:
        sessions = self._load_sessions()
        sessions.append(session.model_dump())
        self._save_sessions(sessions)
        return session

    def end_session(self, session_id: str, end_time: Optional[str] = None) -> Optional[AuditSession]:
        sessions = self._load_sessions()
        for s in sessions:
            if s["session_id"] == session_id:
                s["status"] = "ended"
                s["end_time"] = end_time or datetime.now().isoformat()
                self._save_sessions(sessions)
                return AuditSession(**s)
        return None

    def get_session(self, session_id: str) -> Optional[AuditSession]:
        for s in self._load_sessions():
            if s["session_id"] == session_id:
                return AuditSession(**s)
        return None

    def list_sessions(self, user_id: Optional[str] = None, limit: int = 100) -> List[AuditSession]:
        sessions = [AuditSession(**s) for s in self._load_sessions()]
        if user_id:
            sessions = [s for s in sessions if s.user_id == user_id]
        sessions.sort(key=lambda x: x.start_time, reverse=True)
        return sessions[:limit]

    def _load_sessions(self) -> List[Dict[str, Any]]:
        if not _sessions_file().exists():
            return []
        try:
            return json.loads(_sessions_file().read_text(encoding="utf-8"))
        except Exception:
            return []

    def _save_sessions(self, sessions: List[Dict[str, Any]]) -> None:
        _sessions_file().write_text(
            json.dumps(sessions, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def save_operation(self, operation: AuditOperation) -> AuditOperation:
        with _write_lock:
            chain = _load_hash_chain()
            prev_hash = chain.get("last_hash")
            today_str = date.today().isoformat()

            if chain.get("last_date") != today_str:
                prev_hash = None

            operation.current_hash = _compute_hash(operation, prev_hash)
            operation.previous_hash = prev_hash

            data_line = json.dumps(operation.model_dump(), ensure_ascii=False)
            encrypted = _simple_encrypt(data_line)

            file_path = _ops_file_for_date()
            with open(file_path, "a", encoding="utf-8") as f:
                f.write(encrypted + "\n")

            chain["last_hash"] = operation.current_hash
            chain["total_operations"] = chain.get("total_operations", 0) + 1
            chain["last_date"] = today_str
            _save_hash_chain(chain)

        return operation

    def save_operations_batch(self, operations: List[AuditOperation]) -> List[AuditOperation]:
        return [self.save_operation(op) for op in operations]

    def query_operations(self, query: AuditQuery) -> Dict[str, Any]:
        result: List[AuditOperation] = []
        files_to_check = self._collect_ops_files(query.start_time, query.end_time)

        for fp in files_to_check:
            if not fp.exists():
                continue
            lines = fp.read_text(encoding="utf-8").splitlines()
            for line in lines:
                if not line.strip():
                    continue
                try:
                    decrypted = _simple_decrypt(line.strip())
                    data = json.loads(decrypted)
                    op = AuditOperation(**data)
                    if self._match_query(op, query):
                        result.append(op)
                except Exception:
                    continue

        result.sort(key=lambda x: x.timestamp, reverse=True)
        total = len(result)
        offset = query.offset or 0
        limit = query.limit or 500
        paginated = result[offset:offset + limit]

        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "items": [op.model_dump() for op in paginated],
        }

    def _collect_ops_files(self, start_time: Optional[str], end_time: Optional[str]) -> List[Path]:
        files = sorted(AUDIT_OPS_DIR.glob("ops_*.jsonl.enc"), reverse=True)
        if not start_time and not end_time:
            return files[:7]

        start_d = self._parse_date_from_str(start_time)
        end_d = self._parse_date_from_str(end_time) or date.today()

        if not start_d:
            return files

        filtered = []
        for fp in files:
            name = fp.stem.split(".")[0]
            date_str = name.replace("ops_", "")
            try:
                d = date.fromisoformat(date_str)
                if start_d <= d <= end_d:
                    filtered.append(fp)
            except Exception:
                continue
        return filtered

    def _parse_date_from_str(self, s: Optional[str]) -> Optional[date]:
        if not s:
            return None
        try:
            return datetime.fromisoformat(s).date()
        except Exception:
            try:
                return date.fromisoformat(s)
            except Exception:
                return None

    def _match_query(self, op: AuditOperation, q: AuditQuery) -> bool:
        if q.start_time and op.timestamp < q.start_time:
            return False
        if q.end_time and op.timestamp > q.end_time:
            return False
        if q.user_id and op.user_id != q.user_id:
            return False
        if q.user_name and q.user_name not in (op.user_name or ""):
            return False
        if q.operation_type and op.operation_type != q.operation_type:
            return False
        if q.session_id and op.session_id != q.session_id:
            return False
        if q.target and q.target not in (op.target or ""):
            return False
        if q.result and op.result != q.result:
            return False
        if q.keyword:
            kw = q.keyword.lower()
            detail_str = json.dumps(op.detail, ensure_ascii=False).lower()
            haystack = f"{op.target or ''} {op.target_id or ''} {detail_str} {op.operation_type}".lower()
            if kw not in haystack:
                return False
        return True

    def _record_tampering_alert(self, violation: Dict[str, Any], verified_count: int, error: str) -> None:
        try:
            alert = AuditAlert(
                alert_id=f"alert-{uuid.uuid4().hex[:16]}",
                rule_id="tampering_detected",
                rule_name="数据篡改检测",
                alert_type="tampering_detected",
                severity="critical",
                session_id=None,
                user_id=None,
                user_name=None,
                timestamp=datetime.now().isoformat(),
                description="审计数据完整性校验发现篡改或损坏",
                evidence={
                    "error": error,
                    "violation": violation,
                    "verified_count": verified_count,
                },
                operation_ids=[],
            )
            self.save_alert(alert)
        except Exception:
            pass

    def verify_integrity(self, date_str: Optional[str] = None) -> Dict[str, Any]:
        files = self._collect_ops_files(date_str, date_str)
        if not files:
            return {"valid": True, "error": None, "verified_count": 0, "first_violation": None}

        files.sort()
        prev_hash: Optional[str] = None
        count = 0
        first_violation = None

        for fp in files:
            lines = fp.read_text(encoding="utf-8").splitlines()
            for line in lines:
                if not line.strip():
                    continue
                try:
                    decrypted = _simple_decrypt(line.strip())
                    data = json.loads(decrypted)
                    op = AuditOperation(**data)
                    expected = _compute_hash(op, prev_hash)
                    if expected != op.current_hash:
                        first_violation = {
                            "operation_id": op.id,
                            "timestamp": op.timestamp,
                            "expected_hash": expected,
                            "actual_hash": op.current_hash,
                            "file": fp.name,
                        }
                        self._record_tampering_alert(first_violation, count, "hash_mismatch")
                        return {"valid": False, "error": "hash_mismatch", "verified_count": count, "first_violation": first_violation}
                    if op.previous_hash != prev_hash:
                        first_violation = {
                            "operation_id": op.id,
                            "timestamp": op.timestamp,
                            "expected_prev": prev_hash,
                            "actual_prev": op.previous_hash,
                            "file": fp.name,
                        }
                        self._record_tampering_alert(first_violation, count, "chain_break")
                        return {"valid": False, "error": "chain_break", "verified_count": count, "first_violation": first_violation}
                    prev_hash = op.current_hash
                    count += 1
                except Exception as e:
                    first_violation = {"error": str(e), "file": fp.name}
                    self._record_tampering_alert(first_violation, count, "parse_error")
                    return {"valid": False, "error": "parse_error", "verified_count": count, "first_violation": first_violation}

        return {"valid": True, "error": None, "verified_count": count, "first_violation": None}

    def save_recording_frames(self, req: "RecordingSessionRequest") -> RecordingSession:
        session_dir = AUDIT_RECORDINGS_DIR / req.session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        session_file = session_dir / "session.json"
        frames_file = session_dir / "frames.jsonl"

        existing_frames_count = 0
        if frames_file.exists():
            existing_frames_count = len(frames_file.read_text(encoding="utf-8").splitlines())

        keyframe_indices: List[int] = []
        start_ts = float("inf")
        end_ts = 0

        with open(frames_file, "a", encoding="utf-8") as f:
            for i, frame in enumerate(req.frames):
                global_idx = existing_frames_count + i
                if frame.is_keyframe:
                    keyframe_indices.append(global_idx)
                start_ts = min(start_ts, frame.timestamp)
                end_ts = max(end_ts, frame.timestamp)
                f.write(json.dumps(frame.model_dump(), ensure_ascii=False) + "\n")

        duration_ms = max(0, int(end_ts - start_ts)) if start_ts != float("inf") else 0
        audit_session = self.get_session(req.session_id)
        start_time_iso = audit_session.start_time if audit_session else datetime.now().isoformat()
        end_time_iso: Optional[str] = None
        if duration_ms > 0:
            try:
                end_time_iso = (
                    datetime.fromisoformat(start_time_iso) + timedelta(milliseconds=duration_ms)
                ).isoformat()
            except Exception:
                end_time_iso = None

        session = RecordingSession(
            session_id=req.session_id,
            user_id=req.user_id,
            user_name=req.user_name,
            start_time=start_time_iso,
            end_time=end_time_iso,
            total_frames=existing_frames_count + len(req.frames),
            keyframe_indices=keyframe_indices,
            duration_ms=duration_ms,
        )
        session_file.write_text(json.dumps(session.model_dump(), indent=2, ensure_ascii=False), encoding="utf-8")
        return session

    def get_recording_session(self, session_id: str) -> Optional[RecordingSession]:
        session_file = AUDIT_RECORDINGS_DIR / session_id / "session.json"
        if not session_file.exists():
            return None
        try:
            data = json.loads(session_file.read_text(encoding="utf-8"))
            return RecordingSession(**data)
        except Exception:
            return None

    def list_recording_sessions(self, user_id: Optional[str] = None, limit: int = 50) -> List[RecordingSession]:
        result: List[RecordingSession] = []
        for entry in sorted(AUDIT_RECORDINGS_DIR.iterdir(), reverse=True):
            if not entry.is_dir():
                continue
            session_file = entry / "session.json"
            if not session_file.exists():
                continue
            try:
                data = json.loads(session_file.read_text(encoding="utf-8"))
                rs = RecordingSession(**data)
                if user_id and rs.user_id != user_id:
                    continue
                result.append(rs)
                if len(result) >= limit:
                    break
            except Exception:
                continue
        return result

    def get_recording_frames(self, session_id: str, start_index: int = 0, end_index: Optional[int] = None) -> List[RecordingFrame]:
        frames_file = AUDIT_RECORDINGS_DIR / session_id / "frames.jsonl"
        if not frames_file.exists():
            return []
        lines = frames_file.read_text(encoding="utf-8").splitlines()
        end = end_index if end_index is not None else len(lines)
        frames: List[RecordingFrame] = []
        for line in lines[start_index:end]:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                frames.append(RecordingFrame(**data))
            except Exception:
                continue
        return frames

    def save_alert(self, alert: AuditAlert) -> AuditAlert:
        file_path = _alerts_file_for_date()
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert.model_dump(), ensure_ascii=False) + "\n")
        return alert

    def query_alerts(self, query: AuditAlertQuery) -> Dict[str, Any]:
        result: List[AuditAlert] = []
        alert_files = sorted(AUDIT_ALERTS_DIR.glob("alerts_*.jsonl"), reverse=True)

        start_d = self._parse_date_from_str(query.start_time)
        end_d = self._parse_date_from_str(query.end_time)

        for fp in alert_files:
            try:
                name = fp.stem.replace("alerts_", "")
                d = date.fromisoformat(name)
                if start_d and d < start_d:
                    continue
                if end_d and d > end_d:
                    continue
            except Exception:
                pass

            for line in fp.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    alert = AuditAlert(**data)
                    if self._match_alert_query(alert, query):
                        result.append(alert)
                except Exception:
                    continue

        result.sort(key=lambda x: x.timestamp, reverse=True)
        limit = query.limit or 100
        return {
            "total": len(result),
            "items": [a.model_dump() for a in result[:limit]],
        }

    def _match_alert_query(self, alert: AuditAlert, q: AuditAlertQuery) -> bool:
        if q.alert_type and alert.alert_type != q.alert_type:
            return False
        if q.severity and alert.severity != q.severity:
            return False
        if q.user_id and alert.user_id != q.user_id:
            return False
        if q.acknowledged is not None and alert.acknowledged != q.acknowledged:
            return False
        return True

    def acknowledge_alert(self, alert_id: str, user: str, notes: Optional[str] = None) -> Optional[AuditAlert]:
        for fp in AUDIT_ALERTS_DIR.glob("alerts_*.jsonl"):
            lines = fp.read_text(encoding="utf-8").splitlines()
            new_lines: List[str] = []
            found: Optional[AuditAlert] = None
            for line in lines:
                if not line.strip():
                    new_lines.append(line)
                    continue
                try:
                    data = json.loads(line)
                    alert = AuditAlert(**data)
                    if alert.alert_id == alert_id:
                        alert.acknowledged = True
                        alert.acknowledged_by = user
                        alert.acknowledged_at = datetime.now().isoformat()
                        if notes:
                            alert.notes = notes
                        found = alert
                        data = alert.model_dump()
                    new_lines.append(json.dumps(data, ensure_ascii=False))
                except Exception:
                    new_lines.append(line)
            if found:
                fp.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                return found
        return None

    def get_rules(self) -> List[AlertRule]:
        if not AUDIT_RULES_FILE.exists():
            return []
        try:
            data = json.loads(AUDIT_RULES_FILE.read_text(encoding="utf-8"))
            return [AlertRule(**d) for d in data]
        except Exception:
            return []

    def update_rule(self, rule: AlertRule) -> AlertRule:
        rules = self.get_rules()
        updated = False
        new_rules: List[Dict[str, Any]] = []
        for r in rules:
            if r.rule_id == rule.rule_id:
                new_rules.append(rule.model_dump())
                updated = True
            else:
                new_rules.append(r.model_dump())
        if not updated:
            new_rules.append(rule.model_dump())
        AUDIT_RULES_FILE.write_text(json.dumps(new_rules, indent=2, ensure_ascii=False), encoding="utf-8")
        return rule

    def compute_stats(self, days: int = 7) -> AuditStats:
        stats = AuditStats()
        today = date.today()

        sessions = self._load_sessions()
        stats.total_sessions = len(sessions)
        for s in sessions:
            try:
                sd = date.fromisoformat(s["start_time"][:10])
                if (today - sd).days <= days:
                    stats.total_operations += s.get("operation_count", 0)
            except Exception:
                pass

        for fp in sorted(AUDIT_OPS_DIR.glob("ops_*.jsonl.enc"), reverse=True):
            try:
                name = fp.stem.split(".")[0].replace("ops_", "")
                d = date.fromisoformat(name)
                if (today - d).days > days:
                    continue
                daily_count = 0
                for line in fp.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        decrypted = _simple_decrypt(line.strip())
                        data = json.loads(decrypted)
                        op_type = data.get("operation_type", "unknown")
                        user_name = data.get("user_name", "unknown")
                        stats.operations_by_type[op_type] = stats.operations_by_type.get(op_type, 0) + 1
                        stats.operations_by_user[user_name] = stats.operations_by_user.get(user_name, 0) + 1
                        stats.total_operations += 1
                        daily_count += 1
                    except Exception:
                        continue
                stats.daily_operations[d.isoformat()] = daily_count
            except Exception:
                continue

        for fp in AUDIT_ALERTS_DIR.glob("alerts_*.jsonl"):
            try:
                name = fp.stem.replace("alerts_", "")
                d = date.fromisoformat(name)
                if (today - d).days > days:
                    continue
            except Exception:
                pass

            for line in fp.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    severity = data.get("severity", "unknown")
                    a_type = data.get("alert_type", "unknown")
                    stats.alerts_by_severity[severity] = stats.alerts_by_severity.get(severity, 0) + 1
                    stats.alerts_by_type[a_type] = stats.alerts_by_type.get(a_type, 0) + 1
                    stats.total_alerts += 1
                except Exception:
                    continue

        return stats


audit_storage = AuditStorage()
