export interface ServerConfig {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  password: string;
  private_key: string;
  tags: string[];
}

export interface ExecutionResult {
  task_id: string;
  server_id: string;
  server_name: string;
  command: string;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  start_time: string;
  end_time: string | null;
  status: 'pending' | 'running' | 'success' | 'failed' | 'error';
}

export interface StreamMessage {
  type: 'output' | 'status';
  task_id: string;
  server_id: string;
  server_name: string;
  stream: 'stdout' | 'stderr' | '';
  content: string;
  exit_code: number | null;
  status: string;
  timestamp: string;
}

export interface ScriptTemplate {
  id: string;
  name: string;
  description: string;
  script_content: string;
  interpreter: string;
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface LogEntry {
  task_id: string;
  server_name: string;
  server_id: string;
  command: string;
  script_name: string | null;
  start_time: string;
  end_time: string;
  status: string;
  exit_code: number | null;
  output: string;
  log_file: string;
}

export interface CommandExecuteRequest {
  server_ids: string[];
  command: string;
  timeout?: number;
  env?: Record<string, string>;
}

export interface ScriptExecuteRequest {
  server_ids: string[];
  script_content: string;
  script_name?: string;
  interpreter?: string;
  args?: string[];
  timeout?: number;
}

export type OperationType =
  | 'command_execute'
  | 'script_execute'
  | 'server_select'
  | 'server_deselect'
  | 'server_create'
  | 'server_update'
  | 'server_delete'
  | 'server_test'
  | 'template_create'
  | 'template_update'
  | 'template_delete'
  | 'template_execute'
  | 'tab_switch'
  | 'login'
  | 'logout'
  | 'session_start'
  | 'session_end'
  | 'page_view'
  | 'custom';

export type AlertType =
  | 'massive_deletion'
  | 'frequent_server_switch'
  | 'suspicious_command'
  | 'abnormal_execution_count'
  | 'off_hours_operation'
  | 'privilege_escalation_attempt'
  | 'tampering_detected';

export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface AuditSession {
  session_id: string;
  user_id: string;
  user_name: string;
  client_ip: string;
  user_agent: string;
  start_time: string;
  end_time: string | null;
  duration_ms: number;
  operation_count: number;
  status: string;
}

export interface AuditOperation {
  id: string;
  session_id: string;
  user_id: string;
  user_name: string;
  operation_type: OperationType;
  timestamp: string;
  target: string | null;
  target_id: string | null;
  detail: Record<string, any>;
  client_ip: string;
  user_agent: string;
  page: string;
  component: string;
  result: string;
  error_message: string | null;
  previous_hash: string | null;
  current_hash: string;
}

export interface RecordingFrame {
  frame_id: string;
  timestamp: number;
  type: string;
  data: Record<string, any>;
  is_keyframe: boolean;
}

export interface RecordingSession {
  session_id: string;
  user_id: string;
  user_name: string;
  start_time: string;
  end_time: string | null;
  total_frames: number;
  keyframe_indices: number[];
  duration_ms: number;
}

export interface AlertRule {
  rule_id: string;
  name: string;
  alert_type: AlertType;
  severity: AlertSeverity;
  enabled: boolean;
  description: string;
  parameters: Record<string, any>;
}

export interface AuditAlert {
  alert_id: string;
  rule_id: string;
  rule_name: string;
  alert_type: AlertType;
  severity: AlertSeverity;
  session_id: string | null;
  user_id: string | null;
  user_name: string | null;
  timestamp: string;
  description: string;
  evidence: Record<string, any>;
  operation_ids: string[];
  acknowledged: boolean;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  notes: string | null;
}

export interface AuditQuery {
  start_time?: string;
  end_time?: string;
  user_id?: string;
  user_name?: string;
  operation_type?: OperationType;
  session_id?: string;
  target?: string;
  result?: string;
  keyword?: string;
  limit?: number;
  offset?: number;
}

export interface AuditAlertQuery {
  start_time?: string;
  end_time?: string;
  alert_type?: AlertType;
  severity?: AlertSeverity;
  user_id?: string;
  acknowledged?: boolean;
  limit?: number;
}

export interface AuditStats {
  total_sessions: number;
  total_operations: number;
  total_alerts: number;
  operations_by_type: Record<string, number>;
  operations_by_user: Record<string, number>;
  alerts_by_severity: Record<string, number>;
  alerts_by_type: Record<string, number>;
  daily_operations: Record<string, number>;
}

export interface OperationRecordingRequest {
  session_id: string;
  operations: AuditOperation[];
}

export interface RecordingSessionRequest {
  session_id: string;
  user_id: string;
  user_name: string;
  frames: RecordingFrame[];
}

