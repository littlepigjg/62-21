import axios from 'axios';
import type {
  ServerConfig,
  ExecutionResult,
  ScriptTemplate,
  LogEntry,
  CommandExecuteRequest,
  ScriptExecuteRequest,
  AuditSession,
  AuditOperation,
  AuditAlert,
  AlertRule,
  AuditQuery,
  AuditAlertQuery,
  AuditStats,
  RecordingSession,
  RecordingFrame,
  OperationRecordingRequest,
  RecordingSessionRequest,
} from '../types';

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
});

const AUDIT_HEADERS_KEYS = ['x-audit-session', 'x-audit-user-id', 'x-audit-user-name'] as const;

const getAuditHeaders = (): Record<string, string> => {
  const headers: Record<string, string> = {};
  try {
    const sessionId = localStorage.getItem('audit_session_id');
    const userId = localStorage.getItem('audit_user_id');
    const userName = localStorage.getItem('audit_user_name');
    if (sessionId) headers['x-audit-session'] = sessionId;
    if (userId) headers['x-audit-user-id'] = userId;
    if (userName) headers['x-audit-user-name'] = decodeURIComponent(userName);
  } catch (e) {}
  return headers;
};

api.interceptors.request.use((config) => {
  const auditHeaders = getAuditHeaders();
  Object.entries(auditHeaders).forEach(([k, v]) => {
    config.headers.set(k, v);
  });
  return config;
});

export const serversApi = {
  list: (tag?: string): Promise<ServerConfig[]> =>
    api.get('/servers', { params: { tag } }).then(r => r.data),
  get: (id: string): Promise<ServerConfig> =>
    api.get(`/servers/${id}`).then(r => r.data),
  tags: (): Promise<string[]> =>
    api.get('/servers/tags').then(r => r.data),
  create: (data: Partial<ServerConfig>): Promise<ServerConfig> =>
    api.post('/servers', data).then(r => r.data),
  update: (id: string, data: Partial<ServerConfig>): Promise<ServerConfig> =>
    api.put(`/servers/${id}`, data).then(r => r.data),
  delete: (id: string): Promise<void> =>
    api.delete(`/servers/${id}`).then(r => r.data),
  test: (id: string): Promise<{ success: boolean; message: string }> =>
    api.post(`/servers/${id}/test`).then(r => r.data),
};

export const executeApi = {
  command: (data: CommandExecuteRequest): Promise<ExecutionResult[]> =>
    api.post('/execute/command', data).then(r => r.data),
  script: (data: ScriptExecuteRequest): Promise<ExecutionResult[]> =>
    api.post('/execute/script', data).then(r => r.data),
  listTasks: (serverId?: string, limit = 100): Promise<ExecutionResult[]> =>
    api.get('/execute/tasks', { params: { server_id: serverId, limit } }).then(r => r.data),
  getTask: (taskId: string): Promise<ExecutionResult> =>
    api.get(`/execute/tasks/${taskId}`).then(r => r.data),
};

export const templatesApi = {
  list: (tag?: string, keyword?: string): Promise<ScriptTemplate[]> =>
    api.get('/templates', { params: { tag, keyword } }).then(r => r.data),
  tags: (): Promise<string[]> =>
    api.get('/templates/tags').then(r => r.data),
  get: (id: string): Promise<ScriptTemplate> =>
    api.get(`/templates/${id}`).then(r => r.data),
  create: (data: Partial<ScriptTemplate> & { name: string; script_content: string }): Promise<ScriptTemplate> =>
    api.post('/templates', data).then(r => r.data),
  update: (id: string, data: Partial<ScriptTemplate>): Promise<ScriptTemplate> =>
    api.put(`/templates/${id}`, data).then(r => r.data),
  delete: (id: string): Promise<void> =>
    api.delete(`/templates/${id}`).then(r => r.data),
};

export const logsApi = {
  list: (params: { date?: string; server_id?: string; limit?: number } = {}): Promise<LogEntry[]> =>
    api.get('/logs', { params }).then(r => r.data),
  dates: (): Promise<string[]> =>
    api.get('/logs/dates').then(r => r.data),
  getByTask: (taskId: string): Promise<LogEntry> =>
    api.get(`/logs/${taskId}`).then(r => r.data),
};

export const auditApi = {
  createSession: (userId: string, userName: string, clientIp = '', userAgent = ''): Promise<AuditSession> =>
    api.post('/audit/sessions', { user_id: userId, user_name: userName, client_ip: clientIp, user_agent: userAgent }).then(r => r.data),
  endSession: (sessionId: string): Promise<AuditSession> =>
    api.put(`/audit/sessions/${sessionId}/end`).then(r => r.data),
  listSessions: (userId?: string, limit = 100): Promise<AuditSession[]> =>
    api.get('/audit/sessions', { params: { user_id: userId, limit } }).then(r => r.data),
  getSession: (sessionId: string): Promise<AuditSession> =>
    api.get(`/audit/sessions/${sessionId}`).then(r => r.data),

  recordOperations: (data: OperationRecordingRequest): Promise<{ saved: number; operations: AuditOperation[]; alerts_triggered: number; alerts: AuditAlert[] }> =>
    api.post('/audit/operations', data).then(r => r.data),
  queryOperations: (query: AuditQuery): Promise<{ total: number; offset: number; limit: number; items: AuditOperation[] }> =>
    api.post('/audit/operations/query', query).then(r => r.data),

  saveRecordingFrames: (data: RecordingSessionRequest): Promise<RecordingSession> =>
    api.post('/audit/recordings/frames', data).then(r => r.data),
  listRecordingSessions: (userId?: string, limit = 50): Promise<RecordingSession[]> =>
    api.get('/audit/recordings/sessions', { params: { user_id: userId, limit } }).then(r => r.data),
  getRecordingSession: (sessionId: string): Promise<RecordingSession> =>
    api.get(`/audit/recordings/sessions/${sessionId}`).then(r => r.data),
  getRecordingFrames: (sessionId: string, startIndex = 0, endIndex?: number, keyframesOnly = false): Promise<{ total: number; frames: RecordingFrame[] }> =>
    api.get(`/audit/recordings/sessions/${sessionId}/frames`, { params: { start_index: startIndex, end_index: endIndex, keyframes_only: keyframesOnly } }).then(r => r.data),
  getPlaybackData: (sessionId: string): Promise<{ session: RecordingSession; frames: RecordingFrame[]; operations: AuditOperation[] }> =>
    api.get(`/audit/recordings/sessions/${sessionId}/playback`).then(r => r.data),
  jumpToFrame: (sessionId: string, targetTimestamp: number): Promise<{ target_index: number; target_frame: RecordingFrame; keyframe_index: number; frames_from_keyframe: RecordingFrame[] }> =>
    api.get(`/audit/recordings/sessions/${sessionId}/jump`, { params: { target_timestamp: targetTimestamp } }).then(r => r.data),

  queryAlerts: (query: AuditAlertQuery): Promise<{ total: number; items: AuditAlert[] }> =>
    api.post('/audit/alerts/query', query).then(r => r.data),
  listAlerts: (alertType?: string, severity?: string, userId?: string, acknowledged?: boolean, limit = 100): Promise<AuditAlert[]> =>
    api.get('/audit/alerts', { params: { alert_type: alertType, severity, user_id: userId, acknowledged, limit } }).then(r => r.data),
  getAlert: (alertId: string): Promise<AuditAlert> =>
    api.get(`/audit/alerts/${alertId}`).then(r => r.data),
  acknowledgeAlert: (alertId: string, user: string, notes?: string): Promise<AuditAlert> =>
    api.put(`/audit/alerts/${alertId}/acknowledge`, { user, notes }).then(r => r.data),

  listRules: (): Promise<AlertRule[]> =>
    api.get('/audit/rules').then(r => r.data),
  updateRule: (rule: AlertRule): Promise<AlertRule> =>
    api.put('/audit/rules', rule).then(r => r.data),

  getStats: (days = 7): Promise<AuditStats> =>
    api.get('/audit/stats', { params: { days } }).then(r => r.data),
  verifyIntegrity: (date?: string): Promise<{ valid: boolean; error: string | null; verified_count: number; first_violation: any | null }> =>
    api.get('/audit/integrity/verify', { params: { date } }).then(r => r.data),
};

export default api;
