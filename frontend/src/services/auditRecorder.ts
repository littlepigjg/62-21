import type { AuditOperation, RecordingFrame, OperationType } from '../types';
import { auditApi } from './api';

class AuditRecorder {
  private sessionId: string = '';
  private userId: string = '';
  private userName: string = '';
  private operationBuffer: AuditOperation[] = [];
  private frameBuffer: RecordingFrame[] = [];
  private flushTimer: number | null = null;
  private frameTimer: number | null = null;
  private lastFrameTime: number = 0;
  private sessionStartTime: number = 0;
  private initialized: boolean = false;
  private domListeners: Array<() => void> = [];
  private frameCounter: number = 0;

  constructor() {}

  async init(userId: string, userName: string): Promise<void> {
    if (this.initialized) return;

    this.userId = userId;
    this.userName = userName;
    this.sessionStartTime = Date.now();

    try {
      const session = await auditApi.createSession(
        userId,
        userName,
        '',
        navigator.userAgent
      );
      this.sessionId = session.session_id;

      try {
        localStorage.setItem('audit_session_id', this.sessionId);
        localStorage.setItem('audit_user_id', this.userId);
        localStorage.setItem('audit_user_name', encodeURIComponent(this.userName));
      } catch (e) {}

      this.setupDOMListeners();
      this.startFlushTimer();
      this.startFrameCapture();

      this.initialized = true;
      this.recordOperation('session_start', 'session', this.sessionId, {});
    } catch (e) {
      console.warn('Failed to initialize audit recorder:', e);
    }
  }

  private setupDOMListeners(): void {
    const handleClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      const tagName = target.tagName?.toLowerCase() || '';
      const text = target.textContent?.slice(0, 100) || '';
      const btnText = target.innerText?.slice(0, 50) || '';
      const component = target.closest('[data-audit-component]')?.getAttribute('data-audit-component') || '';
      const action = target.getAttribute('data-audit-action') || '';

      if (['button', 'a', 'input', 'select'].includes(tagName) || target.closest('button')) {
        this.recordOperation('custom', 'ui_click', null, {
          element: tagName,
          text: btnText || text,
          component,
          action,
          id: target.id,
          className: target.className?.toString().slice(0, 100),
        });
      }
    };

    const handleChange = (e: Event) => {
      const target = e.target as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT') {
        const component = target.closest('[data-audit-component]')?.getAttribute('data-audit-component') || '';
        this.recordOperation('custom', 'ui_input', null, {
          element: target.tagName.toLowerCase(),
          id: target.id,
          component,
          input_type: (target as HTMLInputElement).type || '',
          has_value: !!target.value,
        });
      }
    };

    document.addEventListener('click', handleClick, true);
    document.addEventListener('change', handleChange, true);

    this.domListeners.push(() => {
      document.removeEventListener('click', handleClick, true);
      document.removeEventListener('change', handleChange, true);
    });
  }

  private startFlushTimer(): void {
    this.flushTimer = window.setInterval(() => {
      this.flush();
    }, 5000);
  }

  private startFrameCapture(): void {
    this.captureFrame(true);
    this.frameTimer = window.setInterval(() => {
      this.frameCounter += 1;
      this.captureFrame(this.frameCounter % 5 === 0);
    }, 2000);
  }

  captureKeyframe(): void {
    if (!this.initialized) return;
    this.captureFrame(true);
  }

  private captureDomSnapshot(): string {
    try {
      const clone = document.body.cloneNode(true) as HTMLElement;
      clone.querySelectorAll('script, style, noscript, link, svg').forEach(el => el.remove());
      clone.querySelectorAll('*').forEach(el => {
        Array.from(el.attributes).forEach(attr => {
          if (attr.name.startsWith('on')) el.removeAttribute(attr.name);
        });
      });
      clone.querySelectorAll('input').forEach(el => {
        const input = el as HTMLInputElement;
        if (input.type === 'password') {
          input.setAttribute('value', '••••••');
        } else {
          input.setAttribute('value', (input.value || '').slice(0, 80));
        }
        if (input.checked) input.setAttribute('checked', '');
        else input.removeAttribute('checked');
      });
      clone.querySelectorAll('textarea').forEach(el => {
        const ta = el as HTMLTextAreaElement;
        ta.textContent = (ta.value || '').slice(0, 200);
      });
      let html = clone.innerHTML;
      const MAX = 200000;
      if (html.length > MAX) {
        html = html.slice(0, MAX) + '\n<!-- snapshot truncated -->';
      }
      return html;
    } catch (e) {
      return '';
    }
  }

  private captureFrame(isKeyframe: boolean): void {
    const now = Date.now();
    const frame: RecordingFrame = {
      frame_id: `frame-${this.sessionId}-${now}`,
      timestamp: now - this.sessionStartTime,
      type: 'dom_snapshot',
      data: {
        url: window.location.href,
        scrollY: window.scrollY,
        scrollX: window.scrollX,
        title: document.title,
        viewport_width: window.innerWidth,
        viewport_height: window.innerHeight,
      },
      is_keyframe: isKeyframe,
    };

    if (isKeyframe) {
      const snapshot = this.captureDomSnapshot();
      if (snapshot) {
        frame.data.dom_snapshot = snapshot;
        frame.data.dom_snapshot_size = snapshot.length;
      }
    }

    this.frameBuffer.push(frame);
    this.lastFrameTime = now;

    if (this.frameBuffer.length >= 50) {
      this.flushFrames();
    }
  }

  recordOperation(
    operationType: OperationType,
    target: string | null = null,
    targetId: string | null = null,
    detail: Record<string, any> = {},
    page: string = '',
    component: string = '',
    result: string = 'success'
  ): void {
    if (!this.initialized) return;

    const op: AuditOperation = {
      id: `op-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
      session_id: this.sessionId,
      user_id: this.userId,
      user_name: this.userName,
      operation_type: operationType,
      timestamp: new Date().toISOString(),
      target,
      target_id: targetId,
      detail,
      client_ip: '',
      user_agent: navigator.userAgent,
      page: page || window.location.pathname,
      component,
      result,
      error_message: null,
      previous_hash: null,
      current_hash: '',
    };
    this.operationBuffer.push(op);

    if (this.operationBuffer.length >= 50) {
      this.flushOperations();
    }
  }

  recordServerSelect(serverId: string, serverName: string, selected: boolean): void {
    this.recordOperation(
      selected ? 'server_select' : 'server_deselect',
      'server',
      serverId,
      { server_id: serverId, server_name: serverName },
      '',
      'MachineManagement'
    );
  }

  recordTabSwitch(tabKey: string): void {
    this.recordOperation(
      'tab_switch',
      'tab',
      tabKey,
      { tab: tabKey },
      '',
      'App'
    );
    this.captureKeyframe();
  }

  recordPageView(page: string): void {
    this.recordOperation('page_view', 'page', page, { page });
  }

  private async flushOperations(): Promise<void> {
    if (this.operationBuffer.length === 0) return;

    const ops = [...this.operationBuffer];
    this.operationBuffer = [];

    try {
      await auditApi.recordOperations({
        session_id: this.sessionId,
        operations: ops,
      });
    } catch (e) {
      console.warn('Failed to flush audit operations:', e);
      this.operationBuffer = [...ops, ...this.operationBuffer].slice(0, 500);
    }
  }

  private async flushFrames(): Promise<void> {
    if (this.frameBuffer.length === 0) return;

    const frames = [...this.frameBuffer];
    this.frameBuffer = [];

    try {
      await auditApi.saveRecordingFrames({
        session_id: this.sessionId,
        user_id: this.userId,
        user_name: this.userName,
        frames,
      });
    } catch (e) {
      console.warn('Failed to flush recording frames:', e);
      this.frameBuffer = [...frames, ...this.frameBuffer].slice(0, 500);
    }
  }

  async flush(): Promise<void> {
    await Promise.all([this.flushOperations(), this.flushFrames()]);
  }

  async destroy(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    if (this.frameTimer) {
      clearInterval(this.frameTimer);
      this.frameTimer = null;
    }

    this.domListeners.forEach(cleanup => cleanup());
    this.domListeners = [];

    if (this.initialized) {
      this.recordOperation('session_end', 'session', this.sessionId, {});
    }

    await this.flush();

    if (this.sessionId && this.initialized) {
      try {
        await auditApi.endSession(this.sessionId);
      } catch (e) {}
    }

    try {
      localStorage.removeItem('audit_session_id');
    } catch (e) {}

    this.initialized = false;
  }

  getSessionId(): string {
    return this.sessionId;
  }

  isInitialized(): boolean {
    return this.initialized;
  }
}

export function getAuditIdentity(): { userId: string; userName: string } {
  try {
    const raw = localStorage.getItem('audit_user_name');
    if (raw) {
      const userName = decodeURIComponent(raw);
      const userId = localStorage.getItem('audit_user_id') || userName;
      return { userId, userName };
    }
  } catch (e) {}
  return { userId: 'admin', userName: '管理员' };
}

export function setAuditIdentity(userName: string): void {
  const name = userName?.trim() || '管理员';
  const userId = userName?.trim() || 'admin';
  try {
    localStorage.setItem('audit_user_id', userId);
    localStorage.setItem('audit_user_name', encodeURIComponent(name));
  } catch (e) {}
}

export const auditRecorder = new AuditRecorder();
