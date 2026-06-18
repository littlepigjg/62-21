import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider, App as AntApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import App from './App';
import { wsService } from './services/websocket';
import { auditRecorder, getAuditIdentity } from './services/auditRecorder';
import 'xterm/css/xterm.css';
import './index.css';

wsService.connect();

const auditIdentity = getAuditIdentity();
auditRecorder.init(auditIdentity.userId, auditIdentity.userName).catch(() => {});

const handleVisibilityFlush = () => {
  if (document.visibilityState === 'hidden') {
    auditRecorder.flush();
  }
};
window.addEventListener('beforeunload', () => {
  auditRecorder.flush();
});
document.addEventListener('visibilitychange', handleVisibilityFlush);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#1677ff' } }}>
      <AntApp>
        <App />
      </AntApp>
    </ConfigProvider>
  </React.StrictMode>,
);
