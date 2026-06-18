import React, { useEffect, useState } from 'react';
import {
  Card,
  Row,
  Col,
  Statistic,
  Table,
  Tag,
  DatePicker,
  Input,
  Select,
  Button,
  Space,
  Modal,
  Form,
  message,
  Tabs,
  List,
  Tooltip,
  Progress,
  Alert,
} from 'antd';
import {
  SafetyCertificateOutlined,
  WarningOutlined,
  UserOutlined,
  FileTextOutlined,
  SearchOutlined,
  PlayCircleOutlined,
  EyeOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import dayjs, { Dayjs } from 'dayjs';
import type {
  AuditOperation,
  AuditAlert,
  AuditStats,
  AuditSession,
  AlertRule,
  AuditQuery,
  AuditAlertQuery,
  OperationType,
  AlertSeverity,
} from '../../types';
import { auditApi } from '../../services/api';
import { auditRecorder, getAuditIdentity, setAuditIdentity } from '../../services/auditRecorder';
import OperationReplay from './OperationReplay';

const { RangePicker } = DatePicker;
const { Option } = Select;

const OPERATION_TYPE_LABELS: Record<OperationType, string> = {
  command_execute: '命令执行',
  script_execute: '脚本执行',
  server_select: '选择服务器',
  server_deselect: '取消选择服务器',
  server_create: '创建服务器',
  server_update: '更新服务器',
  server_delete: '删除服务器',
  server_test: '测试服务器',
  template_create: '创建脚本模板',
  template_update: '更新脚本模板',
  template_delete: '删除脚本模板',
  template_execute: '执行脚本模板',
  tab_switch: '切换标签',
  login: '登录',
  logout: '登出',
  session_start: '会话开始',
  session_end: '会话结束',
  page_view: '页面浏览',
  custom: '自定义操作',
};

const ALERT_SEVERITY_COLOR: Record<AlertSeverity, string> = {
  low: 'blue',
  medium: 'gold',
  high: 'orange',
  critical: 'red',
};

const ALERT_SEVERITY_LABEL: Record<AlertSeverity, string> = {
  low: '低',
  medium: '中',
  high: '高',
  critical: '严重',
};

const ALERT_TYPE_LABELS: Record<string, string> = {
  massive_deletion: '大量删除',
  frequent_server_switch: '频繁切换服务器',
  suspicious_command: '可疑命令',
  abnormal_execution_count: '异常执行次数',
  off_hours_operation: '非工作时间操作',
  privilege_escalation_attempt: '权限提升尝试',
  tampering_detected: '数据篡改检测',
};

const AuditPanel: React.FC = () => {
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [operations, setOperations] = useState<AuditOperation[]>([]);
  const [operationsTotal, setOperationsTotal] = useState(0);
  const [operationsLoading, setOperationsLoading] = useState(false);
  const [alerts, setAlerts] = useState<AuditAlert[]>([]);
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [sessions, setSessions] = useState<AuditSession[]>([]);
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [replayModalVisible, setReplayModalVisible] = useState(false);
  const [replaySessionId, setReplaySessionId] = useState('');
  const [detailModalVisible, setDetailModalVisible] = useState(false);
  const [currentDetail, setCurrentDetail] = useState<AuditOperation | AuditAlert | null>(null);
  const [detailType, setDetailType] = useState<'operation' | 'alert'>('operation');
  const [integrityResult, setIntegrityResult] = useState<any>(null);
  const [integrityLoading, setIntegrityLoading] = useState(false);
  const [auditUserName, setAuditUserName] = useState(getAuditIdentity().userName);
  const [identityLoading, setIdentityLoading] = useState(false);

  const [opQuery, setOpQuery] = useState<AuditQuery>({
    limit: 50,
    offset: 0,
  });
  const [alertQuery, setAlertQuery] = useState<AuditAlertQuery>({
    limit: 100,
  });

  useEffect(() => {
    loadStats();
    loadOperations();
    loadAlerts();
    loadSessions();
    loadRules();
  }, []);

  const loadStats = async () => {
    try {
      const data = await auditApi.getStats(7);
      setStats(data);
    } catch (e) {
      console.error('Failed to load stats:', e);
    }
  };

  const loadOperations = async (query?: AuditQuery) => {
    setOperationsLoading(true);
    try {
      const q = query || opQuery;
      const result = await auditApi.queryOperations(q);
      setOperations(result.items);
      setOperationsTotal(result.total);
    } catch (e) {
      console.error('Failed to load operations:', e);
      message.error('加载操作日志失败');
    } finally {
      setOperationsLoading(false);
    }
  };

  const loadAlerts = async (query?: AuditAlertQuery) => {
    setAlertsLoading(true);
    try {
      const q = query || alertQuery;
      const result = await auditApi.queryAlerts(q);
      setAlerts(result.items);
    } catch (e) {
      console.error('Failed to load alerts:', e);
      message.error('加载告警失败');
    } finally {
      setAlertsLoading(false);
    }
  };

  const loadSessions = async () => {
    try {
      const data = await auditApi.listSessions(undefined, 50);
      setSessions(data);
    } catch (e) {
      console.error('Failed to load sessions:', e);
    }
  };

  const loadRules = async () => {
    try {
      const data = await auditApi.listRules();
      setRules(data);
    } catch (e) {
      console.error('Failed to load rules:', e);
    }
  };

  const handleAcknowledgeAlert = async (alert: AuditAlert) => {
    try {
      const userName = localStorage.getItem('audit_user_name') || 'admin';
      await auditApi.acknowledgeAlert(
        alert.alert_id,
        decodeURIComponent(userName),
        '已确认'
      );
      message.success('告警已确认');
      loadAlerts();
      loadStats();
    } catch (e) {
      message.error('确认告警失败');
    }
  };

  const handleToggleRule = async (rule: AlertRule) => {
    try {
      await auditApi.updateRule({ ...rule, enabled: !rule.enabled });
      message.success(rule.enabled ? '规则已禁用' : '规则已启用');
      loadRules();
    } catch (e) {
      message.error('更新规则失败');
    }
  };

  const handleVerifyIntegrity = async () => {
    setIntegrityLoading(true);
    try {
      const result = await auditApi.verifyIntegrity();
      setIntegrityResult(result);
      if (result.valid) {
        message.success(`数据完整性校验通过，共验证 ${result.verified_count} 条记录`);
      } else {
        message.error(`数据完整性校验失败：${result.error}`);
      }
    } catch (e) {
      message.error('完整性校验失败');
    } finally {
      setIntegrityLoading(false);
    }
  };

  const handleApplyIdentity = async () => {
    setIdentityLoading(true);
    try {
      setAuditIdentity(auditUserName);
      const id = getAuditIdentity();
      await auditRecorder.destroy();
      await auditRecorder.init(id.userId, id.userName);
      message.success('审计身份已更新，新审计会话已开启');
      loadStats();
      loadSessions();
    } catch (e) {
      message.error('更新审计身份失败');
    } finally {
      setIdentityLoading(false);
    }
  };

  const handleViewOperationDetail = (op: AuditOperation) => {
    setCurrentDetail(op);
    setDetailType('operation');
    setDetailModalVisible(true);
  };

  const handleViewAlertDetail = (alert: AuditAlert) => {
    setCurrentDetail(alert);
    setDetailType('alert');
    setDetailModalVisible(true);
  };

  const handleStartReplay = (sessionId: string) => {
    setReplaySessionId(sessionId);
    setReplayModalVisible(true);
  };

  const operationColumns: ColumnsType<AuditOperation> = [
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 180,
      render: (t: string) => dayjs(t).format('YYYY-MM-DD HH:mm:ss'),
    },
    {
      title: '用户',
      dataIndex: 'user_name',
      key: 'user_name',
      width: 120,
      render: (name: string) => (
        <Space>
          <UserOutlined />
          {name}
        </Space>
      ),
    },
    {
      title: '操作类型',
      dataIndex: 'operation_type',
      key: 'operation_type',
      width: 140,
      render: (type: OperationType) => (
        <Tag color="blue">{OPERATION_TYPE_LABELS[type] || type}</Tag>
      ),
    },
    {
      title: '目标',
      dataIndex: 'target',
      key: 'target',
      width: 120,
      render: (t: string | null) => t || '-',
    },
    {
      title: '目标ID',
      dataIndex: 'target_id',
      key: 'target_id',
      width: 200,
      ellipsis: true,
      render: (id: string | null) => id || '-',
    },
    {
      title: '结果',
      dataIndex: 'result',
      key: 'result',
      width: 80,
      render: (r: string) => (
        <Tag color={r === 'success' ? 'green' : 'red'}>
          {r === 'success' ? '成功' : '失败'}
        </Tag>
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: 80,
      render: (_, record) => (
        <Button type="link" size="small" icon={<EyeOutlined />} onClick={() => handleViewOperationDetail(record)}>
          详情
        </Button>
      ),
    },
  ];

  const alertColumns: ColumnsType<AuditAlert> = [
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 180,
      render: (t: string) => dayjs(t).format('YYYY-MM-DD HH:mm:ss'),
    },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (s: AlertSeverity) => (
        <Tag color={ALERT_SEVERITY_COLOR[s]}>
          {ALERT_SEVERITY_LABEL[s]}
        </Tag>
      ),
    },
    {
      title: '告警类型',
      dataIndex: 'alert_type',
      key: 'alert_type',
      width: 160,
      render: (t: string) => (
        <Space>
          <WarningOutlined style={{ color: (ALERT_SEVERITY_COLOR as Record<string, string>)[t] }} />
          {ALERT_TYPE_LABELS[t] || t}
        </Space>
      ),
    },
    {
      title: '规则名称',
      dataIndex: 'rule_name',
      key: 'rule_name',
      width: 180,
    },
    {
      title: '用户',
      dataIndex: 'user_name',
      key: 'user_name',
      width: 120,
      render: (name: string | null) => name || '-',
    },
    {
      title: '状态',
      dataIndex: 'acknowledged',
      key: 'acknowledged',
      width: 100,
      render: (ack: boolean) => (
        <Tag color={ack ? 'green' : 'orange'}>
          {ack ? '已确认' : '待处理'}
        </Tag>
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: 180,
      render: (_, record) => (
        <Space>
          <Button type="link" size="small" icon={<EyeOutlined />} onClick={() => handleViewAlertDetail(record)}>
            详情
          </Button>
          {!record.acknowledged && (
            <Button type="link" size="small" icon={<CheckCircleOutlined />} onClick={() => handleAcknowledgeAlert(record)}>
              确认
            </Button>
          )}
        </Space>
      ),
    },
  ];

  const renderStatsPanel = () => (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      <Card size="small" title={<Space><UserOutlined /> 审计身份（用于定责与多用户检索）</Space>}>
        <Space wrap>
          <Input
            value={auditUserName}
            onChange={e => setAuditUserName(e.target.value)}
            placeholder="输入操作人姓名/工号"
            style={{ width: 240 }}
            prefix={<UserOutlined />}
            onPressEnter={handleApplyIdentity}
          />
          <Button type="primary" loading={identityLoading} onClick={handleApplyIdentity}>
            应用并重置会话
          </Button>
          <span style={{ color: '#999', fontSize: 12 }}>
            切换身份后会结束当前审计会话并开启新会话，后续操作将以新身份记录，支持按用户检索与定责
          </span>
        </Space>
      </Card>

      <Row gutter={16}>
        <Col span={6}>
          <Card>
            <Statistic
              title="总会话数"
              value={stats?.total_sessions || 0}
              prefix={<SafetyCertificateOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="总操作数"
              value={stats?.total_operations || 0}
              prefix={<FileTextOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="总告警数"
              value={stats?.total_alerts || 0}
              prefix={<WarningOutlined />}
              valueStyle={{ color: '#faad14' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Space direction="vertical">
              <Button
                type="primary"
                icon={integrityLoading ? <ReloadOutlined spin /> : <SafetyCertificateOutlined />}
                onClick={handleVerifyIntegrity}
                loading={integrityLoading}
                block
              >
                数据完整性校验
              </Button>
              {integrityResult && (
                <Alert
                  type={integrityResult.valid ? 'success' : 'error'}
                  showIcon
                  message={integrityResult.valid ? '校验通过' : '校验失败'}
                  description={`已验证 ${integrityResult.verified_count} 条记录`}
                />
              )}
            </Space>
          </Card>
        </Col>
      </Row>

      <Row gutter={16}>
        <Col span={12}>
          <Card title="操作类型分布">
            {stats && Object.keys(stats.operations_by_type).length > 0 ? (
              <List
                size="small"
                dataSource={Object.entries(stats.operations_by_type)}
                renderItem={([type, count]) => {
                  const total = Object.values(stats.operations_by_type).reduce((a, b) => a + b, 0) || 1;
                  return (
                    <List.Item>
                      <Space style={{ width: '100%' }}>
                        <Tag color="blue" style={{ minWidth: 120 }}>
                          {OPERATION_TYPE_LABELS[type as OperationType] || type}
                        </Tag>
                        <Progress
                          percent={Math.round((count / total) * 100)}
                          size="small"
                          style={{ flex: 1 }}
                        />
                        <span style={{ minWidth: 50, textAlign: 'right' }}>{count}</span>
                      </Space>
                    </List.Item>
                  );
                }}
              />
            ) : (
              <div style={{ color: '#999', textAlign: 'center', padding: 20 }}>暂无数据</div>
            )}
          </Card>
        </Col>
        <Col span={12}>
          <Card title="告警分布">
            {stats && Object.keys(stats.alerts_by_severity).length > 0 ? (
              <List
                size="small"
                dataSource={Object.entries(stats.alerts_by_severity)}
                renderItem={([severity, count]) => (
                  <List.Item>
                    <Space style={{ width: '100%' }}>
                      <Tag color={ALERT_SEVERITY_COLOR[severity as AlertSeverity]} style={{ minWidth: 80 }}>
                        {ALERT_SEVERITY_LABEL[severity as AlertSeverity]}
                      </Tag>
                      <Progress
                        percent={Math.min(100, count * 10)}
                        size="small"
                        strokeColor={ALERT_SEVERITY_COLOR[severity as AlertSeverity]}
                        style={{ flex: 1 }}
                      />
                      <span style={{ minWidth: 50, textAlign: 'right' }}>{count}</span>
                    </Space>
                  </List.Item>
                )}
              />
            ) : (
              <div style={{ color: '#999', textAlign: 'center', padding: 20 }}>暂无数据</div>
            )}
          </Card>
        </Col>
      </Row>
    </Space>
  );

  const renderOperationsPanel = () => (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Card size="small">
        <Space wrap>
          <RangePicker
            showTime
            onChange={(dates) => {
              setOpQuery(q => ({
                ...q,
                start_time: dates?.[0]?.toISOString(),
                end_time: dates?.[1]?.toISOString(),
              }));
            }}
          />
          <Input
            placeholder="用户名"
            style={{ width: 150 }}
            prefix={<UserOutlined />}
            onChange={(e) => setOpQuery(q => ({ ...q, user_name: e.target.value || undefined }))}
          />
          <Select
            placeholder="操作类型"
            style={{ width: 160 }}
            allowClear
            onChange={(v) => setOpQuery(q => ({ ...q, operation_type: v }))}
          >
            {Object.entries(OPERATION_TYPE_LABELS).map(([k, v]) => (
              <Option key={k} value={k}>{v}</Option>
            ))}
          </Select>
          <Input
            placeholder="关键词搜索"
            style={{ width: 200 }}
            prefix={<SearchOutlined />}
            onChange={(e) => setOpQuery(q => ({ ...q, keyword: e.target.value || undefined }))}
          />
          <Button type="primary" icon={<SearchOutlined />} onClick={() => loadOperations()}>
            查询
          </Button>
          <Button onClick={() => { setOpQuery({ limit: 50, offset: 0 }); loadOperations({ limit: 50, offset: 0 }); }}>
            重置
          </Button>
        </Space>
      </Card>

      <Table
        columns={operationColumns}
        dataSource={operations}
        rowKey="id"
        loading={operationsLoading}
        pagination={{
          total: operationsTotal,
          pageSize: opQuery.limit || 50,
          showSizeChanger: true,
          onChange: (page, pageSize) => {
            const newQuery = { ...opQuery, offset: (page - 1) * pageSize, limit: pageSize };
            setOpQuery(newQuery);
            loadOperations(newQuery);
          },
        }}
        scroll={{ x: 1000 }}
      />
    </Space>
  );

  const renderAlertsPanel = () => (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Card size="small">
        <Space wrap>
          <Select
            placeholder="严重程度"
            style={{ width: 140 }}
            allowClear
            onChange={(v) => setAlertQuery(q => ({ ...q, severity: v }))}
          >
            {Object.entries(ALERT_SEVERITY_LABEL).map(([k, v]) => (
              <Option key={k} value={k}>{v}</Option>
            ))}
          </Select>
          <Select
            placeholder="告警类型"
            style={{ width: 180 }}
            allowClear
            onChange={(v) => setAlertQuery(q => ({ ...q, alert_type: v }))}
          >
            {Object.entries(ALERT_TYPE_LABELS).map(([k, v]) => (
              <Option key={k} value={k}>{v}</Option>
            ))}
          </Select>
          <Select
            placeholder="状态"
            style={{ width: 140 }}
            allowClear
            onChange={(v) => setAlertQuery(q => ({ ...q, acknowledged: v }))}
          >
            <Option value={false}>待处理</Option>
            <Option value={true}>已确认</Option>
          </Select>
          <Button type="primary" icon={<SearchOutlined />} onClick={() => loadAlerts()}>
            查询
          </Button>
          <Button onClick={() => { setAlertQuery({ limit: 100 }); loadAlerts({ limit: 100 }); }}>
            重置
          </Button>
        </Space>
      </Card>

      <Table
        columns={alertColumns}
        dataSource={alerts}
        rowKey="alert_id"
        loading={alertsLoading}
        pagination={{ pageSize: 20 }}
        scroll={{ x: 1000 }}
      />
    </Space>
  );

  const renderRulesPanel = () => (
    <Card title="告警规则配置">
      <List
        dataSource={rules}
        renderItem={(rule) => (
          <List.Item
            actions={[
              <Button
                type={rule.enabled ? 'default' : 'primary'}
                size="small"
                icon={rule.enabled ? <SafetyCertificateOutlined /> : <CheckCircleOutlined />}
                onClick={() => handleToggleRule(rule)}
              >
                {rule.enabled ? '禁用' : '启用'}
              </Button>,
            ]}
          >
            <List.Item.Meta
              avatar={
                <Tag color={ALERT_SEVERITY_COLOR[rule.severity]}>
                  {ALERT_SEVERITY_LABEL[rule.severity]}
                </Tag>
              }
              title={
                <Space>
                  {rule.name}
                  {!rule.enabled && <Tag color="default">已禁用</Tag>}
                </Space>
              }
              description={
                <Space direction="vertical" size="small">
                  <span>{rule.description}</span>
                  <Space size="small">
                    {Object.entries(rule.parameters).map(([k, v]) => (
                      <Tag key={k}>{k}: {JSON.stringify(v)}</Tag>
                    ))}
                  </Space>
                </Space>
              }
            />
          </List.Item>
        )}
      />
    </Card>
  );

  const renderReplayPanel = () => (
    <Card title="操作录像回放">
      {sessions.length > 0 ? (
        <Table
          rowKey="session_id"
          dataSource={sessions}
          columns={[
            {
              title: '会话ID',
              dataIndex: 'session_id',
              key: 'session_id',
              width: 240,
            },
            {
              title: '用户',
              dataIndex: 'user_name',
              key: 'user_name',
              width: 120,
            },
            {
              title: '开始时间',
              dataIndex: 'start_time',
              key: 'start_time',
              width: 180,
              render: (t: string) => dayjs(t).format('YYYY-MM-DD HH:mm:ss'),
            },
            {
              title: '操作次数',
              dataIndex: 'operation_count',
              key: 'operation_count',
              width: 100,
            },
            {
              title: '状态',
              dataIndex: 'status',
              key: 'status',
              width: 100,
              render: (s: string) => (
                <Tag color={s === 'active' ? 'blue' : 'default'}>
                  {s === 'active' ? '进行中' : '已结束'}
                </Tag>
              ),
            },
            {
              title: '操作',
              key: 'action',
              width: 120,
              render: (_, record) => (
                <Tooltip title="回放操作录像">
                  <Button
                    type="primary"
                    size="small"
                    icon={<PlayCircleOutlined />}
                    onClick={() => handleStartReplay(record.session_id)}
                  >
                    回放
                  </Button>
                </Tooltip>
              ),
            },
          ]}
          pagination={{ pageSize: 10 }}
        />
      ) : (
        <div style={{ color: '#999', textAlign: 'center', padding: 40 }}>暂无会话记录</div>
      )}
    </Card>
  );

  const tabItems = [
    {
      key: 'overview',
      label: <span><SafetyCertificateOutlined /> 概览统计</span>,
      children: renderStatsPanel(),
    },
    {
      key: 'operations',
      label: <span><FileTextOutlined /> 操作日志</span>,
      children: renderOperationsPanel(),
    },
    {
      key: 'alerts',
      label: (
        <span>
          <WarningOutlined /> 安全告警
          {alerts.filter(a => !a.acknowledged).length > 0 && (
            <Tag color="red" style={{ marginLeft: 8 }}>
              {alerts.filter(a => !a.acknowledged).length}
            </Tag>
          )}
        </span>
      ),
      children: renderAlertsPanel(),
    },
    {
      key: 'replay',
      label: <span><PlayCircleOutlined /> 操作回放</span>,
      children: renderReplayPanel(),
    },
    {
      key: 'rules',
      label: <span><ExclamationCircleOutlined /> 规则配置</span>,
      children: renderRulesPanel(),
    },
  ];

  return (
    <div style={{ padding: 16 }}>
      <Card title="🔒 安全审计与操作回放">
        <Tabs items={tabItems} size="large" />
      </Card>

      <Modal
        title="操作详情"
        open={detailModalVisible}
        onCancel={() => setDetailModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setDetailModalVisible(false)}>
            关闭
          </Button>,
        ]}
        width={700}
      >
        {currentDetail && detailType === 'operation' && (
          <pre style={{ maxHeight: 400, overflow: 'auto', background: '#f5f5f5', padding: 12, borderRadius: 4 }}>
            {JSON.stringify(currentDetail, null, 2)}
          </pre>
        )}
        {currentDetail && detailType === 'alert' && (
          <pre style={{ maxHeight: 400, overflow: 'auto', background: '#f5f5f5', padding: 12, borderRadius: 4 }}>
            {JSON.stringify(currentDetail, null, 2)}
          </pre>
        )}
      </Modal>

      <Modal
        title="操作录像回放"
        open={replayModalVisible}
        onCancel={() => setReplayModalVisible(false)}
        footer={null}
        width={900}
        destroyOnClose
      >
        {replayModalVisible && replaySessionId && (
          <OperationReplay sessionId={replaySessionId} />
        )}
      </Modal>
    </div>
  );
};

export default AuditPanel;
