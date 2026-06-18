import React, { useEffect, useRef, useState, useCallback } from 'react';
import {
  Card,
  Button,
  Slider,
  Space,
  Select,
  Tag,
  List,
  Statistic,
  Row,
  Col,
  Empty,
  Spin,
  message,
  Tooltip,
  Progress,
} from 'antd';
import {
  PlayCircleOutlined,
  PauseCircleOutlined,
  StepBackwardOutlined,
  StepForwardOutlined,
  FastBackwardOutlined,
  FastForwardOutlined,
  ReloadOutlined,
  UserOutlined,
  ClockCircleOutlined,
} from '@ant-design/icons';
import dayjs from 'dayjs';
import type { RecordingFrame, AuditOperation, RecordingSession } from '../../types';
import { auditApi } from '../../services/api';

const PLAYBACK_SPEEDS = [0.5, 1, 1.5, 2, 4, 8];

interface Props {
  sessionId: string;
}

const OperationReplay: React.FC<Props> = ({ sessionId }) => {
  const [loading, setLoading] = useState(true);
  const [session, setSession] = useState<RecordingSession | null>(null);
  const [frames, setFrames] = useState<RecordingFrame[]>([]);
  const [operations, setOperations] = useState<AuditOperation[]>([]);
  const [currentFrameIndex, setCurrentFrameIndex] = useState(0);
  const [currentTime, setCurrentTime] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const timerRef = useRef<number | null>(null);
  const startTimeRef = useRef<number>(0);
  const startFrameRef = useRef<number>(0);

  useEffect(() => {
    loadPlaybackData();
    return () => {
      if (timerRef.current) {
        cancelAnimationFrame(timerRef.current);
      }
    };
  }, [sessionId]);

  const loadPlaybackData = async () => {
    setLoading(true);
    try {
      const data = await auditApi.getPlaybackData(sessionId);
      setSession(data.session);
      setFrames(data.frames);
      setOperations(data.operations || []);
      if (data.frames.length > 0) {
        setCurrentTime(data.frames[0].timestamp);
      }
    } catch (e) {
      console.error('Failed to load playback data:', e);
      message.error('加载回放数据失败');
    } finally {
      setLoading(false);
    }
  };

  const updatePlayback = useCallback(() => {
    if (!isPlaying || frames.length === 0) return;

    const now = performance.now();
    const elapsed = (now - startTimeRef.current) * playbackSpeed;
    const targetTime = frames[startFrameRef.current].timestamp + elapsed;

    let nextIndex = startFrameRef.current;
    while (nextIndex < frames.length - 1 && frames[nextIndex + 1].timestamp <= targetTime) {
      nextIndex++;
    }

    if (nextIndex >= frames.length - 1) {
      setCurrentFrameIndex(frames.length - 1);
      setCurrentTime(frames[frames.length - 1].timestamp);
      setIsPlaying(false);
      return;
    }

    setCurrentFrameIndex(nextIndex);
    setCurrentTime(targetTime);
    timerRef.current = requestAnimationFrame(updatePlayback);
  }, [isPlaying, frames, playbackSpeed]);

  useEffect(() => {
    if (isPlaying) {
      startTimeRef.current = performance.now();
      startFrameRef.current = currentFrameIndex;
      timerRef.current = requestAnimationFrame(updatePlayback);
    } else if (timerRef.current) {
      cancelAnimationFrame(timerRef.current);
      timerRef.current = null;
    }
    return () => {
      if (timerRef.current) {
        cancelAnimationFrame(timerRef.current);
      }
    };
  }, [isPlaying, updatePlayback, currentFrameIndex]);

  const handlePlayPause = () => {
    if (frames.length === 0) return;
    setIsPlaying(!isPlaying);
  };

  const handleStop = () => {
    setIsPlaying(false);
    setCurrentFrameIndex(0);
    setCurrentTime(frames[0]?.timestamp || 0);
  };

  const handleJumpToKeyframe = (direction: 'prev' | 'next') => {
    if (!session || frames.length === 0) return;

    const keyframeIndices = session.keyframe_indices || [];
    if (keyframeIndices.length === 0) return;

    let targetIdx: number;
    if (direction === 'prev') {
      const candidates = keyframeIndices.filter(i => i < currentFrameIndex);
      targetIdx = candidates.length > 0 ? candidates[candidates.length - 1] : keyframeIndices[0];
    } else {
      const candidates = keyframeIndices.filter(i => i > currentFrameIndex);
      targetIdx = candidates.length > 0 ? candidates[0] : keyframeIndices[keyframeIndices.length - 1];
    }
    targetIdx = Math.max(0, Math.min(frames.length - 1, targetIdx));
    setCurrentFrameIndex(targetIdx);
    setCurrentTime(frames[targetIdx].timestamp);
    if (isPlaying) {
      setIsPlaying(false);
      setTimeout(() => setIsPlaying(true), 50);
    }
  };

  const handleSeek = (value: number) => {
    if (frames.length === 0) return;
    const targetIdx = Math.max(0, Math.min(frames.length - 1, value));
    setCurrentFrameIndex(targetIdx);
    setCurrentTime(frames[targetIdx].timestamp);
    if (isPlaying) {
      setIsPlaying(false);
      setTimeout(() => setIsPlaying(true), 50);
    }
  };

  const handleJumpToTime = async (targetTimestamp: number) => {
    try {
      const result = await auditApi.jumpToFrame(sessionId, targetTimestamp);
      setCurrentFrameIndex(result.target_index);
      setCurrentTime(result.target_frame.timestamp);
      if (isPlaying) {
        setIsPlaying(false);
        setTimeout(() => setIsPlaying(true), 50);
      }
    } catch (e) {
      message.error('跳转失败');
    }
  };

  const formatTime = (ms: number) => {
    const totalSeconds = Math.floor(ms / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    const millis = Math.floor((ms % 1000) / 10);
    return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}.${millis.toString().padStart(2, '0')}`;
  };

  const getOperationsAtCurrentTime = () => {
    if (!session || operations.length === 0) return [];
    const sessionStart = dayjs(session.start_time).valueOf();
    const currentAbsoluteMs = sessionStart + currentTime;

    return operations.filter(op => {
      const opTime = dayjs(op.timestamp).valueOf();
      return opTime <= currentAbsoluteMs;
    }).slice(-20);
  };

  const currentFrame = frames[currentFrameIndex];
  const snapshotHtml = (currentFrame?.data?.dom_snapshot as string | undefined) || '';
  const replaySrcDoc = snapshotHtml
    ? `<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:12px;margin:8px;color:#333;background:#fff;line-height:1.5;} *{max-width:100%;box-sizing:border-box;} img,svg{display:none;} input,button,textarea,select{font:inherit;margin:2px;} .ant-tag{display:inline-block;padding:0 6px;border:1px solid #d9d9d9;border-radius:2px;margin:2px;font-size:11px;}</style></head><body>${snapshotHtml}</body></html>`
    : '';
  const visibleOperations = getOperationsAtCurrentTime();
  const duration = frames.length > 0 ? frames[frames.length - 1].timestamp - frames[0].timestamp : 0;
  const progress = duration > 0 ? ((currentTime - (frames[0]?.timestamp || 0)) / duration) * 100 : 0;

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: 60 }}>
        <Spin size="large" tip="加载回放数据中..." />
      </div>
    );
  }

  if (frames.length === 0) {
    return <Empty description="该会话暂无操作录像数据" />;
  }

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Row gutter={16}>
        <Col span={8}>
          <Card size="small">
            <Statistic
              title="用户"
              value={session?.user_name || '-'}
              prefix={<UserOutlined />}
            />
          </Card>
        </Col>
        <Col span={8}>
          <Card size="small">
            <Statistic
              title="总帧数"
              value={frames.length}
              suffix="帧"
            />
          </Card>
        </Col>
        <Col span={8}>
          <Card size="small">
            <Statistic
              title="总时长"
              value={formatTime(duration)}
              prefix={<ClockCircleOutlined />}
            />
          </Card>
        </Col>
      </Row>

      <Card
        size="small"
        title={
          <Space>
            <span>播放控制</span>
            <Tag color="blue">
              关键帧: {session?.keyframe_indices?.length || 0} 个
            </Tag>
            <Tag color="green">
              操作: {operations.length} 条
            </Tag>
          </Space>
        }
      >
        <Space direction="vertical" size="middle" style={{ width: '100%' }}>
          <Space style={{ width: '100%', justifyContent: 'center' }} size="middle">
            <Tooltip title="上一关键帧">
              <Button
                icon={<FastBackwardOutlined />}
                onClick={() => handleJumpToKeyframe('prev')}
                size="large"
              />
            </Tooltip>
            <Tooltip title="上一帧">
              <Button
                icon={<StepBackwardOutlined />}
                onClick={() => handleSeek(currentFrameIndex - 1)}
                size="large"
                disabled={currentFrameIndex <= 0}
              />
            </Tooltip>
            <Button
              type="primary"
              shape="circle"
              size="large"
              icon={isPlaying ? <PauseCircleOutlined /> : <PlayCircleOutlined />}
              onClick={handlePlayPause}
              style={{ width: 56, height: 56, fontSize: 24 }}
            />
            <Tooltip title="下一帧">
              <Button
                icon={<StepForwardOutlined />}
                onClick={() => handleSeek(currentFrameIndex + 1)}
                size="large"
                disabled={currentFrameIndex >= frames.length - 1}
              />
            </Tooltip>
            <Tooltip title="下一关键帧">
              <Button
                icon={<FastForwardOutlined />}
                onClick={() => handleJumpToKeyframe('next')}
                size="large"
              />
            </Tooltip>
            <Tooltip title="重新播放">
              <Button icon={<ReloadOutlined />} onClick={handleStop} size="large" />
            </Tooltip>
            <Select
              value={playbackSpeed}
              onChange={setPlaybackSpeed}
              style={{ width: 100 }}
              size="large"
              suffixIcon={<span>x</span>}
            >
              {PLAYBACK_SPEEDS.map(s => (
                <Select.Option key={s} value={s}>{s}x</Select.Option>
              ))}
            </Select>
          </Space>

          <div style={{ padding: '0 16px' }}>
            <Progress
              percent={progress}
              showInfo={false}
              strokeColor="#1890ff"
              style={{ marginBottom: 8 }}
            />
            <Slider
              min={0}
              max={frames.length - 1}
              value={currentFrameIndex}
              onChange={handleSeek}
              tooltip={{
                formatter: (value) => `帧 ${value} / ${frames.length - 1} - ${formatTime(frames[value ?? 0]?.timestamp || 0)}`,
              }}
              marks={
                (session?.keyframe_indices || []).reduce((acc, idx) => {
                  if (frames.length > 10 && idx % Math.ceil(frames.length / 10) < frames.length) {
                    acc[idx] = { style: { color: '#52c41a' }, label: '|' };
                  } else if (frames.length <= 10) {
                    acc[idx] = { style: { color: '#52c41a' }, label: '|' };
                  }
                  return acc;
                }, {} as Record<number, any>)
              }
            />
            <Space style={{ width: '100%', justifyContent: 'space-between' }}>
              <span style={{ fontFamily: 'monospace', color: '#666' }}>
                {formatTime(currentTime - (frames[0]?.timestamp || 0))}
              </span>
              <span style={{ color: '#999' }}>
                当前帧: {currentFrameIndex} / {frames.length - 1}
                {currentFrame?.is_keyframe && <Tag color="green" style={{ marginLeft: 8 }}>关键帧</Tag>}
              </span>
              <span style={{ fontFamily: 'monospace', color: '#666' }}>
                {formatTime(duration)}
              </span>
            </Space>
          </div>
        </Space>
      </Card>

      <Card
        size="small"
        title={
          <Space>
            <span>界面回放快照</span>
            {snapshotHtml ? (
              <Tag color="green">关键帧已还原</Tag>
            ) : (
              <Tag color="default">非关键帧·无快照</Tag>
            )}
            {currentFrame?.data?.url && (
              <Tooltip title={currentFrame.data.url as string}>
                <span style={{ color: '#999', fontSize: 12, maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'inline-block', verticalAlign: 'middle' }}>
                  {currentFrame.data.url as string}
                </span>
              </Tooltip>
            )}
          </Space>
        }
      >
        {snapshotHtml ? (
          <iframe
            key={currentFrame?.frame_id}
            title="操作回放"
            sandbox=""
            srcDoc={replaySrcDoc}
            style={{ width: '100%', height: 380, border: '1px solid #e8e8e8', borderRadius: 4, background: '#fff' }}
          />
        ) : (
          <div style={{ padding: 24, color: '#999', textAlign: 'center' }}>
            当前帧为非关键帧，未捕获界面快照。使用「上一/下一关键帧」按钮跳转至关键帧即可查看界面还原。
          </div>
        )}
      </Card>

      <Card size="small" title={`操作时间线 (${visibleOperations.length}/${operations.length})`}>
        <div style={{ maxHeight: 300, overflow: 'auto' }}>
          {visibleOperations.length > 0 ? (
            <List
              size="small"
              dataSource={visibleOperations}
              locale={{ emptyText: '暂无操作记录' }}
              renderItem={(op) => (
                <List.Item>
                  <Space style={{ width: '100%' }}>
                    <span style={{ fontFamily: 'monospace', color: '#666', minWidth: 140 }}>
                      {dayjs(op.timestamp).format('HH:mm:ss.SSS')}
                    </span>
                    <Tag color="blue" style={{ minWidth: 100 }}>
                      {op.operation_type}
                    </Tag>
                    <span style={{ color: '#1890ff' }}>{op.user_name}</span>
                    <span style={{ color: '#666' }}>
                      {op.target ? `${op.target}${op.target_id ? ` (${op.target_id})` : ''}` : ''}
                    </span>
                    <span style={{ color: '#999', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {Object.keys(op.detail || {}).length > 0 ? JSON.stringify(op.detail) : ''}
                    </span>
                  </Space>
                </List.Item>
              )}
            />
          ) : (
            <Empty description="暂无操作" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          )}
        </div>
      </Card>
    </Space>
  );
};

export default OperationReplay;
