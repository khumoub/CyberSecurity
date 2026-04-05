'use client';

import { useEffect, useRef, useState } from 'react';

interface TerminalLine {
  type: 'output' | 'error' | 'info';
  line: string;
  timestamp: string;
}

type ConnectionStatus = 'connecting' | 'running' | 'completed' | 'failed' | 'idle';

interface TerminalOutputProps {
  taskId: string | null;
  height?: number;
}

const statusColors: Record<ConnectionStatus, string> = {
  idle: 'text-[#8892a4] bg-[rgba(136,146,164,0.15)] border-[rgba(136,146,164,0.3)]',
  connecting: 'text-[#ffcc00] bg-[rgba(255,204,0,0.15)] border-[rgba(255,204,0,0.3)]',
  running: 'text-[#00d4ff] bg-[rgba(0,212,255,0.15)] border-[rgba(0,212,255,0.3)]',
  completed: 'text-[#00ff88] bg-[rgba(0,255,136,0.15)] border-[rgba(0,255,136,0.3)]',
  failed: 'text-[#ff3b3b] bg-[rgba(255,59,59,0.15)] border-[rgba(255,59,59,0.3)]',
};

export function TerminalOutput({ taskId, height = 400 }: TerminalOutputProps) {
  const [lines, setLines] = useState<TerminalLine[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>('idle');
  const wsRef = useRef<WebSocket | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!taskId) return;

    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000';
    setStatus('connecting');
    setLines([]);

    const ws = new WebSocket(`${wsUrl}/ws/scan/${taskId}`);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus('running');
      setLines((prev) => [
        ...prev,
        {
          type: 'info',
          line: `Connected to task ${taskId}`,
          timestamp: new Date().toISOString(),
        },
      ]);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as { type: string; line?: string; timestamp?: string };
        if (data.type === 'output' || data.type === 'error' || data.type === 'info') {
          setLines((prev) => [
            ...prev,
            {
              type: data.type as TerminalLine['type'],
              line: data.line || '',
              timestamp: data.timestamp || new Date().toISOString(),
            },
          ]);
        } else if (data.type === 'status') {
          if (data.line === 'completed') setStatus('completed');
          else if (data.line === 'failed') setStatus('failed');
        }
      } catch {
        // raw text fallback
        setLines((prev) => [
          ...prev,
          { type: 'output', line: event.data, timestamp: new Date().toISOString() },
        ]);
      }
    };

    ws.onerror = () => {
      setStatus('failed');
      setLines((prev) => [
        ...prev,
        { type: 'error', line: 'WebSocket connection error', timestamp: new Date().toISOString() },
      ]);
    };

    ws.onclose = () => {
      if (status === 'running') setStatus('completed');
    };

    return () => {
      ws.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [taskId]);

  // Auto-scroll to bottom
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [lines]);

  const handleAbort = () => {
    wsRef.current?.close();
    setStatus('failed');
    setLines((prev) => [
      ...prev,
      { type: 'error', line: '--- ABORTED BY USER ---', timestamp: new Date().toISOString() },
    ]);
  };

  const lineColor = (type: TerminalLine['type']) => {
    if (type === 'error') return '#ff3b3b';
    if (type === 'info') return '#00d4ff';
    return '#00ff88';
  };

  return (
    <div className="rounded-lg border border-[#1e2028] overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-[#0d0f14] border-b border-[#1e2028]">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-[#ff3b3b]" />
            <div className="w-3 h-3 rounded-full bg-[#ffcc00]" />
            <div className="w-3 h-3 rounded-full bg-[#00ff88]" />
          </div>
          <span className="text-xs font-mono text-[#8892a4]">
            {taskId ? `task://${taskId}` : 'terminal'}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span
            className={`text-xs font-semibold px-2 py-0.5 rounded border uppercase tracking-wide ${statusColors[status]}`}
          >
            {status}
          </span>
          {(status === 'running' || status === 'connecting') && (
            <button
              onClick={handleAbort}
              className="text-xs text-[#ff3b3b] border border-[rgba(255,59,59,0.3)] bg-[rgba(255,59,59,0.1)] px-2 py-0.5 rounded hover:bg-[rgba(255,59,59,0.2)] transition-colors"
            >
              Abort
            </button>
          )}
        </div>
      </div>

      {/* Terminal body */}
      <div
        className="bg-[#0a0b0d] overflow-y-auto p-4 font-mono text-sm"
        style={{ height }}
      >
        {lines.length === 0 && (
          <div className="text-[#8892a4] text-xs">
            {taskId ? 'Connecting...' : 'No task running. Launch a scan to see output here.'}
          </div>
        )}
        {lines.map((l, i) => (
          <div key={i} className="flex gap-3 leading-5">
            <span className="text-[#3a3d4a] text-xs shrink-0 mt-0.5">
              {new Date(l.timestamp).toLocaleTimeString('en-US', { hour12: false })}
            </span>
            <span style={{ color: lineColor(l.type) }}>{l.line}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
