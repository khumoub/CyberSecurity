'use client';

import { useEffect, useRef, useState, useCallback } from 'react';

interface TerminalLine {
  type: 'output' | 'error' | 'info';
  line: string;
  timestamp: string;
}

type ConnectionStatus = 'idle' | 'connecting' | 'running' | 'completed' | 'failed';

export interface TerminalOutputProps {
  taskId: string | null;
  height?: number;
  onComplete?: (status: string) => void;
  onAbort?: () => void;
}

const statusColors: Record<ConnectionStatus, string> = {
  idle: 'text-[#8892a4] bg-[rgba(136,146,164,0.15)] border-[rgba(136,146,164,0.3)]',
  connecting: 'text-[#ffcc00] bg-[rgba(255,204,0,0.15)] border-[rgba(255,204,0,0.3)]',
  running: 'text-[#00d4ff] bg-[rgba(0,212,255,0.15)] border-[rgba(0,212,255,0.3)]',
  completed: 'text-[#00ff88] bg-[rgba(0,255,136,0.15)] border-[rgba(0,255,136,0.3)]',
  failed: 'text-[#ff3b3b] bg-[rgba(255,59,59,0.15)] border-[rgba(255,59,59,0.3)]',
};

const statusDot: Record<ConnectionStatus, string> = {
  idle: '',
  connecting: 'bg-[#ffcc00] animate-pulse',
  running: 'bg-[#00d4ff] animate-pulse',
  completed: 'bg-[#00ff88]',
  failed: 'bg-[#ff3b3b]',
};

function lineColor(type: TerminalLine['type']): string {
  if (type === 'error') return '#ff3b3b';
  if (type === 'info') return '#00d4ff';
  return '#00ff88';
}

export function TerminalOutput({ taskId, height = 350, onComplete, onAbort }: TerminalOutputProps) {
  const [lines, setLines] = useState<TerminalLine[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>('idle');
  const wsRef = useRef<WebSocket | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const statusRef = useRef<ConnectionStatus>('idle');

  // Keep statusRef in sync
  useEffect(() => {
    statusRef.current = status;
  }, [status]);

  const appendLine = useCallback((type: TerminalLine['type'], line: string, timestamp?: string) => {
    setLines((prev) => [
      ...prev,
      { type, line, timestamp: timestamp || new Date().toISOString() },
    ]);
  }, []);

  useEffect(() => {
    if (!taskId) {
      setLines([]);
      setStatus('idle');
      return;
    }

    const wsUrl = (process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000').replace(/\/$/, '');
    setStatus('connecting');
    setLines([]);

    const ws = new WebSocket(`${wsUrl}/ws/scan/${taskId}`);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus('running');
      appendLine('info', `Connected — task ${taskId}`);
    };

    ws.onmessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data as string) as {
          type: string;
          line?: string;
          timestamp?: string;
        };
        if (data.type === 'output' || data.type === 'error' || data.type === 'info') {
          appendLine(data.type as TerminalLine['type'], data.line || '', data.timestamp);
        } else if (data.type === 'status') {
          const s = data.line as ConnectionStatus;
          if (s === 'completed' || s === 'failed') {
            setStatus(s);
            onComplete?.(s);
          }
        }
      } catch {
        appendLine('output', event.data as string);
      }
    };

    ws.onerror = () => {
      setStatus('failed');
      appendLine('error', 'WebSocket connection error');
    };

    ws.onclose = () => {
      setStatus((prev) => {
        if (prev === 'running' || prev === 'connecting') {
          onComplete?.('completed');
          return 'completed';
        }
        return prev;
      });
    };

    return () => {
      ws.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [taskId]);

  // Auto-scroll
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [lines]);

  const handleAbort = () => {
    if (wsRef.current) {
      wsRef.current.close();
    }
    setStatus('failed');
    appendLine('error', '--- ABORTED BY USER ---');
    onAbort?.();
  };

  const handleDownload = () => {
    const text = lines
      .map((l) => `[${new Date(l.timestamp).toLocaleTimeString('en-US', { hour12: false })}] ${l.line}`)
      .join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `task-${taskId || 'output'}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="rounded-lg border border-[#1e2028] overflow-hidden">
      {/* Header bar */}
      <div className="flex items-center justify-between px-4 py-2 bg-[#0d0f14] border-b border-[#1e2028]">
        <div className="flex items-center gap-3">
          {/* Traffic lights */}
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-[#ff3b3b]" />
            <div className="w-3 h-3 rounded-full bg-[#ffcc00]" />
            <div className="w-3 h-3 rounded-full bg-[#00ff88]" />
          </div>
          <span className="text-xs font-mono text-[#8892a4]">
            {taskId ? `task://${taskId}` : 'terminal — idle'}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {/* Status badge */}
          <span
            className={`flex items-center gap-1.5 text-[11px] font-semibold px-2 py-0.5 rounded border uppercase tracking-wide ${statusColors[status]}`}
          >
            {statusDot[status] && (
              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${statusDot[status]}`} />
            )}
            {status}
          </span>

          {/* Abort button */}
          {(status === 'running' || status === 'connecting') && (
            <button
              onClick={handleAbort}
              className="text-xs text-[#ff3b3b] border border-[rgba(255,59,59,0.3)] bg-[rgba(255,59,59,0.08)] px-2 py-0.5 rounded hover:bg-[rgba(255,59,59,0.2)] transition-colors"
            >
              Abort
            </button>
          )}

          {/* Download button */}
          {lines.length > 0 && (
            <button
              onClick={handleDownload}
              title="Download output as .txt"
              className="text-xs text-[#8892a4] border border-[#1e2028] px-2 py-0.5 rounded hover:border-[#2a2d3a] hover:text-[#e8eaf0] transition-colors flex items-center gap-1"
            >
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="7 10 12 15 17 10" />
                <line x1="12" y1="15" x2="12" y2="3" />
              </svg>
              .txt
            </button>
          )}
        </div>
      </div>

      {/* Terminal body */}
      <div
        className="bg-[#0a0b0d] overflow-y-auto p-4 font-mono"
        style={{ height, fontSize: '12px', lineHeight: '1.6' }}
      >
        {lines.length === 0 && (
          <div className="text-[#3a3d4a] text-xs">
            {taskId ? 'Waiting for output...' : 'No task running. Launch a scan to stream output here.'}
          </div>
        )}
        {lines.map((l, i) => (
          <div key={i} className="flex gap-3">
            <span className="text-[#3a3d4a] text-[11px] shrink-0 mt-0.5 select-none">
              {new Date(l.timestamp).toLocaleTimeString('en-US', { hour12: false })}
            </span>
            <span style={{ color: lineColor(l.type), wordBreak: 'break-all' }}>{l.line}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
