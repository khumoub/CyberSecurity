'use client';

import { useState, ReactNode } from 'react';
import { TerminalOutput } from '@/components/ui/TerminalOutput';

export interface ToolPanelProps {
  toolId: string;
  toolName: string;
  binary: string;
  description: string;
  tags: string[];
  category: string;
  accentColor: string;
  authRequired: boolean;
  configForm: ReactNode;
  onLaunch: (config: Record<string, unknown>) => Promise<string | null>;
}

export function ToolPanel({
  toolId,
  toolName,
  binary,
  description,
  tags,
  category,
  accentColor,
  authRequired,
  configForm,
  onLaunch,
}: ToolPanelProps) {
  const [expanded, setExpanded] = useState(false);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [launching, setLaunching] = useState(false);

  const handleLaunch = async () => {
    setLaunching(true);
    try {
      const id = await onLaunch({});
      if (id) setTaskId(id);
    } finally {
      setLaunching(false);
    }
  };

  const handleReset = () => {
    setTaskId(null);
    setExpanded(true);
  };

  return (
    <div
      className="bg-[#111318] border rounded-lg transition-all duration-200"
      style={{ borderColor: expanded ? `${accentColor}40` : '#1e2028' }}
    >
      {/* Card header — always visible */}
      <div className="p-5">
        <div className="flex items-start justify-between mb-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-0.5 flex-wrap">
              <span className="text-sm font-bold text-[#e8eaf0]">{toolName}</span>
              {authRequired && (
                <span className="text-[9px] font-bold text-[#ff3b3b] bg-[rgba(255,59,59,0.12)] border border-[rgba(255,59,59,0.4)] px-1.5 py-0.5 rounded uppercase tracking-wide">
                  Auth Required
                </span>
              )}
            </div>
            <div className="font-mono text-[10px] text-[#8892a4]">{binary}</div>
          </div>
          <span
            className="text-[10px] font-medium px-2 py-0.5 rounded shrink-0 ml-2"
            style={{ color: accentColor, background: `${accentColor}10` }}
          >
            {category}
          </span>
        </div>

        <p className="text-xs text-[#8892a4] leading-relaxed mb-4">{description}</p>

        <div className="flex items-center justify-between gap-2">
          <div className="flex flex-wrap gap-1">
            {tags.map((tag) => (
              <span key={tag} className="text-[9px] px-1.5 py-0.5 rounded bg-[#1e2028] text-[#8892a4]">
                {tag}
              </span>
            ))}
          </div>
          <button
            onClick={() => setExpanded((v) => !v)}
            className="text-xs font-semibold px-3 py-1.5 rounded-md transition-all border shrink-0"
            style={{
              color: accentColor,
              borderColor: `${accentColor}40`,
              background: expanded ? `${accentColor}20` : `${accentColor}10`,
            }}
          >
            {expanded ? 'Collapse' : 'Launch'}
          </button>
        </div>
      </div>

      {/* Expanded panel */}
      {expanded && (
        <div className="border-t border-[#1e2028] px-5 pb-5 pt-4 space-y-4">
          {/* Auth banner */}
          {authRequired && (
            <div className="bg-[rgba(255,59,59,0.08)] border border-[rgba(255,59,59,0.3)] rounded-lg px-4 py-3">
              <div className="flex items-start gap-2">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#ff3b3b" strokeWidth="2" className="mt-0.5 shrink-0">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                  <line x1="12" y1="9" x2="12" y2="13" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
                <div>
                  <div className="text-[10px] font-bold text-[#ff3b3b] uppercase tracking-wide mb-0.5">
                    AUTHORIZATION REQUIRED
                  </div>
                  <div className="text-[10px] text-[#8892a4]">
                    This tool may be used offensively. You must hold written authorization from the asset owner before proceeding.
                    Unauthorized use is a criminal offence. All sessions are logged and attributed to your account.
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Config form injected by parent */}
          {!taskId && configForm}

          {/* Launch / terminal */}
          {!taskId ? (
            <button
              onClick={handleLaunch}
              disabled={launching}
              className="cyber-btn text-sm flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {launching ? (
                <>
                  <svg className="animate-spin" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                  </svg>
                  Launching…
                </>
              ) : (
                <>
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <polygon points="5 3 19 12 5 21 5 3" />
                  </svg>
                  Run {binary}
                </>
              )}
            </button>
          ) : (
            <div className="space-y-3">
              <TerminalOutput taskId={taskId} height={320} onComplete={() => {}} />
              <button onClick={handleReset} className="cyber-btn-ghost text-xs">
                ← Reconfigure
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
