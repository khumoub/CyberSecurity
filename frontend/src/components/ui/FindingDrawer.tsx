'use client';

import { useEffect, useRef, useState } from 'react';
import { SeverityBadge } from './SeverityBadge';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
type FindingStatus = 'open' | 'in_remediation' | 'resolved' | 'accepted_risk';

export interface FindingDetail {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cvss_score?: number;
  cve_id?: string | null;
  cwe_id?: string | null;
  asset: string;
  port?: string | null;
  service?: string | null;
  component?: string | null;
  mitre_technique?: string | null;
  known_exploited?: boolean;
  exploit_available?: boolean;
  remediation?: string;
  raw_output?: string;
  status: FindingStatus;
  assigned_to?: string | null;
  discovered?: string;
}

export interface FindingDrawerProps {
  finding: FindingDetail | null;
  onClose: () => void;
  onStatusChange?: (id: string, status: FindingStatus) => void;
  onAssign?: (id: string, userId: string) => void;
  onAddNote?: (id: string, note: string) => void;
}

const statusOptions: { value: FindingStatus; label: string }[] = [
  { value: 'open', label: 'Open' },
  { value: 'in_remediation', label: 'In Remediation' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'accepted_risk', label: 'Accepted Risk' },
];

const statusStyle: Record<FindingStatus, string> = {
  open: 'text-[#ff6b35] bg-[rgba(255,107,53,0.12)] border-[rgba(255,107,53,0.3)]',
  in_remediation: 'text-[#00d4ff] bg-[rgba(0,212,255,0.12)] border-[rgba(0,212,255,0.3)]',
  resolved: 'text-[#00ff88] bg-[rgba(0,255,136,0.12)] border-[rgba(0,255,136,0.3)]',
  accepted_risk: 'text-[#8892a4] bg-[rgba(136,146,164,0.12)] border-[rgba(136,146,164,0.3)]',
};

function CvssBar({ score }: { score: number }) {
  const pct = Math.min(Math.max(score / 10, 0), 1) * 100;
  // Gradient stops: 0=green, 4=yellow, 7=orange, 10=red
  const color =
    score >= 9 ? '#ff3b3b' :
    score >= 7 ? '#ff6b35' :
    score >= 4 ? '#ffcc00' :
    '#00ff88';

  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-[#8892a4]">CVSS Score</span>
        <span className="text-sm font-bold" style={{ color }}>{score.toFixed(1)}</span>
      </div>
      <div className="h-2 rounded-full bg-[#1e2028] overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{
            width: `${pct}%`,
            background: `linear-gradient(90deg, #00ff88, #ffcc00, #ff6b35, #ff3b3b)`,
            backgroundSize: '400% 100%',
            backgroundPosition: `${(score / 10) * 100}% 50%`,
          }}
        />
      </div>
      <div className="flex justify-between text-[10px] text-[#3a3d4a] mt-0.5">
        <span>0</span><span>Low</span><span>Medium</span><span>High</span><span>Critical 10</span>
      </div>
    </div>
  );
}

export function FindingDrawer({ finding, onClose, onStatusChange, onAssign, onAddNote }: FindingDrawerProps) {
  const [rawExpanded, setRawExpanded] = useState(false);
  const [localStatus, setLocalStatus] = useState<FindingStatus>('open');
  const [assignInput, setAssignInput] = useState('');
  const [note, setNote] = useState('');
  const drawerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (finding) {
      setLocalStatus(finding.status);
      setAssignInput(finding.assigned_to || '');
      setRawExpanded(false);
    }
  }, [finding]);

  // ESC to close
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  // Click outside backdrop closes
  const handleBackdropClick = (e: React.MouseEvent) => {
    if (drawerRef.current && !drawerRef.current.contains(e.target as Node)) {
      onClose();
    }
  };

  const handleStatusChange = (s: FindingStatus) => {
    setLocalStatus(s);
    if (finding) onStatusChange?.(finding.id, s);
  };

  const handleAssign = () => {
    if (finding && assignInput.trim()) {
      onAssign?.(finding.id, assignInput.trim());
    }
  };

  const handleAddNote = () => {
    if (finding && note.trim()) {
      onAddNote?.(finding.id, note.trim());
      setNote('');
    }
  };

  return (
    <>
      {/* Overlay */}
      <div
        className={`fixed inset-0 z-40 bg-black/50 backdrop-blur-sm transition-opacity duration-200 ${finding ? 'opacity-100' : 'opacity-0 pointer-events-none'}`}
        onClick={handleBackdropClick}
      />

      {/* Drawer panel */}
      <div
        ref={drawerRef}
        className={`fixed right-0 top-0 bottom-0 z-50 flex flex-col bg-[#0d0f14] border-l border-[#1e2028] shadow-2xl transition-transform duration-300 ease-out overflow-hidden`}
        style={{
          width: '620px',
          transform: finding ? 'translateX(0)' : 'translateX(100%)',
        }}
      >
        {finding && (
          <>
            {/* Header */}
            <div className="flex items-start justify-between px-6 py-4 border-b border-[#1e2028] shrink-0">
              <div className="flex-1 pr-4">
                <div className="flex items-center gap-2 mb-2">
                  <SeverityBadge severity={finding.severity} />
                  {finding.known_exploited && (
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-[rgba(255,59,59,0.2)] text-[#ff3b3b] border border-[rgba(255,59,59,0.4)] uppercase tracking-wide">
                      Known Exploited
                    </span>
                  )}
                  {finding.exploit_available && !finding.known_exploited && (
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-[rgba(255,107,53,0.2)] text-[#ff6b35] border border-[rgba(255,107,53,0.4)] uppercase tracking-wide">
                      Exploit Available
                    </span>
                  )}
                </div>
                <h2 className="text-base font-bold text-[#e8eaf0] leading-snug">{finding.title}</h2>
              </div>
              <button
                onClick={onClose}
                className="text-[#8892a4] hover:text-[#e8eaf0] transition-colors shrink-0 mt-0.5"
              >
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>

            {/* Scrollable body */}
            <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">

              {/* CVSS bar */}
              {finding.cvss_score !== undefined && finding.cvss_score !== null && (
                <CvssBar score={finding.cvss_score} />
              )}

              {/* Description */}
              <div>
                <h3 className="text-xs font-semibold text-[#8892a4] uppercase tracking-widest mb-2">Description</h3>
                <p className="text-sm text-[#b8bcc8] leading-relaxed">{finding.description}</p>
              </div>

              {/* IDs */}
              <div className="grid grid-cols-2 gap-3">
                {finding.cve_id && (
                  <div className="bg-[#111318] border border-[#1e2028] rounded-lg p-3">
                    <div className="text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider mb-1">CVE ID</div>
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm font-mono text-[#00d4ff] hover:underline"
                    >
                      {finding.cve_id}
                    </a>
                  </div>
                )}
                {finding.cwe_id && (
                  <div className="bg-[#111318] border border-[#1e2028] rounded-lg p-3">
                    <div className="text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider mb-1">CWE ID</div>
                    <a
                      href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm font-mono text-[#ffcc00] hover:underline"
                    >
                      {finding.cwe_id}
                    </a>
                  </div>
                )}
              </div>

              {/* Affected */}
              <div>
                <h3 className="text-xs font-semibold text-[#8892a4] uppercase tracking-widest mb-2">Affected</h3>
                <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
                  <div className="flex justify-between border-b border-[#1e2028] pb-1">
                    <span className="text-[#8892a4]">Asset</span>
                    <span className="font-mono text-[#4fc3f7]">{finding.asset}</span>
                  </div>
                  {finding.port && (
                    <div className="flex justify-between border-b border-[#1e2028] pb-1">
                      <span className="text-[#8892a4]">Port</span>
                      <span className="font-mono text-[#e8eaf0]">{finding.port}</span>
                    </div>
                  )}
                  {finding.service && (
                    <div className="flex justify-between border-b border-[#1e2028] pb-1">
                      <span className="text-[#8892a4]">Service</span>
                      <span className="font-mono text-[#e8eaf0]">{finding.service}</span>
                    </div>
                  )}
                  {finding.component && (
                    <div className="flex justify-between border-b border-[#1e2028] pb-1">
                      <span className="text-[#8892a4]">Component</span>
                      <span className="font-mono text-[#e8eaf0]">{finding.component}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* MITRE ATT&CK */}
              {finding.mitre_technique && (
                <div className="bg-[rgba(0,212,255,0.05)] border border-[rgba(0,212,255,0.2)] rounded-lg p-3 flex items-center gap-3">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00d4ff" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
                  </svg>
                  <div>
                    <div className="text-[10px] font-semibold text-[#00d4ff] uppercase tracking-wider">MITRE ATT&amp;CK</div>
                    <div className="text-sm text-[#e8eaf0]">{finding.mitre_technique}</div>
                  </div>
                </div>
              )}

              {/* Remediation */}
              {finding.remediation && (
                <div>
                  <h3 className="text-xs font-semibold text-[#8892a4] uppercase tracking-widest mb-2">Remediation Steps</h3>
                  <div className="bg-[#111318] border border-[#1e2028] rounded-lg p-4 text-sm text-[#b8bcc8] leading-relaxed whitespace-pre-wrap">
                    {finding.remediation}
                  </div>
                </div>
              )}

              {/* Raw output (collapsible) */}
              {finding.raw_output && (
                <div>
                  <button
                    onClick={() => setRawExpanded((v) => !v)}
                    className="flex items-center gap-2 text-xs font-semibold text-[#8892a4] uppercase tracking-widest hover:text-[#e8eaf0] transition-colors mb-2"
                  >
                    <svg
                      width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                      className={`transition-transform ${rawExpanded ? 'rotate-90' : ''}`}
                    >
                      <polyline points="9 18 15 12 9 6" />
                    </svg>
                    Raw Output
                  </button>
                  {rawExpanded && (
                    <div className="bg-[#0a0b0d] border border-[#1e2028] rounded-lg p-4 font-mono text-xs text-[#00ff88] overflow-x-auto max-h-48 overflow-y-auto whitespace-pre">
                      {finding.raw_output}
                    </div>
                  )}
                </div>
              )}

              {/* Status + Assignment + Note */}
              <div className="space-y-4 border-t border-[#1e2028] pt-4">
                <h3 className="text-xs font-semibold text-[#8892a4] uppercase tracking-widest">Triage</h3>

                {/* Status dropdown */}
                <div>
                  <label className="block text-xs text-[#8892a4] mb-1.5">Status</label>
                  <div className="relative">
                    <select
                      value={localStatus}
                      onChange={(e) => handleStatusChange(e.target.value as FindingStatus)}
                      className="w-full appearance-none bg-[#111318] border border-[#1e2028] rounded-lg px-3 py-2 text-sm text-[#e8eaf0] focus:outline-none focus:border-[#00d4ff] cursor-pointer"
                    >
                      {statusOptions.map((opt) => (
                        <option key={opt.value} value={opt.value}>{opt.label}</option>
                      ))}
                    </select>
                    <div className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2">
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#8892a4" strokeWidth="2">
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                    </div>
                  </div>
                  <div className="mt-1.5">
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border uppercase tracking-wide ${statusStyle[localStatus]}`}>
                      {statusOptions.find((o) => o.value === localStatus)?.label}
                    </span>
                  </div>
                </div>

                {/* Assign */}
                <div>
                  <label className="block text-xs text-[#8892a4] mb-1.5">Assign To</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={assignInput}
                      onChange={(e) => setAssignInput(e.target.value)}
                      placeholder="username or email"
                      className="flex-1 bg-[#111318] border border-[#1e2028] rounded-lg px-3 py-2 text-sm text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff]"
                    />
                    <button
                      onClick={handleAssign}
                      className="cyber-btn text-xs px-3"
                    >
                      Assign
                    </button>
                  </div>
                </div>

                {/* Note */}
                <div>
                  <label className="block text-xs text-[#8892a4] mb-1.5">Add Note</label>
                  <textarea
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    placeholder="Add investigation notes, remediation comments..."
                    rows={3}
                    className="w-full bg-[#111318] border border-[#1e2028] rounded-lg px-3 py-2 text-sm text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff] resize-none"
                  />
                  <button
                    onClick={handleAddNote}
                    disabled={!note.trim()}
                    className="mt-2 text-xs cyber-btn-ghost disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    Save Note
                  </button>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </>
  );
}
