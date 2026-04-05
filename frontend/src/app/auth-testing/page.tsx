'use client';

import { useState } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { TerminalOutput } from '@/components/ui/TerminalOutput';

interface AuthTool {
  id: string;
  name: string;
  binary: string;
  description: string;
  tags: string[];
  accentColor: string;
  requiredAuth: boolean;
  icon: React.ReactNode;
}

const authTools: AuthTool[] = [
  {
    id: 'hydra',
    name: 'Multi-Protocol Login Test',
    binary: 'hydra',
    description: 'Credential brute-forcing and password spraying across SSH, FTP, HTTP, RDP, SMB, Telnet, MySQL, PostgreSQL and 50+ protocols.',
    tags: ['hydra', 'medusa', 'SSH', 'RDP', 'SMB'],
    accentColor: '#ff3b3b',
    requiredAuth: true,
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    ),
  },
  {
    id: 'hashid',
    name: 'Hash Identification',
    binary: 'hashid',
    description: 'Identify hash type from sample — supports MD5, SHA-1, SHA-256, NTLM, bcrypt, scrypt, Argon2 and 300+ other hash formats.',
    tags: ['hashid', 'Hash Analysis', 'Passive'],
    accentColor: '#ffcc00',
    requiredAuth: false,
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <polyline points="4 7 4 4 20 4 20 7" />
        <line x1="9" y1="20" x2="15" y2="20" />
        <line x1="12" y1="4" x2="12" y2="20" />
      </svg>
    ),
  },
  {
    id: 'hashcat',
    name: 'Hash Analysis & Crack Estimation',
    binary: 'hashcat',
    description: 'GPU-accelerated hash cracking with dictionary, rule-based, mask, combination and brute-force attacks. Benchmark mode available.',
    tags: ['hashcat', 'john', 'GPU', 'Dictionary'],
    accentColor: '#ff6b35',
    requiredAuth: true,
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
      </svg>
    ),
  },
  {
    id: 'wordlist',
    name: 'Wordlist Manager',
    binary: 'wordlist-mgr',
    description: 'Manage, generate and combine wordlists. Includes SecLists, rockyou, Seclists and custom rule-based mutation with hashcat rules.',
    tags: ['Wordlist', 'SecLists', 'rockyou'],
    accentColor: '#4fc3f7',
    requiredAuth: false,
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="8" y1="13" x2="16" y2="13" />
        <line x1="8" y1="17" x2="16" y2="17" />
        <polyline points="10 9 9 9 8 9" />
      </svg>
    ),
  },
  {
    id: 'default-creds',
    name: 'Default Credential Checker',
    binary: 'default-creds',
    description: 'Test devices and services against known default credential pairs. Database covers routers, switches, cameras, printers and common apps.',
    tags: ['Default Creds', 'IoT', 'Network'],
    accentColor: '#00d4ff',
    requiredAuth: false,
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
      </svg>
    ),
  },
];

interface LaunchModalProps {
  tool: AuthTool;
  onClose: () => void;
}

function LaunchModal({ tool, onClose }: LaunchModalProps) {
  const [target, setTarget] = useState('');
  const [protocol, setProtocol] = useState('ssh');
  const [wordlist, setWordlist] = useState('/usr/share/wordlists/rockyou.txt');
  const [taskId, setTaskId] = useState<string | null>(null);
  const [accepted, setAccepted] = useState(false);

  const protocols = ['ssh', 'ftp', 'rdp', 'smb', 'http', 'https', 'telnet', 'mysql', 'postgresql', 'vnc'];

  const handleLaunch = () => {
    if (!target.trim() || !accepted) return;
    setTaskId(`task-${tool.id}-${Date.now()}`);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#111318] border border-[#1e2028] rounded-xl w-full max-w-2xl mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2028]">
          <div className="flex items-center gap-3">
            <span style={{ color: tool.accentColor }}>{tool.icon}</span>
            <div>
              <h3 className="text-base font-bold text-[#e8eaf0]">{tool.name}</h3>
              <span className="font-mono text-xs text-[#8892a4]">{tool.binary}</span>
            </div>
          </div>
          <button onClick={onClose} className="text-[#8892a4] hover:text-[#e8eaf0]">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
        <div className="p-6 space-y-4">
          {!taskId ? (
            <>
              <div className="bg-[rgba(255,59,59,0.08)] border border-[rgba(255,59,59,0.3)] rounded-lg px-4 py-3">
                <div className="flex items-start gap-2">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ff3b3b" strokeWidth="2" className="mt-0.5 shrink-0">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                    <line x1="12" y1="9" x2="12" y2="13" />
                    <line x1="12" y1="17" x2="12.01" y2="17" />
                  </svg>
                  <div>
                    <div className="text-xs font-bold text-[#ff3b3b] mb-1">Authorization Required</div>
                    <div className="text-xs text-[#8892a4]">
                      This tool performs credential testing. Unauthorized use against systems you do not own or have written permission to test is illegal and may result in criminal prosecution.
                    </div>
                  </div>
                </div>
                <label className="flex items-center gap-2 mt-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={accepted}
                    onChange={(e) => setAccepted(e.target.checked)}
                    className="w-4 h-4 accent-[#ff3b3b]"
                  />
                  <span className="text-xs text-[#e8eaf0]">I confirm I have written authorization to test this target</span>
                </label>
              </div>
              <div>
                <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">Target</label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="10.0.1.45 or ssh://target.corp.com"
                  className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff]"
                />
              </div>
              {(tool.id === 'hydra' || tool.id === 'default-creds') && (
                <div>
                  <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">Protocol</label>
                  <select
                    value={protocol}
                    onChange={(e) => setProtocol(e.target.value)}
                    className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm text-[#e8eaf0] focus:outline-none focus:border-[#00d4ff]"
                  >
                    {protocols.map((p) => (
                      <option key={p} value={p}>{p.toUpperCase()}</option>
                    ))}
                  </select>
                </div>
              )}
              {(tool.id === 'hydra' || tool.id === 'hashcat') && (
                <div>
                  <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">Wordlist Path</label>
                  <input
                    type="text"
                    value={wordlist}
                    onChange={(e) => setWordlist(e.target.value)}
                    className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm font-mono text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff]"
                  />
                </div>
              )}
              <div className="flex gap-3">
                <button
                  onClick={handleLaunch}
                  disabled={!accepted}
                  className="cyber-btn text-sm disabled:opacity-40 disabled:cursor-not-allowed"
                  style={{ background: accepted ? tool.accentColor : undefined }}
                >
                  Launch {tool.binary}
                </button>
                <button onClick={onClose} className="cyber-btn-ghost text-sm">Cancel</button>
              </div>
            </>
          ) : (
            <TerminalOutput taskId={taskId} height={350} />
          )}
        </div>
      </div>
    </div>
  );
}

export default function AuthTestingPage() {
  const [activeTool, setActiveTool] = useState<AuthTool | null>(null);

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6 min-h-full">
        {/* Red authorization banner */}
        <div className="flex items-center gap-4 bg-[rgba(255,59,59,0.1)] border border-[rgba(255,59,59,0.4)] rounded-lg px-5 py-4">
          <div className="w-10 h-10 rounded-lg bg-[rgba(255,59,59,0.2)] flex items-center justify-center shrink-0">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#ff3b3b" strokeWidth="2">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
          </div>
          <div>
            <div className="text-sm font-bold text-[#ff3b3b] uppercase tracking-wide">
              AUTHORIZED TESTING ONLY — All activity logged
            </div>
            <div className="text-xs text-[#8892a4] mt-0.5">
              Unauthorized use of these tools is prohibited and may constitute a criminal offense under the Computer Fraud and Abuse Act (CFAA) and equivalent laws. All sessions are recorded and attributed to your account.
            </div>
          </div>
        </div>

        <div>
          <h1 className="text-xl font-bold text-[#e8eaf0]">Authentication Testing</h1>
          <p className="text-[#8892a4] text-sm mt-0.5">Credential testing, hash analysis and wordlist management — authorized testing only</p>
        </div>

        <div className="grid grid-cols-3 gap-4">
          {authTools.map((tool) => (
            <div
              key={tool.id}
              className="bg-[#111318] border border-[#1e2028] rounded-lg p-5 hover:border-[#2a2d3a] transition-all"
            >
              <div className="flex items-start justify-between mb-3">
                <div
                  className="w-11 h-11 rounded-lg flex items-center justify-center"
                  style={{ background: `${tool.accentColor}15` }}
                >
                  <span style={{ color: tool.accentColor }}>{tool.icon}</span>
                </div>
                {tool.requiredAuth && (
                  <span className="text-[10px] font-bold text-[#ff3b3b] bg-[rgba(255,59,59,0.12)] border border-[rgba(255,59,59,0.4)] px-2 py-0.5 rounded uppercase tracking-wide">
                    Auth Required
                  </span>
                )}
              </div>
              <h3 className="text-sm font-bold text-[#e8eaf0] mb-0.5">{tool.name}</h3>
              <div className="font-mono text-[10px] text-[#8892a4] mb-2">{tool.binary}</div>
              <p className="text-xs text-[#8892a4] leading-relaxed mb-4">{tool.description}</p>
              <div className="flex items-center justify-between">
                <div className="flex flex-wrap gap-1">
                  {tool.tags.map((tag) => (
                    <span key={tag} className="text-[10px] px-1.5 py-0.5 rounded bg-[#1e2028] text-[#8892a4]">
                      {tag}
                    </span>
                  ))}
                </div>
                <button
                  onClick={() => setActiveTool(tool)}
                  className="text-sm font-semibold px-3 py-1.5 rounded-md transition-all border"
                  style={{
                    color: tool.accentColor,
                    borderColor: `${tool.accentColor}40`,
                    background: `${tool.accentColor}10`,
                  }}
                >
                  Launch
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {activeTool && (
        <LaunchModal tool={activeTool} onClose={() => setActiveTool(null)} />
      )}
    </DashboardLayout>
  );
}
