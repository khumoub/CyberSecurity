'use client';

import { useState } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { TerminalOutput } from '@/components/ui/TerminalOutput';

interface WebTool {
  id: string;
  name: string;
  binary: string;
  description: string;
  tags: string[];
  accentColor: string;
  riskLevel: 'safe' | 'moderate' | 'aggressive';
  icon: React.ReactNode;
}

const webTools: WebTool[] = [
  {
    id: 'sqlmap',
    name: 'SQL Injection',
    binary: 'sqlmap',
    description: 'Automated SQL injection detection and exploitation. Tests GET/POST parameters, cookies, and HTTP headers for injection flaws.',
    tags: ['SQLi', 'Exploitation', 'sqlmap'],
    accentColor: '#ff3b3b',
    riskLevel: 'aggressive',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <ellipse cx="12" cy="5" rx="9" ry="3" />
        <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" />
        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
      </svg>
    ),
  },
  {
    id: 'gobuster',
    name: 'Directory Discovery',
    binary: 'gobuster',
    description: 'Fast directory and file brute-forcing using wordlists. Discovers hidden paths, admin panels, backup files and API endpoints.',
    tags: ['Dirbusting', 'gobuster', 'dirb'],
    accentColor: '#ff6b35',
    riskLevel: 'moderate',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
      </svg>
    ),
  },
  {
    id: 'wfuzz',
    name: 'Web Fuzzing',
    binary: 'wfuzz',
    description: 'Advanced web application fuzzer for parameters, headers, cookies and URL paths. Supports multiple injection points simultaneously.',
    tags: ['Fuzzing', 'wfuzz', 'Parameters'],
    accentColor: '#ffcc00',
    riskLevel: 'moderate',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M12 20h9" />
        <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" />
      </svg>
    ),
  },
  {
    id: 'wpscan',
    name: 'WordPress Audit',
    binary: 'wpscan',
    description: 'WordPress security scanner — checks plugin/theme vulnerabilities, user enumeration, weak credentials and misconfigurations.',
    tags: ['WordPress', 'CMS', 'wpscan'],
    accentColor: '#4fc3f7',
    riskLevel: 'moderate',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="12" cy="12" r="10" />
        <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
      </svg>
    ),
  },
  {
    id: 'zaproxy',
    name: 'OWASP ZAP',
    binary: 'zaproxy',
    description: 'Full OWASP ZAP active scan for OWASP Top 10 — XSS, CSRF, injection flaws, insecure deserialization, broken auth and more.',
    tags: ['OWASP', 'ZAP', 'Active Scan'],
    accentColor: '#00ff88',
    riskLevel: 'aggressive',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
  },
  {
    id: 'http-viewer',
    name: 'HTTP Request Viewer',
    binary: 'curl',
    description: 'Raw HTTP/HTTPS request and response inspection. View all headers, cookies, redirects, TLS certificates and timing data.',
    tags: ['HTTP', 'curl', 'Inspection'],
    accentColor: '#00d4ff',
    riskLevel: 'safe',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <polyline points="4 17 10 11 4 5" />
        <line x1="12" y1="19" x2="20" y2="19" />
      </svg>
    ),
  },
  {
    id: 'security-headers',
    name: 'Security Headers Audit',
    binary: 'curl+check',
    description: 'Comprehensive HTTP security header analysis — grades CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy.',
    tags: ['Headers', 'CSP', 'HSTS'],
    accentColor: '#8892a4',
    riskLevel: 'safe',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="9" y1="15" x2="15" y2="15" />
        <line x1="9" y1="11" x2="15" y2="11" />
      </svg>
    ),
  },
];

const riskColors = {
  safe: { label: 'Safe', color: 'text-[#00ff88] bg-[rgba(0,255,136,0.1)] border-[rgba(0,255,136,0.3)]' },
  moderate: { label: 'Moderate', color: 'text-[#ffcc00] bg-[rgba(255,204,0,0.1)] border-[rgba(255,204,0,0.3)]' },
  aggressive: { label: 'Aggressive', color: 'text-[#ff3b3b] bg-[rgba(255,59,59,0.1)] border-[rgba(255,59,59,0.3)]' },
};

interface LaunchModalProps {
  tool: WebTool;
  onClose: () => void;
}

function LaunchModal({ tool, onClose }: LaunchModalProps) {
  const [target, setTarget] = useState('');
  const [taskId, setTaskId] = useState<string | null>(null);
  const [opts, setOpts] = useState('');

  const handleLaunch = () => {
    if (!target.trim()) return;
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
          <button onClick={onClose} className="text-[#8892a4] hover:text-[#e8eaf0] transition-colors">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
        <div className="p-6 space-y-4">
          {tool.riskLevel === 'aggressive' && (
            <div className="flex items-center gap-2 bg-[rgba(255,59,59,0.08)] border border-[rgba(255,59,59,0.3)] rounded-lg px-4 py-2.5">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ff3b3b" strokeWidth="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
              <span className="text-xs text-[#ff3b3b]">
                This is an aggressive scan. Only target systems you are authorized to test.
              </span>
            </div>
          )}
          {!taskId ? (
            <>
              <div>
                <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">Target URL</label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://target.example.com"
                  className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff]"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">Additional Options (optional)</label>
                <input
                  type="text"
                  value={opts}
                  onChange={(e) => setOpts(e.target.value)}
                  placeholder="e.g. --level=3 --risk=2"
                  className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff] font-mono"
                />
              </div>
              <div className="flex gap-3">
                <button onClick={handleLaunch} className="cyber-btn text-sm">Launch {tool.binary}</button>
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

export default function WebTestingPage() {
  const [activeTool, setActiveTool] = useState<WebTool | null>(null);

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6 min-h-full">
        <div>
          <h1 className="text-xl font-bold text-[#e8eaf0]">Web Application Testing</h1>
          <p className="text-[#8892a4] text-sm mt-0.5">OWASP Top 10 scanning, directory discovery, injection testing and CMS audits</p>
        </div>

        <div className="bg-[rgba(255,204,0,0.06)] border border-[rgba(255,204,0,0.2)] rounded-lg px-5 py-3 flex items-center gap-3">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ffcc00" strokeWidth="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
          <span className="text-xs text-[#ffcc00]">
            All scans in this module are active and intrusive. Ensure you have written authorization before testing any target.
          </span>
        </div>

        <div className="grid grid-cols-3 gap-4">
          {webTools.map((tool) => (
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
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wide ${riskColors[tool.riskLevel].color}`}>
                  {riskColors[tool.riskLevel].label}
                </span>
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
