'use client';

import { useState } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { TerminalOutput } from '@/components/ui/TerminalOutput';
import { useRunTool } from '@/lib/hooks';

interface Tool {
  id: string;
  name: string;
  description: string;
  tags: string[];
  icon: React.ReactNode;
  accentColor: string;
  endpoint: string;
  placeholder: string;
  extraFields?: { key: string; label: string; type: 'text' | 'select'; options?: string[]; default?: string }[];
}

const tools: Tool[] = [
  {
    id: 'subdomain-enum',
    name: 'Subdomain Enumeration',
    description: 'Discover subdomains via passive DNS, certificate transparency logs, and brute-force wordlists.',
    tags: ['DNS', 'OSINT', 'Passive'],
    accentColor: '#00d4ff',
    endpoint: 'subdomain-enum',
    placeholder: 'e.g. example.com',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="12" cy="12" r="10" />
        <line x1="2" y1="12" x2="22" y2="12" />
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
      </svg>
    ),
  },
  {
    id: 'dns-analysis',
    name: 'DNS Analysis',
    description: 'Full DNS record enumeration: A, AAAA, MX, TXT, SOA, NS, CNAME, SRV records with zone transfer attempts.',
    tags: ['DNS', 'Recon'],
    accentColor: '#00ff88',
    endpoint: 'dns-analysis',
    placeholder: 'e.g. example.com',
    extraFields: [
      { key: 'dns_server', label: 'DNS Server (optional)', type: 'text', default: '' },
    ],
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M9 12h6M9 16h6M9 8h6M5 20h14a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2z" />
      </svg>
    ),
  },
  {
    id: 'whois',
    name: 'WHOIS Lookup',
    description: 'Domain registration data, registrar info, nameservers, expiry dates and associated IPs.',
    tags: ['OSINT', 'Passive'],
    accentColor: '#ffcc00',
    endpoint: 'whois',
    placeholder: 'e.g. example.com',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
      </svg>
    ),
  },
  {
    id: 'web-fingerprinting',
    name: 'Web Fingerprinting',
    description: 'Identify web technologies, CMS platforms, frameworks, and server banners using WhatWeb signatures.',
    tags: ['Web', 'Fingerprint', 'WhatWeb'],
    accentColor: '#4fc3f7',
    endpoint: 'web-fingerprinting',
    placeholder: 'e.g. https://example.com',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="11" cy="11" r="8" />
        <line x1="21" y1="21" x2="16.65" y2="16.65" />
      </svg>
    ),
  },
  {
    id: 'osint-harvesting',
    name: 'OSINT Harvesting',
    description: 'Collect emails, subdomains, IPs, URLs and employee names from search engines via theHarvester.',
    tags: ['OSINT', 'Email', 'theHarvester'],
    accentColor: '#ff6b35',
    endpoint: 'osint',
    placeholder: 'e.g. example.com',
    extraFields: [
      { key: 'sources', label: 'Source', type: 'select', options: ['google', 'bing', 'linkedin', 'shodan', 'all'], default: 'google' },
      { key: 'limit', label: 'Result Limit', type: 'text', default: '100' },
    ],
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M20 7H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2z" />
        <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" />
      </svg>
    ),
  },
  {
    id: 'lan-discovery',
    name: 'LAN Discovery',
    description: 'Discover live hosts on local network segments using ARP scanning and ICMP probes.',
    tags: ['LAN', 'ARP', 'Internal'],
    accentColor: '#00ff88',
    endpoint: 'lan-discovery',
    placeholder: 'e.g. 192.168.1.0/24',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <rect x="2" y="2" width="6" height="6" rx="1" />
        <rect x="16" y="2" width="6" height="6" rx="1" />
        <rect x="9" y="16" width="6" height="6" rx="1" />
        <line x1="5" y1="8" x2="5" y2="18" />
        <line x1="19" y1="8" x2="19" y2="18" />
        <line x1="5" y1="18" x2="12" y2="18" />
        <line x1="19" y1="18" x2="12" y2="18" />
      </svg>
    ),
  },
  {
    id: 'port-scanning',
    name: 'Port Scanning',
    description: 'High-speed port scanning using masscan at 100k packets/s with service detection.',
    tags: ['masscan', 'TCP', 'UDP'],
    accentColor: '#ff3b3b',
    endpoint: 'masscan',
    placeholder: 'e.g. 10.0.0.0/24',
    extraFields: [
      { key: 'ports', label: 'Port Range', type: 'text', default: '1-65535' },
      { key: 'rate', label: 'Rate (pkts/s)', type: 'text', default: '10000' },
    ],
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
      </svg>
    ),
  },
  {
    id: 'network-topology',
    name: 'Network Topology Map',
    description: 'Visual network topology mapping — discover routers, switches and hosts with traceroute and TTL analysis.',
    tags: ['Map', 'Topology', 'traceroute'],
    accentColor: '#00d4ff',
    endpoint: 'nmap',
    placeholder: 'e.g. 10.0.0.0/24',
    extraFields: [
      { key: 'scan_type', label: 'Mode', type: 'select', options: ['traceroute', 'topology'], default: 'traceroute' },
    ],
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="18" cy="5" r="3" />
        <circle cx="6" cy="12" r="3" />
        <circle cx="18" cy="19" r="3" />
        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
      </svg>
    ),
  },
  {
    id: 'http-headers',
    name: 'HTTP Headers Checker',
    description: 'Audit HTTP/HTTPS security headers: HSTS, CSP, X-Frame-Options, CORS policy and cookie flags.',
    tags: ['HTTP', 'Headers', 'Web'],
    accentColor: '#ffcc00',
    endpoint: 'http-request',
    placeholder: 'e.g. https://example.com',
    extraFields: [
      { key: 'method', label: 'Method', type: 'select', options: ['GET', 'HEAD', 'OPTIONS'], default: 'HEAD' },
    ],
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
      </svg>
    ),
  },
];

interface LaunchFormProps {
  tool: Tool;
  onClose: () => void;
}

function LaunchForm({ tool, onClose }: LaunchFormProps) {
  const [target, setTarget] = useState('');
  const [extras, setExtras] = useState<Record<string, string>>(
    Object.fromEntries((tool.extraFields ?? []).map(f => [f.key, f.default ?? '']))
  );
  const [taskId, setTaskId] = useState<string | null>(null);
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runTool = useRunTool();

  const handleLaunch = async () => {
    if (!target.trim()) return;
    setLaunching(true);
    setError(null);
    try {
      const body: any = { target, ...extras };
      // Map specific field names for each endpoint
      if (tool.endpoint === 'http-request') {
        body.url = target;
        body.method = extras.method ?? 'HEAD';
        body.follow_redirects = true;
      } else if (tool.endpoint === 'dns-analysis') {
        body.domain = target;
      } else if (tool.endpoint === 'lan-discovery') {
        body.ip_range = target;
      } else if (tool.endpoint === 'masscan') {
        body.ports = extras.ports ?? '1-65535';
        body.rate = parseInt(extras.rate ?? '10000');
      } else if (tool.endpoint === 'osint') {
        body.domain = target;
        body.sources = extras.sources ?? 'google';
        body.limit = parseInt(extras.limit ?? '100');
      } else if (tool.endpoint === 'subdomain-enum') {
        body.domain = target;
      } else if (tool.endpoint === 'web-fingerprinting') {
        body.url = target;
      } else if (tool.endpoint === 'whois') {
        body.domain = target;
      }

      const res = await runTool.mutateAsync({ tool: tool.endpoint, body });
      setTaskId(res.scan_id);
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? err?.message ?? 'Launch failed');
    } finally {
      setLaunching(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#111318] border border-[#1e2028] rounded-xl w-full max-w-2xl mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2028]">
          <div className="flex items-center gap-3">
            <span style={{ color: tool.accentColor }}>{tool.icon}</span>
            <h3 className="text-base font-bold text-[#e8eaf0]">{tool.name}</h3>
          </div>
          <button onClick={onClose} className="text-[#8892a4] hover:text-[#e8eaf0] transition-colors">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div className="p-6 space-y-4">
          {!taskId ? (
            <>
              <div>
                <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">
                  Target (domain, IP, or CIDR)
                </label>
                <input
                  type="text" value={target} onChange={e => setTarget(e.target.value)}
                  placeholder={tool.placeholder}
                  className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff]"
                />
              </div>

              {(tool.extraFields ?? []).map(field => (
                <div key={field.key}>
                  <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">{field.label}</label>
                  {field.type === 'select' ? (
                    <select value={extras[field.key]} onChange={e => setExtras(ex => ({ ...ex, [field.key]: e.target.value }))}
                      className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm text-[#e8eaf0] focus:outline-none focus:border-[#00d4ff]">
                      {(field.options ?? []).map(opt => <option key={opt} value={opt}>{opt}</option>)}
                    </select>
                  ) : (
                    <input type="text" value={extras[field.key]} onChange={e => setExtras(ex => ({ ...ex, [field.key]: e.target.value }))}
                      className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm font-mono text-[#e8eaf0] focus:outline-none focus:border-[#00d4ff]"
                    />
                  )}
                </div>
              ))}

              {error && (
                <div className="text-xs text-[#ff3b3b] bg-[rgba(255,59,59,0.1)] border border-[rgba(255,59,59,0.3)] rounded px-3 py-2">{error}</div>
              )}

              <div className="flex gap-3">
                <button
                  onClick={handleLaunch}
                  disabled={!target.trim() || launching}
                  className="cyber-btn text-sm flex items-center gap-2"
                  style={{ background: tool.accentColor }}
                >
                  {launching && <svg className="animate-spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>}
                  {launching ? 'Launching…' : 'Launch Scan'}
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

export default function NetworkReconPage() {
  const [activeTool, setActiveTool] = useState<Tool | null>(null);

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6 min-h-full">
        <div>
          <h1 className="text-xl font-bold text-[#e8eaf0]">Network Reconnaissance</h1>
          <p className="text-[#8892a4] text-sm mt-0.5">Passive & active network discovery, DNS analysis and OSINT collection</p>
        </div>

        <div className="grid grid-cols-3 gap-4">
          {tools.map((tool) => (
            <div key={tool.id} className="bg-[#111318] border border-[#1e2028] rounded-lg p-5 hover:border-[#2a2d3a] transition-all group">
              <div className="flex items-start justify-between mb-3">
                <div className="w-11 h-11 rounded-lg flex items-center justify-center" style={{ background: `${tool.accentColor}15` }}>
                  <span style={{ color: tool.accentColor }}>{tool.icon}</span>
                </div>
              </div>
              <h3 className="text-sm font-bold text-[#e8eaf0] mb-1">{tool.name}</h3>
              <p className="text-xs text-[#8892a4] leading-relaxed mb-4">{tool.description}</p>
              <div className="flex items-center justify-between">
                <div className="flex flex-wrap gap-1">
                  {tool.tags.map(tag => (
                    <span key={tag} className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-[#1e2028] text-[#8892a4]">{tag}</span>
                  ))}
                </div>
                <button
                  onClick={() => setActiveTool(tool)}
                  className="text-sm font-semibold px-3 py-1.5 rounded-md transition-all border"
                  style={{ color: tool.accentColor, borderColor: `${tool.accentColor}40`, background: `${tool.accentColor}10` }}
                >
                  Launch
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {activeTool && <LaunchForm tool={activeTool} onClose={() => setActiveTool(null)} />}
    </DashboardLayout>
  );
}
