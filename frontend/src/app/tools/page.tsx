'use client';

import { useState } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { TerminalOutput } from '@/components/ui/TerminalOutput';

interface KaliTool {
  id: string;
  name: string;
  binary: string;
  description: string;
  tags: string[];
  category: string;
  accentColor: string;
  requiresAuth: boolean;
}

const kaliTools: KaliTool[] = [
  {
    id: 'nmap', name: 'Nmap', binary: 'nmap',
    description: 'Network exploration and security auditing. Host discovery, port scanning, service/version detection and OS fingerprinting.',
    tags: ['Port Scan', 'Discovery', 'Scripting'], category: 'Network', accentColor: '#00d4ff', requiresAuth: false,
  },
  {
    id: 'theharvester', name: 'theHarvester', binary: 'theHarvester',
    description: 'OSINT tool for gathering emails, subdomains, IPs, URLs and employee names from public sources and search engines.',
    tags: ['OSINT', 'Email', 'Passive'], category: 'OSINT', accentColor: '#4fc3f7', requiresAuth: false,
  },
  {
    id: 'dnsrecon', name: 'DNSrecon', binary: 'dnsrecon',
    description: 'DNS enumeration — zone transfers, reverse lookups, standard records, brute-force and Google/Bing cache lookups.',
    tags: ['DNS', 'Recon', 'Zone Transfer'], category: 'DNS', accentColor: '#00ff88', requiresAuth: false,
  },
  {
    id: 'whatweb', name: 'WhatWeb', binary: 'whatweb',
    description: 'Web fingerprinting — identifies CMS, frameworks, server software, analytics and thousands of technology signatures.',
    tags: ['Fingerprint', 'Web', 'CMS'], category: 'Web', accentColor: '#4fc3f7', requiresAuth: false,
  },
  {
    id: 'masscan', name: 'Masscan', binary: 'masscan',
    description: 'Internet-scale port scanner. Transmits 10M+ packets/sec — scan entire internet in under 6 minutes.',
    tags: ['Port Scan', 'Fast', 'TCP'], category: 'Network', accentColor: '#ff6b35', requiresAuth: false,
  },
  {
    id: 'netdiscover', name: 'Netdiscover / ARP-Scan', binary: 'netdiscover',
    description: 'Active/passive ARP reconnaissance. Discover hosts on local network segments, identify MAC addresses and vendors.',
    tags: ['ARP', 'LAN', 'Discovery'], category: 'Network', accentColor: '#00d4ff', requiresAuth: false,
  },
  {
    id: 'nuclei', name: 'Nuclei', binary: 'nuclei',
    description: 'Fast vulnerability scanner powered by community templates. 9000+ templates for CVEs, misconfigs, exposures and panels.',
    tags: ['Templates', 'CVE', 'Fast'], category: 'Vulnerability', accentColor: '#ffcc00', requiresAuth: false,
  },
  {
    id: 'nikto', name: 'Nikto', binary: 'nikto',
    description: 'Web server scanner — checks for dangerous files, outdated software, default credentials, server misconfigurations.',
    tags: ['Web Server', 'Misconfig', 'Files'], category: 'Web', accentColor: '#ff6b35', requiresAuth: false,
  },
  {
    id: 'sslscan', name: 'SSLScan / TestSSL', binary: 'sslscan',
    description: 'Comprehensive TLS/SSL scanner — cipher suites, protocol versions, certificate validity, BEAST, POODLE, Heartbleed.',
    tags: ['TLS', 'SSL', 'Ciphers'], category: 'Web', accentColor: '#4fc3f7', requiresAuth: false,
  },
  {
    id: 'wpscan', name: 'WPScan', binary: 'wpscan',
    description: 'WordPress security scanner — enumerates plugins, themes, users, API keys and tests against WPVulnDB.',
    tags: ['WordPress', 'CMS', 'CVE'], category: 'Web', accentColor: '#00d4ff', requiresAuth: false,
  },
  {
    id: 'lynis', name: 'Lynis', binary: 'lynis',
    description: 'Security auditing and hardening tool for Linux/Unix/macOS. Checks 300+ security controls and generates hardening report.',
    tags: ['Hardening', 'Audit', 'Linux'], category: 'System', accentColor: '#00ff88', requiresAuth: false,
  },
  {
    id: 'sqlmap', name: 'SQLMap', binary: 'sqlmap',
    description: 'Automated SQL injection detection and database takeover. Supports MySQL, Oracle, MSSQL, PostgreSQL, SQLite and more.',
    tags: ['SQLi', 'Exploit', 'Database'], category: 'Web', accentColor: '#ff3b3b', requiresAuth: true,
  },
  {
    id: 'gobuster', name: 'Gobuster / Dirb', binary: 'gobuster',
    description: 'Directory/file brute-forcing and DNS subdomain enumeration. Concurrent requests with customizable wordlists.',
    tags: ['Dirbusting', 'DNS', 'Fast'], category: 'Web', accentColor: '#ffcc00', requiresAuth: false,
  },
  {
    id: 'wfuzz', name: 'Wfuzz', binary: 'wfuzz',
    description: 'Web application fuzzer — fuzz parameters, headers, cookies and paths. Find injection points, hidden parameters.',
    tags: ['Fuzzing', 'Parameters', 'Headers'], category: 'Web', accentColor: '#ffcc00', requiresAuth: false,
  },
  {
    id: 'zaproxy', name: 'OWASP ZAP', binary: 'zaproxy',
    description: 'Intercepting proxy and DAST scanner. Passive and active scanning for OWASP Top 10 with browser integration.',
    tags: ['DAST', 'Proxy', 'OWASP'], category: 'Web', accentColor: '#00ff88', requiresAuth: false,
  },
  {
    id: 'hydra', name: 'Hydra / Medusa', binary: 'hydra',
    description: 'Multi-protocol credential brute-forcer. Supports SSH, FTP, HTTP, SMTP, SMB, RDP, MySQL and 50+ protocols.',
    tags: ['Brute Force', 'SSH', 'FTP'], category: 'Auth', accentColor: '#ff3b3b', requiresAuth: true,
  },
  {
    id: 'hashcat', name: 'Hashcat / John', binary: 'hashcat',
    description: 'World\'s fastest password recovery tool. GPU-accelerated with dictionary, rule, mask and combination attacks.',
    tags: ['Password', 'GPU', 'Cracking'], category: 'Auth', accentColor: '#ff6b35', requiresAuth: true,
  },
  {
    id: 'hashid', name: 'HashID', binary: 'hashid',
    description: 'Hash type identification tool. Identify hash format from sample text supporting 250+ hash algorithms.',
    tags: ['Hash', 'Identify', 'Forensic'], category: 'Auth', accentColor: '#ffcc00', requiresAuth: false,
  },
  {
    id: 'whois', name: 'Whois', binary: 'whois',
    description: 'Domain registration lookup — registrar details, nameservers, expiry dates, registrant info and IP WHOIS.',
    tags: ['OSINT', 'Domain', 'Passive'], category: 'OSINT', accentColor: '#8892a4', requiresAuth: false,
  },
  {
    id: 'recon-ng', name: 'Recon-ng', binary: 'recon-ng',
    description: 'Full-featured reconnaissance framework with modular architecture. Integrates with Shodan, VirusTotal, GitHub, HaveIBeenPwned.',
    tags: ['Framework', 'OSINT', 'Modules'], category: 'OSINT', accentColor: '#00d4ff', requiresAuth: false,
  },
  {
    id: 'pcap', name: 'PCAP Analyser', binary: 'tcpdump/wireshark',
    description: 'Packet capture analysis — inspect traffic, extract credentials, identify protocols and analyse network behaviour.',
    tags: ['PCAP', 'Wireshark', 'Traffic'], category: 'Network', accentColor: '#4fc3f7', requiresAuth: false,
  },
  {
    id: 'metasploit', name: 'Metasploit Framework', binary: 'msfconsole',
    description: 'Penetration testing framework for exploit development, payload generation, post-exploitation and reporting.',
    tags: ['Exploit', 'Payload', 'Post-Exploit'], category: 'Exploit', accentColor: '#ff3b3b', requiresAuth: true,
  },
];

const categories = ['All', ...Array.from(new Set(kaliTools.map(t => t.category)))];

interface LaunchModalProps {
  tool: KaliTool;
  onClose: () => void;
}

function LaunchModal({ tool, onClose }: LaunchModalProps) {
  const [target, setTarget] = useState('');
  const [args, setArgs] = useState('');
  const [taskId, setTaskId] = useState<string | null>(null);
  const [accepted, setAccepted] = useState(!tool.requiresAuth);

  const handleLaunch = () => {
    if (!target.trim() || !accepted) return;
    setTaskId(`task-${tool.id}-${Date.now()}`);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#111318] border border-[#1e2028] rounded-xl w-full max-w-2xl mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2028]">
          <div>
            <h3 className="text-base font-bold text-[#e8eaf0]">{tool.name}</h3>
            <span className="font-mono text-xs text-[#8892a4]">{tool.binary}</span>
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
              {tool.requiresAuth && (
                <div className="bg-[rgba(255,59,59,0.08)] border border-[rgba(255,59,59,0.3)] rounded-lg px-4 py-3">
                  <div className="text-xs font-bold text-[#ff3b3b] mb-2 uppercase tracking-wide">Authorization Required</div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={accepted}
                      onChange={(e) => setAccepted(e.target.checked)}
                      className="w-4 h-4 accent-[#ff3b3b]"
                    />
                    <span className="text-xs text-[#e8eaf0]">I confirm written authorization to test this target</span>
                  </label>
                </div>
              )}
              <div>
                <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">Target</label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="hostname, IP, URL or CIDR range"
                  className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff]"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">Arguments (optional)</label>
                <input
                  type="text"
                  value={args}
                  onChange={(e) => setArgs(e.target.value)}
                  placeholder={`e.g. -sV -O --script vuln`}
                  className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm font-mono text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff]"
                />
              </div>
              <div className="bg-[#0d0f14] rounded-lg px-4 py-2.5 font-mono text-xs text-[#00ff88]">
                $ {tool.binary} {target || '<target>'} {args}
              </div>
              <div className="flex gap-3">
                <button
                  onClick={handleLaunch}
                  disabled={!accepted || !target.trim()}
                  className="cyber-btn text-sm disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Run {tool.binary}
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

export default function ToolsPage() {
  const [activeTool, setActiveTool] = useState<KaliTool | null>(null);
  const [activeCategory, setActiveCategory] = useState('All');
  const [search, setSearch] = useState('');

  const filtered = kaliTools.filter((t) => {
    if (activeCategory !== 'All' && t.category !== activeCategory) return false;
    if (search && !t.name.toLowerCase().includes(search.toLowerCase()) && !t.description.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <DashboardLayout>
      <div className="p-6 space-y-5 min-h-full">
        <div>
          <h1 className="text-xl font-bold text-[#e8eaf0]">Tool Panels</h1>
          <p className="text-[#8892a4] text-sm mt-0.5">22 Kali Linux security tools — launch with real-time terminal output</p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <input
            type="text"
            placeholder="Search tools..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2 text-sm text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff] w-52"
          />
          <div className="flex gap-1 bg-[#111318] border border-[#1e2028] rounded-lg p-1 flex-wrap">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`text-xs font-medium px-3 py-1.5 rounded-md transition-all ${
                  activeCategory === cat ? 'bg-[#1a1f2e] text-[#00d4ff]' : 'text-[#8892a4] hover:text-[#e8eaf0]'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
          <span className="text-xs text-[#8892a4] ml-auto">{filtered.length} tools</span>
        </div>

        <div className="grid grid-cols-3 gap-4">
          {filtered.map((tool) => (
            <div
              key={tool.id}
              className="bg-[#111318] border border-[#1e2028] rounded-lg p-5 hover:border-[#2a2d3a] transition-all"
            >
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-sm font-bold text-[#e8eaf0]">{tool.name}</span>
                    {tool.requiresAuth && (
                      <span className="text-[9px] font-bold text-[#ff3b3b] bg-[rgba(255,59,59,0.12)] border border-[rgba(255,59,59,0.4)] px-1.5 py-0.5 rounded uppercase">
                        Auth
                      </span>
                    )}
                  </div>
                  <div className="font-mono text-[10px] text-[#8892a4]">{tool.binary}</div>
                </div>
                <span
                  className="text-[10px] font-medium px-2 py-0.5 rounded"
                  style={{
                    color: tool.accentColor,
                    background: `${tool.accentColor}10`,
                  }}
                >
                  {tool.category}
                </span>
              </div>
              <p className="text-xs text-[#8892a4] leading-relaxed mb-4">{tool.description}</p>
              <div className="flex items-center justify-between">
                <div className="flex flex-wrap gap-1">
                  {tool.tags.map((tag) => (
                    <span key={tag} className="text-[9px] px-1.5 py-0.5 rounded bg-[#1e2028] text-[#8892a4]">
                      {tag}
                    </span>
                  ))}
                </div>
                <button
                  onClick={() => setActiveTool(tool)}
                  className="text-sm font-semibold px-3 py-1.5 rounded-md transition-all border shrink-0 ml-2"
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
