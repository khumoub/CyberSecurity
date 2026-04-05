'use client';

import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { StatCard } from '@/components/ui/StatCard';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { useRouter } from 'next/navigation';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
type ScanStatus = 'running' | 'completed' | 'failed' | 'queued';
type FindingStatus = 'open' | 'in_progress' | 'resolved' | 'accepted_risk';

interface Finding {
  id: string;
  severity: Severity;
  title: string;
  cve: string | null;
  asset: string;
  timeAgo: string;
  status: FindingStatus;
}

interface ScanJob {
  id: string;
  tool: string;
  target: string;
  status: ScanStatus;
  duration: string;
  findings: number | null;
}

const recentFindings: Finding[] = [
  { id: '1', severity: 'critical', title: 'Apache Log4j Remote Code Execution', cve: 'CVE-2021-44228', asset: '10.0.1.45', timeAgo: '2h ago', status: 'open' },
  { id: '2', severity: 'critical', title: 'OpenSSL Buffer Overflow', cve: 'CVE-2022-0778', asset: 'api.internal.corp', timeAgo: '3h ago', status: 'in_progress' },
  { id: '3', severity: 'high', title: 'Spring4Shell RCE Vulnerability', cve: 'CVE-2022-22965', asset: '10.0.1.102', timeAgo: '5h ago', status: 'open' },
  { id: '4', severity: 'high', title: 'ProxyLogon Exchange Server', cve: 'CVE-2021-26855', asset: 'mail.corp.internal', timeAgo: '8h ago', status: 'open' },
  { id: '5', severity: 'high', title: 'Sudo Privilege Escalation', cve: 'CVE-2021-3156', asset: '10.0.2.33', timeAgo: '12h ago', status: 'in_progress' },
  { id: '6', severity: 'medium', title: 'SSL/TLS Weak Cipher Suite', cve: null, asset: 'vpn.corp.com', timeAgo: '1d ago', status: 'open' },
  { id: '7', severity: 'medium', title: 'Missing HTTP Security Headers', cve: null, asset: 'portal.corp.com', timeAgo: '1d ago', status: 'accepted_risk' },
  { id: '8', severity: 'low', title: 'SSH Protocol Version 1 Enabled', cve: null, asset: '10.0.3.11', timeAgo: '2d ago', status: 'resolved' },
];

const recentScans: ScanJob[] = [
  { id: 's1', tool: 'nmap', target: '10.0.0.0/24', status: 'running', duration: '4m 12s', findings: null },
  { id: 's2', tool: 'nuclei', target: 'portal.corp.com', status: 'completed', duration: '12m 33s', findings: 14 },
  { id: 's3', tool: 'nikto', target: 'api.internal.corp', status: 'completed', duration: '8m 02s', findings: 6 },
  { id: 's4', tool: 'sqlmap', target: 'app.corp.com/login', status: 'failed', duration: '1m 45s', findings: null },
  { id: 's5', tool: 'theHarvester', target: 'corp.com', status: 'completed', duration: '3m 58s', findings: 31 },
  { id: 's6', tool: 'wpscan', target: 'blog.corp.com', status: 'queued', duration: '—', findings: null },
];

const statusChipColors: Record<FindingStatus, string> = {
  open: 'text-[#ff6b35] bg-[rgba(255,107,53,0.12)] border-[rgba(255,107,53,0.3)]',
  in_progress: 'text-[#00d4ff] bg-[rgba(0,212,255,0.12)] border-[rgba(0,212,255,0.3)]',
  resolved: 'text-[#00ff88] bg-[rgba(0,255,136,0.12)] border-[rgba(0,255,136,0.3)]',
  accepted_risk: 'text-[#8892a4] bg-[rgba(136,146,164,0.12)] border-[rgba(136,146,164,0.3)]',
};

const scanStatusColors: Record<ScanStatus, string> = {
  running: 'text-[#00d4ff]',
  completed: 'text-[#00ff88]',
  failed: 'text-[#ff3b3b]',
  queued: 'text-[#ffcc00]',
};

export default function DashboardPage() {
  const router = useRouter();
  const now = new Date();
  const dateStr = now.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6 min-h-full">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-xl font-bold text-[#e8eaf0]">Security Operations Center</h1>
            <p className="text-[#8892a4] text-sm mt-0.5">{dateStr}</p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-[#00d4ff] bg-[rgba(0,212,255,0.12)] border border-[rgba(0,212,255,0.3)] px-3 py-1 rounded-full">
              ACME Corp
            </span>
            <div className="w-2 h-2 rounded-full bg-[#00ff88] animate-pulse" />
            <span className="text-xs text-[#8892a4]">Live</span>
          </div>
        </div>

        {/* Stat cards */}
        <div className="grid grid-cols-4 gap-4">
          <StatCard
            label="Total Assets"
            value="342"
            sub="↑ 12 added this week"
            accentColor="#00d4ff"
            icon={
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="2" y="3" width="20" height="14" rx="2" />
                <line x1="8" y1="21" x2="16" y2="21" />
                <line x1="12" y1="17" x2="12" y2="21" />
              </svg>
            }
          />
          <StatCard
            label="Open Findings"
            value="847"
            sub="C:23 H:114 M:389 L:321"
            accentColor="#ff3b3b"
            trend={{ value: 8, direction: 'up' }}
            icon={
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
            }
          />
          <StatCard
            label="Active Scans"
            value="3"
            sub="2 queued"
            accentColor="#ffcc00"
            icon={
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
              </svg>
            }
          />
          <StatCard
            label="Risk Score"
            value="74"
            sub="HIGH — review required"
            accentColor="#ff6b35"
            trend={{ value: 3, direction: 'down' }}
            icon={
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            }
          />
        </div>

        {/* Two-column middle */}
        <div className="grid grid-cols-5 gap-4">
          {/* Recent Findings (60%) */}
          <div className="col-span-3 bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2028]">
              <h2 className="text-sm font-semibold text-[#e8eaf0]">Recent Findings</h2>
              <button
                onClick={() => router.push('/vulnerability-management')}
                className="text-xs text-[#00d4ff] hover:underline"
              >
                View all
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2028]">
                    <th className="text-left px-5 py-2.5 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">Severity</th>
                    <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">Title</th>
                    <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">CVE</th>
                    <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">Asset</th>
                    <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">Time</th>
                    <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {recentFindings.map((f) => (
                    <tr key={f.id} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                      <td className="px-5 py-3">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="px-3 py-3 text-[#e8eaf0] max-w-[200px]">
                        <span className="truncate block">{f.title}</span>
                      </td>
                      <td className="px-3 py-3 font-mono text-xs text-[#8892a4]">
                        {f.cve ?? '—'}
                      </td>
                      <td className="px-3 py-3 font-mono text-xs text-[#4fc3f7]">{f.asset}</td>
                      <td className="px-3 py-3 text-xs text-[#8892a4]">{f.timeAgo}</td>
                      <td className="px-3 py-3">
                        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border uppercase tracking-wide ${statusChipColors[f.status]}`}>
                          {f.status.replace('_', ' ')}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Scan Activity (40%) */}
          <div className="col-span-2 bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2028]">
              <h2 className="text-sm font-semibold text-[#e8eaf0]">Scan Activity</h2>
              <button
                onClick={() => router.push('/vulnerability-management')}
                className="text-xs text-[#00d4ff] hover:underline"
              >
                Manage
              </button>
            </div>
            <div className="divide-y divide-[#1e2028]">
              {recentScans.map((scan) => (
                <div key={scan.id} className="px-5 py-3 hover:bg-[#161b27] transition-colors">
                  <div className="flex items-start justify-between">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-[#e8eaf0]">{scan.tool}</span>
                        {scan.status === 'running' && (
                          <span className="flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-[#00d4ff] animate-pulse" />
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-[#8892a4] font-mono truncate mt-0.5">{scan.target}</div>
                    </div>
                    <div className="text-right shrink-0 ml-3">
                      <div className={`text-xs font-semibold capitalize ${scanStatusColors[scan.status]}`}>
                        {scan.status}
                      </div>
                      <div className="text-[10px] text-[#8892a4] mt-0.5">{scan.duration}</div>
                    </div>
                  </div>
                  {scan.findings !== null && (
                    <div className="mt-1.5 text-[10px] text-[#8892a4]">
                      <span className="text-[#e8eaf0] font-semibold">{scan.findings}</span> findings
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div>
          <h2 className="text-sm font-semibold text-[#e8eaf0] mb-3">Quick Actions</h2>
          <div className="grid grid-cols-4 gap-3">
            {[
              {
                label: 'New Scan',
                desc: 'Launch a vulnerability scan',
                href: '/vulnerability-management',
                color: '#00d4ff',
                icon: (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="11" cy="11" r="8" />
                    <line x1="21" y1="21" x2="16.65" y2="16.65" />
                    <line x1="11" y1="8" x2="11" y2="14" />
                    <line x1="8" y1="11" x2="14" y2="11" />
                  </svg>
                ),
              },
              {
                label: 'Import Assets',
                desc: 'Add hosts via CSV or CIDR',
                href: '/vulnerability-management',
                color: '#00ff88',
                icon: (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="17 8 12 3 7 8" />
                    <line x1="12" y1="3" x2="12" y2="15" />
                  </svg>
                ),
              },
              {
                label: 'Generate Report',
                desc: 'Export PDF executive report',
                href: '/reporting',
                color: '#ffcc00',
                icon: (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                    <polyline points="14 2 14 8 20 8" />
                    <line x1="16" y1="13" x2="8" y2="13" />
                    <line x1="16" y1="17" x2="8" y2="17" />
                    <polyline points="10 9 9 9 8 9" />
                  </svg>
                ),
              },
              {
                label: 'View All Findings',
                desc: 'Filter and triage vulnerabilities',
                href: '/vulnerability-management',
                color: '#ff6b35',
                icon: (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                    <line x1="12" y1="9" x2="12" y2="13" />
                    <line x1="12" y1="17" x2="12.01" y2="17" />
                  </svg>
                ),
              },
            ].map((action) => (
              <button
                key={action.label}
                onClick={() => router.push(action.href)}
                className="bg-[#111318] border border-[#1e2028] rounded-lg p-4 text-left hover:border-[#2a2d3a] hover:bg-[#161b27] transition-all group"
              >
                <div
                  className="w-10 h-10 rounded-lg flex items-center justify-center mb-3"
                  style={{ background: `${action.color}15` }}
                >
                  <span style={{ color: action.color }}>{action.icon}</span>
                </div>
                <div className="text-sm font-semibold text-[#e8eaf0] group-hover:text-white transition-colors">
                  {action.label}
                </div>
                <div className="text-xs text-[#8892a4] mt-0.5">{action.desc}</div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
