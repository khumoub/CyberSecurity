'use client';

import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { SeverityBadge } from '@/components/ui/SeverityBadge';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface AssetRisk {
  id: string;
  host: string;
  score: number;
  critical: number;
  high: number;
  medium: number;
  trend: number[]; // sparkline data
  delta: number;
}

interface CISAKev {
  id: string;
  cveId: string;
  vendor: string;
  product: string;
  dateAdded: string;
  patchDeadline: string;
  status: 'patched' | 'unpatched' | 'in_progress';
}

interface PatchPriority {
  rank: number;
  cve: string | null;
  title: string;
  severity: Severity;
  asset: string;
  epss: number;
  kev: boolean;
  daysOpen: number;
  score: number;
}

const assetRisks: AssetRisk[] = [
  { id: 'ar1', host: '10.0.1.45', score: 9.8, critical: 2, high: 5, medium: 12, trend: [7, 7.5, 8, 8.5, 9, 9.8], delta: 2.3 },
  { id: 'ar2', host: 'api.internal.corp', score: 8.7, critical: 1, high: 3, medium: 7, trend: [8.2, 8.4, 8.6, 8.5, 8.7, 8.7], delta: 0.5 },
  { id: 'ar3', host: 'mail.corp.internal', score: 8.1, critical: 1, high: 2, medium: 6, trend: [9.1, 8.8, 8.5, 8.2, 8.0, 8.1], delta: -1.0 },
  { id: 'ar4', host: '10.0.1.102', score: 7.9, critical: 1, high: 4, medium: 9, trend: [6.5, 7.0, 7.4, 7.7, 7.8, 7.9], delta: 1.4 },
  { id: 'ar5', host: 'db-prod-01.corp', score: 5.2, critical: 0, high: 1, medium: 3, trend: [6.1, 5.8, 5.5, 5.3, 5.2, 5.2], delta: -0.9 },
  { id: 'ar6', host: '10.0.2.33', score: 4.8, critical: 0, high: 3, medium: 5, trend: [4.2, 4.4, 4.5, 4.7, 4.8, 4.8], delta: 0.6 },
];

const cisaKev: CISAKev[] = [
  { id: 'k1', cveId: 'CVE-2021-44228', vendor: 'Apache', product: 'Log4j', dateAdded: '2021-12-10', patchDeadline: '2021-12-24', status: 'unpatched' },
  { id: 'k2', cveId: 'CVE-2022-22965', vendor: 'VMware', product: 'Spring Framework', dateAdded: '2022-04-04', patchDeadline: '2022-04-25', status: 'in_progress' },
  { id: 'k3', cveId: 'CVE-2021-26855', vendor: 'Microsoft', product: 'Exchange Server', dateAdded: '2021-03-03', patchDeadline: '2021-03-17', status: 'unpatched' },
  { id: 'k4', cveId: 'CVE-2022-0778', vendor: 'OpenSSL', product: 'OpenSSL', dateAdded: '2022-03-16', patchDeadline: '2022-04-06', status: 'in_progress' },
  { id: 'k5', cveId: 'CVE-2023-23397', vendor: 'Microsoft', product: 'Outlook', dateAdded: '2023-03-14', patchDeadline: '2023-03-31', status: 'patched' },
  { id: 'k6', cveId: 'CVE-2024-3400', vendor: 'Palo Alto', product: 'PAN-OS', dateAdded: '2024-04-12', patchDeadline: '2024-04-19', status: 'patched' },
];

const patchPriority: PatchPriority[] = [
  { rank: 1, cve: 'CVE-2021-44228', title: 'Log4j RCE', severity: 'critical', asset: '10.0.1.45', epss: 97.8, kev: true, daysOpen: 482, score: 99 },
  { rank: 2, cve: 'CVE-2021-26855', title: 'ProxyLogon Exchange', severity: 'critical', asset: 'mail.corp.internal', epss: 95.4, kev: true, daysOpen: 398, score: 97 },
  { rank: 3, cve: 'CVE-2022-0778', title: 'OpenSSL DoS/RCE', severity: 'critical', asset: 'api.internal.corp', epss: 82.1, kev: true, daysOpen: 115, score: 91 },
  { rank: 4, cve: 'CVE-2022-22965', title: 'Spring4Shell', severity: 'critical', asset: '10.0.1.102', epss: 79.3, kev: true, daysOpen: 89, score: 88 },
  { rank: 5, cve: 'CVE-2014-0160', title: 'Heartbleed OpenSSL', severity: 'critical', asset: '10.0.1.102', epss: 88.7, kev: false, daysOpen: 4367, score: 85 },
  { rank: 6, cve: 'CVE-2021-3156', title: 'Sudo Baron Samedit', severity: 'high', asset: '10.0.2.33', epss: 61.2, kev: false, daysOpen: 221, score: 74 },
  { rank: 7, cve: null, title: 'SMBv1 Protocol Enabled', severity: 'high', asset: '10.0.1.1', epss: 0, kev: false, daysOpen: 89, score: 68 },
  { rank: 8, cve: null, title: 'Default SNMP Community', severity: 'high', asset: '10.0.1.1', epss: 0, kev: false, daysOpen: 156, score: 62 },
  { rank: 9, cve: null, title: 'Weak SSL/TLS Ciphers', severity: 'medium', asset: 'vpn.corp.com', epss: 0, kev: false, daysOpen: 45, score: 41 },
  { rank: 10, cve: null, title: 'Missing HSTS Header', severity: 'medium', asset: 'portal.corp.com', epss: 0, kev: false, daysOpen: 61, score: 35 },
];

// 4x4 Risk Heatmap data [severity 1-4][likelihood 1-4]
const heatmapData: { count: number; color: string }[][] = [
  [
    { count: 3, color: 'rgba(79,195,247,0.5)' },
    { count: 5, color: 'rgba(79,195,247,0.6)' },
    { count: 2, color: 'rgba(255,204,0,0.5)' },
    { count: 1, color: 'rgba(255,204,0,0.7)' },
  ],
  [
    { count: 7, color: 'rgba(79,195,247,0.4)' },
    { count: 9, color: 'rgba(255,204,0,0.4)' },
    { count: 4, color: 'rgba(255,107,53,0.5)' },
    { count: 2, color: 'rgba(255,107,53,0.7)' },
  ],
  [
    { count: 4, color: 'rgba(255,204,0,0.3)' },
    { count: 6, color: 'rgba(255,107,53,0.4)' },
    { count: 3, color: 'rgba(255,59,59,0.5)' },
    { count: 1, color: 'rgba(255,59,59,0.7)' },
  ],
  [
    { count: 2, color: 'rgba(255,204,0,0.2)' },
    { count: 3, color: 'rgba(255,107,53,0.3)' },
    { count: 2, color: 'rgba(255,59,59,0.6)' },
    { count: 3, color: 'rgba(255,59,59,0.9)' },
  ],
];

const kevStatusColors = {
  patched: 'text-[#00ff88] bg-[rgba(0,255,136,0.1)] border-[rgba(0,255,136,0.3)]',
  unpatched: 'text-[#ff3b3b] bg-[rgba(255,59,59,0.1)] border-[rgba(255,59,59,0.3)]',
  in_progress: 'text-[#00d4ff] bg-[rgba(0,212,255,0.1)] border-[rgba(0,212,255,0.3)]',
};

function MiniSparkline({ data }: { data: number[] }) {
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  const w = 60;
  const h = 20;
  const points = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - ((v - min) / range) * h;
    return `${x},${y}`;
  });
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`}>
      <polyline
        points={points.join(' ')}
        fill="none"
        stroke={data[data.length - 1] > data[0] ? '#ff6b35' : '#00ff88'}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function RiskIntelligencePage() {
  return (
    <DashboardLayout>
      <div className="p-6 space-y-6 min-h-full">
        <div>
          <h1 className="text-xl font-bold text-[#e8eaf0]">Risk Intelligence</h1>
          <p className="text-[#8892a4] text-sm mt-0.5">Asset risk scoring, CISA KEV tracking, heat maps and AI-ranked patch priority</p>
        </div>

        {/* Asset Risk Scores */}
        <div className="bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-[#1e2028]">
            <h2 className="text-sm font-semibold text-[#e8eaf0]">Asset Risk Scores</h2>
            <p className="text-xs text-[#8892a4] mt-0.5">Composite score based on severity, exploitability, CVSS and exposure</p>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2028]">
                {['Host', 'Risk Score', 'Critical', 'High', 'Medium', 'Trend (30d)', 'Change'].map((h) => (
                  <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {assetRisks.map((asset) => (
                <tr key={asset.id} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                  <td className="px-4 py-3 font-mono text-xs text-[#4fc3f7]">{asset.host}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span
                        className="text-lg font-bold"
                        style={{
                          color: asset.score >= 9 ? '#ff3b3b' : asset.score >= 7 ? '#ff6b35' : asset.score >= 5 ? '#ffcc00' : '#4fc3f7',
                        }}
                      >
                        {asset.score.toFixed(1)}
                      </span>
                      <div className="w-16 h-1.5 bg-[#1e2028] rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${asset.score * 10}%`,
                            background: asset.score >= 9 ? '#ff3b3b' : asset.score >= 7 ? '#ff6b35' : asset.score >= 5 ? '#ffcc00' : '#4fc3f7',
                          }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs font-bold text-[#ff3b3b]">{asset.critical || '—'}</td>
                  <td className="px-4 py-3 text-xs font-bold text-[#ff6b35]">{asset.high || '—'}</td>
                  <td className="px-4 py-3 text-xs font-bold text-[#ffcc00]">{asset.medium || '—'}</td>
                  <td className="px-4 py-3">
                    <MiniSparkline data={asset.trend} />
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-bold ${asset.delta > 0 ? 'text-[#ff3b3b]' : 'text-[#00ff88]'}`}>
                      {asset.delta > 0 ? '+' : ''}{asset.delta.toFixed(1)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Two-col: CISA KEV + Heat Map */}
        <div className="grid grid-cols-5 gap-4">
          {/* CISA KEV Feed */}
          <div className="col-span-3 bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
            <div className="px-5 py-4 border-b border-[#1e2028] flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-[#e8eaf0]">CISA KEV Feed</h2>
                <p className="text-xs text-[#8892a4] mt-0.5">Known Exploited Vulnerabilities affecting your assets</p>
              </div>
              <span className="text-[10px] font-bold text-[#ff3b3b] bg-[rgba(255,59,59,0.1)] border border-[rgba(255,59,59,0.3)] px-2 py-0.5 rounded">
                {cisaKev.filter(k => k.status === 'unpatched').length} UNPATCHED
              </span>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2028]">
                  {['CVE ID', 'Vendor', 'Product', 'Date Added', 'Deadline', 'Status'].map((h) => (
                    <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {cisaKev.map((kev) => (
                  <tr key={kev.id} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-[#4fc3f7]">{kev.cveId}</td>
                    <td className="px-4 py-3 text-xs text-[#e8eaf0]">{kev.vendor}</td>
                    <td className="px-4 py-3 text-xs text-[#8892a4]">{kev.product}</td>
                    <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">{kev.dateAdded}</td>
                    <td className="px-4 py-3 font-mono text-xs text-[#ffcc00]">{kev.patchDeadline}</td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border uppercase ${kevStatusColors[kev.status]}`}>
                        {kev.status.replace('_', ' ')}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Risk Heat Map */}
          <div className="col-span-2 bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
            <div className="px-5 py-4 border-b border-[#1e2028]">
              <h2 className="text-sm font-semibold text-[#e8eaf0]">Risk Heat Map</h2>
              <p className="text-xs text-[#8892a4] mt-0.5">Severity × Likelihood matrix</p>
            </div>
            <div className="p-5">
              <div className="flex items-end gap-2">
                {/* Y-axis label */}
                <div className="flex flex-col justify-between h-[180px] shrink-0">
                  {['Critical', 'High', 'Medium', 'Low'].map((l) => (
                    <span key={l} className="text-[9px] text-[#8892a4] text-right w-12">{l}</span>
                  ))}
                </div>
                <div className="flex-1">
                  <div className="grid grid-cols-4 gap-1.5" style={{ height: 180 }}>
                    {heatmapData.map((row, ri) =>
                      row.map((cell, ci) => (
                        <div
                          key={`${ri}-${ci}`}
                          className="rounded flex items-center justify-center text-xs font-bold text-white cursor-pointer hover:opacity-80 transition-opacity"
                          style={{ background: cell.color }}
                          title={`${cell.count} findings`}
                        >
                          {cell.count}
                        </div>
                      ))
                    )}
                  </div>
                  <div className="grid grid-cols-4 gap-1.5 mt-1.5">
                    {['Unlikely', 'Possible', 'Likely', 'Near Certain'].map((l) => (
                      <span key={l} className="text-[9px] text-[#8892a4] text-center">{l}</span>
                    ))}
                  </div>
                  <div className="text-[9px] text-[#8892a4] text-center mt-1">Likelihood</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Patch Priority Queue */}
        <div className="bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-[#1e2028] flex items-center gap-3">
            <h2 className="text-sm font-semibold text-[#e8eaf0]">AI-Ranked Patch Priority Queue</h2>
            <span className="text-[10px] font-bold text-[#00d4ff] bg-[rgba(0,212,255,0.1)] border border-[rgba(0,212,255,0.3)] px-2 py-0.5 rounded">
              AI RANKED
            </span>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2028]">
                {['Rank', 'CVE', 'Title', 'Severity', 'Asset', 'EPSS %', 'KEV', 'Days Open', 'Priority Score'].map((h) => (
                  <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {patchPriority.map((p) => (
                <tr key={p.rank} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                  <td className="px-4 py-3 text-xs font-bold text-[#8892a4]">#{p.rank}</td>
                  <td className="px-4 py-3 font-mono text-xs text-[#4fc3f7]">{p.cve ?? '—'}</td>
                  <td className="px-4 py-3 text-xs text-[#e8eaf0]">{p.title}</td>
                  <td className="px-4 py-3"><SeverityBadge severity={p.severity} /></td>
                  <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">{p.asset}</td>
                  <td className="px-4 py-3 text-xs font-bold" style={{ color: p.epss > 80 ? '#ff3b3b' : p.epss > 50 ? '#ff6b35' : p.epss > 0 ? '#ffcc00' : '#3a3d4a' }}>
                    {p.epss > 0 ? `${p.epss}%` : '—'}
                  </td>
                  <td className="px-4 py-3">
                    {p.kev && (
                      <span className="text-[10px] font-bold text-[#ff3b3b] bg-[rgba(255,59,59,0.1)] border border-[rgba(255,59,59,0.3)] px-1.5 py-0.5 rounded">KEV</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs font-mono" style={{ color: p.daysOpen > 365 ? '#ff3b3b' : p.daysOpen > 90 ? '#ff6b35' : '#ffcc00' }}>
                    {p.daysOpen}d
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 bg-[#1e2028] rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${p.score}%`,
                            background: p.score >= 90 ? '#ff3b3b' : p.score >= 70 ? '#ff6b35' : '#ffcc00',
                          }}
                        />
                      </div>
                      <span className="text-xs font-bold text-[#e8eaf0]">{p.score}</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </DashboardLayout>
  );
}
