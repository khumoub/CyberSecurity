'use client';

import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { StatCard } from '@/components/ui/StatCard';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { ScanLaunchModal } from '@/components/ui/ScanLaunchModal';
import { useDashboardStats, useSeverityTrend, useFindingSlaSummary } from '@/lib/hooks';
import { useState } from 'react';
import { formatDistanceToNow } from 'date-fns';

type FindingStatus = 'open' | 'in_remediation' | 'resolved' | 'accepted_risk';
type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

const statusColors: Record<FindingStatus, string> = {
  open: 'text-[#ff6b35] bg-[rgba(255,107,53,0.12)] border-[rgba(255,107,53,0.3)]',
  in_remediation: 'text-[#00d4ff] bg-[rgba(0,212,255,0.12)] border-[rgba(0,212,255,0.3)]',
  resolved: 'text-[#00ff88] bg-[rgba(0,255,136,0.12)] border-[rgba(0,255,136,0.3)]',
  accepted_risk: 'text-[#8892a4] bg-[rgba(136,146,164,0.12)] border-[rgba(136,146,164,0.3)]',
};

const scanStatusColors: Record<ScanStatus, string> = {
  pending: 'text-[#8892a4]',
  running: 'text-[#00d4ff]',
  completed: 'text-[#00ff88]',
  failed: 'text-[#ff3b3b]',
  cancelled: 'text-[#ffcc00]',
};

function SkeletonRow({ cols }: { cols: number }) {
  return (
    <tr>
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-[#1e2028] rounded animate-pulse w-3/4" />
        </td>
      ))}
    </tr>
  );
}

// Simple SVG sparkline
function Sparkline({ data, color, height = 40 }: { data: number[]; color: string; height?: number }) {
  if (!data || data.length < 2) return <div className="h-10 flex items-center text-xs text-[#8892a4]">No data</div>;
  const max = Math.max(...data, 1);
  const w = 200;
  const h = height;
  const step = w / (data.length - 1);
  const points = data
    .map((v, i) => `${i * step},${h - (v / max) * (h - 4)}`)
    .join(' ');
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full" style={{ height }}>
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

// SLA donut-style gauge
function SlaWidget({ overdue, dueThisWeek, onTrack }: { overdue: number; dueThisWeek: number; onTrack: number }) {
  const total = overdue + dueThisWeek + onTrack;
  if (total === 0) return (
    <div className="flex items-center justify-center h-full text-xs text-[#8892a4]">No SLA findings</div>
  );
  return (
    <div className="grid grid-cols-3 gap-2 text-center text-xs">
      <div className="bg-[rgba(255,59,59,0.08)] border border-[rgba(255,59,59,0.2)] rounded-lg py-3">
        <div className="text-xl font-bold text-[#ff3b3b]">{overdue}</div>
        <div className="text-[#8892a4] mt-0.5">Overdue</div>
      </div>
      <div className="bg-[rgba(255,204,0,0.08)] border border-[rgba(255,204,0,0.2)] rounded-lg py-3">
        <div className="text-xl font-bold text-[#ffcc00]">{dueThisWeek}</div>
        <div className="text-[#8892a4] mt-0.5">Due 7d</div>
      </div>
      <div className="bg-[rgba(0,255,136,0.08)] border border-[rgba(0,255,136,0.2)] rounded-lg py-3">
        <div className="text-xl font-bold text-[#00ff88]">{onTrack}</div>
        <div className="text-[#8892a4] mt-0.5">On Track</div>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { data, isLoading, error, refetch } = useDashboardStats();
  const { data: trendData } = useSeverityTrend(30);
  const { data: slaData } = useFindingSlaSummary();
  const [showScanModal, setShowScanModal] = useState(false);

  const stats = data?.stats;
  const recentFindings = data?.recent_findings ?? [];
  const recentScans = data?.recent_scans ?? [];
  const riskScore = data?.risk_score ?? 0;

  // Build sparkline series from trend
  const trendDays: any[] = trendData?.trend ?? [];
  const criticalSeries = trendDays.map((d: any) => d.critical ?? 0);
  const highSeries = trendDays.map((d: any) => d.high ?? 0);
  const totalSeries = trendDays.map((d: any) => (d.critical ?? 0) + (d.high ?? 0) + (d.medium ?? 0));

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-[#e8eaf0]">Security Operations Center</h1>
            <p className="text-sm text-[#8892a4] mt-0.5">
              {new Date().toLocaleDateString('en-GB', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
              {error && <span className="ml-3 text-[#ff3b3b]">— API connection error</span>}
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setShowScanModal(true)}
              className="text-xs bg-[rgba(0,212,255,0.1)] border border-[rgba(0,212,255,0.3)] text-[#00d4ff] hover:bg-[rgba(0,212,255,0.18)] transition-colors px-3 py-1.5 rounded-lg font-medium"
            >
              ▶ New Scan
            </button>
            <button
              onClick={() => refetch()}
              className="text-xs text-[#8892a4] hover:text-[#00d4ff] transition-colors border border-[#1e2028] px-3 py-1.5 rounded-lg"
            >
              ↻ Refresh
            </button>
          </div>
        </div>

        {/* Alert strip */}
        {!isLoading && ((stats?.sla_breaches ?? 0) > 0 || (stats?.known_exploited_count ?? 0) > 0) && (
          <div className="flex gap-3 flex-wrap">
            {(stats?.sla_breaches ?? 0) > 0 && (
              <div className="flex items-center gap-2 bg-[rgba(255,59,59,0.1)] border border-[rgba(255,59,59,0.3)] rounded-lg px-4 py-2 text-sm text-[#ff3b3b]">
                <span className="font-bold">!</span>
                {stats.sla_breaches} SLA breach{stats.sla_breaches > 1 ? 'es' : ''} — immediate action required
              </div>
            )}
            {(stats?.known_exploited_count ?? 0) > 0 && (
              <div className="flex items-center gap-2 bg-[rgba(255,107,53,0.1)] border border-[rgba(255,107,53,0.3)] rounded-lg px-4 py-2 text-sm text-[#ff6b35]">
                <span className="font-bold">KEV</span>
                {stats.known_exploited_count} CISA Known Exploited Vulnerabilities detected
              </div>
            )}
          </div>
        )}

        {/* Stats Row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="Total Assets"
            value={isLoading ? '—' : (stats?.total_assets ?? 0)}
            sub={`${stats?.active_assets ?? 0} active`}
            accentColor="#00d4ff"
          />
          <StatCard
            label="Open Findings"
            value={isLoading ? '—' : (stats?.findings?.open ?? 0)}
            sub={isLoading ? '' : `${stats?.findings?.critical ?? 0}C · ${stats?.findings?.high ?? 0}H · ${stats?.findings?.medium ?? 0}M`}
            accentColor="#ff3b3b"
          />
          <StatCard
            label="Active Scans"
            value={isLoading ? '—' : (stats?.active_scans ?? 0)}
            sub={`${stats?.completed_today ?? 0} completed today`}
            accentColor="#00ff88"
          />
          <StatCard
            label="Risk Score"
            value={isLoading ? '—' : `${riskScore}/100`}
            sub={riskScore >= 80 ? 'Critical Risk' : riskScore >= 60 ? 'High Risk' : riskScore >= 40 ? 'Medium Risk' : 'Low Risk'}
            accentColor={riskScore >= 80 ? '#ff3b3b' : riskScore >= 60 ? '#ff6b35' : riskScore >= 40 ? '#ffcc00' : '#00ff88'}
          />
        </div>

        {/* Trend + SLA row */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          {/* 30-day severity trend */}
          <div className="xl:col-span-2 bg-[#111318] border border-[#1e2028] rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-semibold text-[#e8eaf0]">30-Day Findings Trend</h2>
              <div className="flex gap-3 text-xs">
                <span className="flex items-center gap-1"><span className="inline-block w-3 h-0.5 bg-[#ff3b3b]" /> Critical</span>
                <span className="flex items-center gap-1"><span className="inline-block w-3 h-0.5 bg-[#ff6b35]" /> High</span>
                <span className="flex items-center gap-1 text-[#8892a4]"><span className="inline-block w-3 h-0.5 bg-[#8892a4]" /> Total</span>
              </div>
            </div>
            {trendDays.length === 0 ? (
              <div className="h-12 flex items-center text-xs text-[#8892a4]">Trend data will appear after findings accumulate</div>
            ) : (
              <div className="space-y-2">
                <div className="relative">
                  <div className="absolute left-0 top-0 text-xs text-[#8892a4]">Critical</div>
                  <div className="mt-4"><Sparkline data={criticalSeries} color="#ff3b3b" height={36} /></div>
                </div>
                <div className="relative">
                  <div className="absolute left-0 top-0 text-xs text-[#8892a4]">High</div>
                  <div className="mt-4"><Sparkline data={highSeries} color="#ff6b35" height={36} /></div>
                </div>
                <div className="relative">
                  <div className="absolute left-0 top-0 text-xs text-[#8892a4]">Total</div>
                  <div className="mt-4"><Sparkline data={totalSeries} color="#8892a4" height={36} /></div>
                </div>
              </div>
            )}
          </div>

          {/* SLA widget */}
          <div className="bg-[#111318] border border-[#1e2028] rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-semibold text-[#e8eaf0]">SLA Status</h2>
              <a href="/vulnerability-management" className="text-xs text-[#00d4ff] hover:underline">Manage →</a>
            </div>
            <SlaWidget
              overdue={slaData?.overdue ?? 0}
              dueThisWeek={slaData?.due_this_week ?? 0}
              onTrack={slaData?.on_track ?? 0}
            />
            {slaData && (
              <p className="text-xs text-[#8892a4] mt-3 text-center">
                {slaData.total_with_sla} findings tracked against SLA
              </p>
            )}
          </div>
        </div>

        {/* Middle Row */}
        <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
          {/* Recent Findings */}
          <div className="xl:col-span-3 bg-[#111318] border border-[#1e2028] rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-[#1e2028] flex items-center justify-between">
              <h2 className="font-semibold text-[#e8eaf0]">Recent Findings</h2>
              <a href="/vulnerability-management" className="text-xs text-[#00d4ff] hover:underline">View all →</a>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[#8892a4] text-xs uppercase tracking-wide border-b border-[#1e2028]">
                    <th className="px-4 py-3 text-left">Severity</th>
                    <th className="px-4 py-3 text-left">Finding</th>
                    <th className="px-4 py-3 text-left">CVE</th>
                    <th className="px-4 py-3 text-left">Asset</th>
                    <th className="px-4 py-3 text-left">Status</th>
                    <th className="px-4 py-3 text-left">When</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2028]">
                  {isLoading
                    ? Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} cols={6} />)
                    : recentFindings.length === 0
                    ? (
                      <tr>
                        <td colSpan={6} className="px-4 py-8 text-center text-[#8892a4]">
                          No findings yet. Run your first scan to get started.
                        </td>
                      </tr>
                    )
                    : recentFindings.map((f: any) => (
                      <tr key={f.id} className="hover:bg-[#0d0f14] transition-colors">
                        <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                        <td className="px-4 py-3 max-w-[200px]">
                          <span className="text-[#e8eaf0] truncate block" title={f.title}>{f.title}</span>
                        </td>
                        <td className="px-4 py-3">
                          {f.cve_id
                            ? <a href={`/threat-intel?cve=${f.cve_id}`} className="text-[#00d4ff] font-mono text-xs hover:underline">{f.cve_id}</a>
                            : <span className="text-[#3a3d4a]">—</span>
                          }
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">{f.asset_value}</td>
                        <td className="px-4 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded border ${statusColors[f.status as FindingStatus] ?? statusColors.open}`}>
                            {f.status?.replace('_', ' ')}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-[#8892a4] text-xs">
                          {f.created_at ? formatDistanceToNow(new Date(f.created_at), { addSuffix: true }) : '—'}
                        </td>
                      </tr>
                    ))
                  }
                </tbody>
              </table>
            </div>
          </div>

          {/* Scan Activity */}
          <div className="xl:col-span-2 bg-[#111318] border border-[#1e2028] rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-[#1e2028] flex items-center justify-between">
              <h2 className="font-semibold text-[#e8eaf0]">Scan Activity</h2>
              <a href="/vulnerability-management" className="text-xs text-[#00d4ff] hover:underline">View all →</a>
            </div>
            <div className="divide-y divide-[#1e2028]">
              {isLoading
                ? Array.from({ length: 5 }).map((_, i) => (
                  <div key={i} className="px-5 py-3">
                    <div className="h-3 bg-[#1e2028] rounded animate-pulse w-3/4 mb-2" />
                    <div className="h-3 bg-[#1e2028] rounded animate-pulse w-1/2" />
                  </div>
                ))
                : recentScans.length === 0
                ? <p className="px-5 py-8 text-center text-[#8892a4] text-sm">No scans yet.</p>
                : recentScans.map((s: any) => (
                  <div key={s.id} className="px-5 py-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-mono text-[#00d4ff] uppercase">{s.scan_type}</span>
                      <span className={`text-xs font-semibold ${scanStatusColors[s.status as ScanStatus]}`}>
                        {s.status === 'running' && <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#00d4ff] animate-pulse mr-1.5" />}
                        {s.status}
                      </span>
                    </div>
                    <p className="text-sm text-[#e8eaf0] font-mono truncate">{s.target}</p>
                    <p className="text-xs text-[#8892a4] mt-0.5">
                      {s.findings_count != null ? `${s.findings_count} findings` : '—'}
                      {s.started_at && ` · ${formatDistanceToNow(new Date(s.started_at), { addSuffix: true })}`}
                    </p>
                  </div>
                ))
              }
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: 'New Scan', icon: '▶', action: () => setShowScanModal(true), color: 'border-[#00d4ff] hover:bg-[rgba(0,212,255,0.06)]' },
            { label: 'Import Assets', icon: '⊕', action: () => window.location.href = '/vulnerability-management', color: 'border-[#1e2028] hover:border-[#00d4ff]' },
            { label: 'Threat Intel', icon: '◈', action: () => window.location.href = '/threat-intel', color: 'border-[#1e2028] hover:border-[#00d4ff]' },
            { label: 'Generate Report', icon: '⬇', action: () => window.location.href = '/reporting', color: 'border-[#1e2028] hover:border-[#00d4ff]' },
            { label: 'All Findings', icon: '◉', action: () => window.location.href = '/vulnerability-management', color: 'border-[#1e2028] hover:border-[#00d4ff]' },
          ].map(({ label, icon, action, color }) => (
            <button
              key={label}
              onClick={action}
              className={`bg-[#111318] border ${color} rounded-xl p-4 text-left transition-all group`}
            >
              <span className="text-2xl text-[#00d4ff] block mb-2">{icon}</span>
              <span className="text-sm font-medium text-[#e8eaf0] group-hover:text-[#00d4ff] transition-colors">{label}</span>
            </button>
          ))}
        </div>
      </div>

      {showScanModal && (
        <ScanLaunchModal
          onClose={() => setShowScanModal(false)}
          onLaunch={() => {
            window.location.href = '/vulnerability-management';
            setShowScanModal(false);
          }}
        />
      )}
    </DashboardLayout>
  );
}
