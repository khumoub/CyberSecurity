'use client';

import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { useRiskScores, useCisaKev, useRiskHeatmap, usePatchPriority } from '@/lib/hooks';

const kevStatusColors: Record<string, string> = {
  patched: 'text-[#00ff88] bg-[rgba(0,255,136,0.1)] border-[rgba(0,255,136,0.3)]',
  unpatched: 'text-[#ff3b3b] bg-[rgba(255,59,59,0.1)] border-[rgba(255,59,59,0.3)]',
  in_progress: 'text-[#00d4ff] bg-[rgba(0,212,255,0.1)] border-[rgba(0,212,255,0.3)]',
};

// Static heatmap when API data unavailable
const staticHeatmap: { count: number; color: string }[][] = [
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

function cellColor(likelihood: number, severity: number): string {
  const score = likelihood * severity;
  if (score >= 12) return 'rgba(255,59,59,0.8)';
  if (score >= 8) return 'rgba(255,107,53,0.6)';
  if (score >= 4) return 'rgba(255,204,0,0.5)';
  return 'rgba(79,195,247,0.4)';
}

function buildHeatmap(data: any[]): { count: number; color: string }[][] {
  // data is array of { likelihood: 1-4, severity: 1-4, count: number }
  const grid: { count: number; color: string }[][] = Array.from({ length: 4 }, () =>
    Array.from({ length: 4 }, () => ({ count: 0, color: 'rgba(79,195,247,0.2)' }))
  );
  for (const cell of data) {
    const ri = 4 - (cell.severity ?? 1); // severity 4=critical=row 0
    const ci = (cell.likelihood ?? 1) - 1;
    if (ri >= 0 && ri < 4 && ci >= 0 && ci < 4) {
      grid[ri][ci] = { count: cell.count, color: cellColor(cell.likelihood, cell.severity) };
    }
  }
  return grid;
}

function MiniSparkline({ data }: { data: number[] }) {
  if (!data || data.length < 2) return null;
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

export default function RiskIntelligencePage() {
  const riskScoresQ = useRiskScores();
  const cisaKevQ = useCisaKev();
  const heatmapQ = useRiskHeatmap();
  const patchQ = usePatchPriority();

  const assetRisks: any[] = riskScoresQ.data?.scores ?? riskScoresQ.data ?? [];
  const kevEntries: any[] = cisaKevQ.data?.vulnerabilities ?? cisaKevQ.data ?? [];
  const heatmapRaw: any[] = heatmapQ.data?.cells ?? heatmapQ.data ?? [];
  const patchList: any[] = patchQ.data?.findings ?? patchQ.data ?? [];

  const heatmapData = heatmapRaw.length > 0 ? buildHeatmap(heatmapRaw) : staticHeatmap;
  const unpatchedKev = kevEntries.filter((k: any) => k.status === 'unpatched' || k.match_status === 'unpatched').length;

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
              {riskScoresQ.isLoading
                ? Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={7} />)
                : assetRisks.length === 0
                ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-[#8892a4]">
                      No risk scores yet. Run scans to populate data.
                    </td>
                  </tr>
                )
                : assetRisks.map((asset: any) => {
                  const score = asset.risk_score ?? asset.score ?? 0;
                  const delta = asset.delta ?? asset.score_delta ?? 0;
                  return (
                    <tr key={asset.id ?? asset.asset_id} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                      <td className="px-4 py-3 font-mono text-xs text-[#4fc3f7]">{asset.asset_value ?? asset.host}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span
                            className="text-lg font-bold"
                            style={{ color: score >= 9 ? '#ff3b3b' : score >= 7 ? '#ff6b35' : score >= 5 ? '#ffcc00' : '#4fc3f7' }}
                          >
                            {score.toFixed(1)}
                          </span>
                          <div className="w-16 h-1.5 bg-[#1e2028] rounded-full overflow-hidden">
                            <div
                              className="h-full rounded-full"
                              style={{
                                width: `${Math.min(score * 10, 100)}%`,
                                background: score >= 9 ? '#ff3b3b' : score >= 7 ? '#ff6b35' : score >= 5 ? '#ffcc00' : '#4fc3f7',
                              }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs font-bold text-[#ff3b3b]">{(asset.critical_count ?? asset.critical) || '—'}</td>
                      <td className="px-4 py-3 text-xs font-bold text-[#ff6b35]">{(asset.high_count ?? asset.high) || '—'}</td>
                      <td className="px-4 py-3 text-xs font-bold text-[#ffcc00]">{(asset.medium_count ?? asset.medium) || '—'}</td>
                      <td className="px-4 py-3">
                        <MiniSparkline data={asset.trend ?? []} />
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-bold ${delta > 0 ? 'text-[#ff3b3b]' : 'text-[#00ff88]'}`}>
                          {delta > 0 ? '+' : ''}{delta.toFixed ? delta.toFixed(1) : delta}
                        </span>
                      </td>
                    </tr>
                  );
                })
              }
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
              {unpatchedKev > 0 && (
                <span className="text-[10px] font-bold text-[#ff3b3b] bg-[rgba(255,59,59,0.1)] border border-[rgba(255,59,59,0.3)] px-2 py-0.5 rounded">
                  {unpatchedKev} UNPATCHED
                </span>
              )}
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
                {cisaKevQ.isLoading
                  ? Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={6} />)
                  : kevEntries.length === 0
                  ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-[#8892a4]">
                        No CISA KEV matches found in your environment.
                      </td>
                    </tr>
                  )
                  : kevEntries.slice(0, 10).map((kev: any, i: number) => {
                    const status = kev.match_status ?? kev.status ?? 'unpatched';
                    return (
                      <tr key={kev.cve_id ?? i} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                        <td className="px-4 py-3 font-mono text-xs text-[#4fc3f7]">{kev.cve_id}</td>
                        <td className="px-4 py-3 text-xs text-[#e8eaf0]">{kev.vendor_project ?? kev.vendor ?? '—'}</td>
                        <td className="px-4 py-3 text-xs text-[#8892a4]">{kev.product ?? '—'}</td>
                        <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">{kev.date_added ?? '—'}</td>
                        <td className="px-4 py-3 font-mono text-xs text-[#ffcc00]">{kev.due_date ?? kev.required_action ?? '—'}</td>
                        <td className="px-4 py-3">
                          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border uppercase ${kevStatusColors[status] ?? kevStatusColors.unpatched}`}>
                            {status.replace('_', ' ')}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                }
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
                {['Rank', 'CVE', 'Title', 'Severity', 'Asset', 'EPSS %', 'KEV', 'Days Open', 'AI Recommendation'].map((h) => (
                  <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {patchQ.isLoading
                ? Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} cols={9} />)
                : patchList.length === 0
                ? (
                  <tr>
                    <td colSpan={9} className="px-4 py-8 text-center text-[#8892a4]">
                      No findings to rank. Run scans to populate the patch priority queue.
                    </td>
                  </tr>
                )
                : patchList.map((p: any, i: number) => {
                  const rank = p.ai_rank ?? p.priority_rank ?? i + 1;
                  const daysOpen = p.days_open ?? 0;
                  const epss = p.epss_score ?? p.epss ?? 0;
                  return (
                    <tr key={p.id ?? i} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                      <td className="px-4 py-3 text-xs font-bold text-[#8892a4]">#{rank}</td>
                      <td className="px-4 py-3 font-mono text-xs text-[#4fc3f7]">{p.cve_id ?? '—'}</td>
                      <td className="px-4 py-3 text-xs text-[#e8eaf0] max-w-[160px]">
                        <span className="truncate block">{p.title}</span>
                      </td>
                      <td className="px-4 py-3"><SeverityBadge severity={p.severity} /></td>
                      <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">{p.asset_value ?? '—'}</td>
                      <td
                        className="px-4 py-3 text-xs font-bold"
                        style={{ color: epss > 0.8 ? '#ff3b3b' : epss > 0.5 ? '#ff6b35' : epss > 0 ? '#ffcc00' : '#3a3d4a' }}
                      >
                        {epss > 0 ? `${(epss * 100).toFixed(1)}%` : '—'}
                      </td>
                      <td className="px-4 py-3">
                        {(p.is_known_exploited || p.kev) && (
                          <span className="text-[10px] font-bold text-[#ff3b3b] bg-[rgba(255,59,59,0.1)] border border-[rgba(255,59,59,0.3)] px-1.5 py-0.5 rounded">
                            KEV
                          </span>
                        )}
                      </td>
                      <td
                        className="px-4 py-3 text-xs font-mono"
                        style={{ color: daysOpen > 365 ? '#ff3b3b' : daysOpen > 90 ? '#ff6b35' : '#ffcc00' }}
                      >
                        {daysOpen}d
                      </td>
                      <td className="px-4 py-3 text-xs text-[#8892a4] max-w-[200px]">
                        <span className="line-clamp-2">{p.ai_recommendation ?? p.remediation ?? '—'}</span>
                      </td>
                    </tr>
                  );
                })
              }
            </tbody>
          </table>
        </div>
      </div>
    </DashboardLayout>
  );
}
