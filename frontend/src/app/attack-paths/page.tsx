'use client';

import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { useAttackPaths, useAttackPathChains, useVprScores } from '@/lib/hooks';

function RiskDot({ risk }: { risk: string }) {
  const color = risk === 'critical' ? '#ff3b3b' : risk === 'high' ? '#ff6b35' : '#ffcc00';
  return <span className="inline-block w-2 h-2 rounded-full mr-1.5" style={{ background: color }} />;
}

// Simple SVG-based force-directed layout (static positions based on index)
function AttackGraph({ nodes, edges }: { nodes: any[]; edges: any[] }) {
  const W = 800, H = 480;
  const n = nodes.length;
  if (n === 0) return (
    <div className="flex items-center justify-center h-full text-[#8892a4] text-sm">
      No asset graph data. Run scans to populate.
    </div>
  );

  // Place nodes in a circle
  const positions: Record<string, { x: number; y: number }> = {};
  nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / n - Math.PI / 2;
    const r = Math.min(W, H) * 0.35;
    positions[node.id] = {
      x: W / 2 + r * Math.cos(angle),
      y: H / 2 + r * Math.sin(angle),
    };
  });

  const nodeColor = (risk: string) =>
    risk === 'critical' ? '#ff3b3b' : risk === 'high' ? '#ff6b35' : risk === 'medium' ? '#ffcc00' : '#4fc3f7';

  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" height="100%">
      {/* Edges */}
      {edges.map((edge, i) => {
        const s = positions[edge.source];
        const t = positions[edge.target];
        if (!s || !t) return null;
        return (
          <g key={i}>
            <line x1={s.x} y1={s.y} x2={t.x} y2={t.y}
              stroke="rgba(0,212,255,0.25)" strokeWidth="1.5" strokeDasharray="4 3" />
            <text
              x={(s.x + t.x) / 2} y={(s.y + t.y) / 2 - 4}
              fontSize="8" fill="#3a3d4a" textAnchor="middle"
            >
              {edge.label}
            </text>
          </g>
        );
      })}
      {/* Nodes */}
      {nodes.map((node) => {
        const { x, y } = positions[node.id];
        const color = nodeColor(node.risk);
        const r = node.risk === 'critical' ? 28 : node.risk === 'high' ? 24 : 20;
        return (
          <g key={node.id}>
            <circle cx={x} cy={y} r={r + 4} fill={`${color}18`} />
            <circle cx={x} cy={y} r={r} fill={`${color}30`} stroke={color} strokeWidth="1.5" />
            <text x={x} y={y + 1} textAnchor="middle" dominantBaseline="middle"
              fontSize="9" fontWeight="bold" fill={color}>
              {node.risk === 'critical' ? 'C' : node.risk === 'high' ? 'H' : 'M'}
            </text>
            <text x={x} y={y + r + 12} textAnchor="middle"
              fontSize="9" fill="#8892a4">
              {node.label.length > 16 ? node.label.slice(0, 14) + '…' : node.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

export default function AttackPathsPage() {
  const { data, isLoading } = useAttackPaths();

  const nodes: any[]   = data?.nodes ?? [];
  const edges: any[]   = data?.edges ?? [];
  const summary: any   = data?.summary ?? {};

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6 min-h-full">
        <div>
          <h1 className="text-xl font-bold text-[#e8eaf0]">Attack Path Visualisation</h1>
          <p className="text-[#8892a4] text-sm mt-0.5">
            Asset graph showing lateral movement potential based on shared CVEs and network exposure
          </p>
        </div>

        {/* Summary cards */}
        <div className="grid grid-cols-3 gap-4">
          {[
            { label: 'Assets in Graph', value: summary.total_nodes ?? nodes.length, color: '#00d4ff' },
            { label: 'Attack Vectors', value: summary.total_edges ?? edges.length, color: '#ff6b35' },
            { label: 'Critical Nodes', value: summary.critical_nodes ?? nodes.filter((n: any) => n.risk === 'critical').length, color: '#ff3b3b' },
          ].map(stat => (
            <div key={stat.label} className="bg-[#111318] border border-[#1e2028] rounded-lg p-4">
              <div className="text-[#8892a4] text-xs uppercase tracking-wider mb-2">{stat.label}</div>
              <div className="text-2xl font-bold" style={{ color: stat.color }}>
                {isLoading ? '—' : stat.value}
              </div>
            </div>
          ))}
        </div>

        {/* Graph */}
        <div className="bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-[#1e2028] flex items-center gap-4">
            <h2 className="text-sm font-semibold text-[#e8eaf0]">Network Attack Graph</h2>
            <div className="flex items-center gap-4 text-xs text-[#8892a4] ml-auto">
              {[
                { color: '#ff3b3b', label: 'Critical' },
                { color: '#ff6b35', label: 'High' },
                { color: '#ffcc00', label: 'Medium' },
              ].map(({ color, label }) => (
                <div key={label} className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ background: color }} />
                  {label}
                </div>
              ))}
              <div className="flex items-center gap-1">
                <span className="inline-block w-6 border-t border-dashed border-[rgba(0,212,255,0.4)]" />
                Shared CVE
              </div>
            </div>
          </div>
          <div className="p-4" style={{ height: 500 }}>
            {isLoading ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-[#8892a4] text-sm animate-pulse">Computing attack paths…</div>
              </div>
            ) : (
              <AttackGraph nodes={nodes} edges={edges} />
            )}
          </div>
        </div>

        {/* Asset table */}
        <div className="bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-[#1e2028]">
            <h2 className="text-sm font-semibold text-[#e8eaf0]">Nodes — Asset Risk Summary</h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2028]">
                {['Asset', 'Type', 'Risk Level', 'Critical', 'High', 'KEV', 'Total Findings'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading
                ? Array.from({ length: 5 }).map((_, i) => (
                    <tr key={i}><td colSpan={7} className="px-4 py-3"><div className="h-4 bg-[#1e2028] rounded animate-pulse" /></td></tr>
                  ))
                : nodes.length === 0
                ? <tr><td colSpan={7} className="px-4 py-8 text-center text-[#8892a4]">No assets with findings. Run scans first.</td></tr>
                : nodes.map((node: any) => (
                  <tr key={node.id} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-[#4fc3f7]">{node.label}</td>
                    <td className="px-4 py-3 text-xs text-[#8892a4] capitalize">{node.asset_type}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center">
                        <RiskDot risk={node.risk} />
                        <span className="text-xs font-bold capitalize" style={{
                          color: node.risk === 'critical' ? '#ff3b3b' : node.risk === 'high' ? '#ff6b35' : '#ffcc00'
                        }}>{node.risk}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs font-bold text-[#ff3b3b]">{node.critical || '—'}</td>
                    <td className="px-4 py-3 text-xs font-bold text-[#ff6b35]">{node.high || '—'}</td>
                    <td className="px-4 py-3">
                      {node.kev > 0 && (
                        <span className="text-[10px] font-bold text-[#ff3b3b] bg-[rgba(255,59,59,0.1)] border border-[rgba(255,59,59,0.3)] px-1.5 py-0.5 rounded">
                          {node.kev} KEV
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-[#e8eaf0] font-mono">{node.total}</td>
                  </tr>
                ))
              }
            </tbody>
          </table>
        </div>

        {/* Edge table */}
        {edges.length > 0 && (
          <div className="bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
            <div className="px-5 py-4 border-b border-[#1e2028]">
              <h2 className="text-sm font-semibold text-[#e8eaf0]">Edges — Lateral Movement Vectors</h2>
              <p className="text-xs text-[#8892a4] mt-0.5">Assets sharing the same CVE represent potential lateral movement paths</p>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2028]">
                  {['Source Asset', 'Target Asset', 'Shared CVE', 'Vector Type'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {edges.slice(0, 20).map((edge: any, i: number) => {
                  const src = nodes.find(n => n.id === edge.source);
                  const tgt = nodes.find(n => n.id === edge.target);
                  return (
                    <tr key={i} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                      <td className="px-4 py-3 font-mono text-xs text-[#4fc3f7]">{src?.label ?? edge.source}</td>
                      <td className="px-4 py-3 font-mono text-xs text-[#4fc3f7]">{tgt?.label ?? edge.target}</td>
                      <td className="px-4 py-3 font-mono text-xs text-[#ffcc00]">{edge.label}</td>
                      <td className="px-4 py-3 text-xs text-[#8892a4] capitalize">{(edge.type ?? 'shared_cve').replace(/_/g, ' ')}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {/* ── Multi-hop Attack Path Chains ── */}
      <AttackChains />

      {/* ── VPR Prioritization ── */}
      <VprTable />
    </DashboardLayout>
  );
}

function AttackChains() {
  const { data, isLoading } = useAttackPathChains();
  if (isLoading) return <div style={{ color: '#94a3b8', padding: '20px 0', fontSize: 14 }}>Loading attack chains...</div>;
  const chains = data?.chains || [];
  const recommended = data?.recommended_fix;
  if (chains.length === 0) return null;

  return (
    <div style={{ marginTop: 32 }}>
      <h2 style={{ color: '#fff', fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Multi-Hop Attack Chains</h2>
      <p style={{ color: '#94a3b8', fontSize: 13, marginBottom: 16 }}>
        {data?.total_chains} chains detected across {data?.assets_analyzed} assets. Max depth: {data?.max_hop_count} hops.
      </p>
      {recommended && (
        <div style={{ background: '#fbbf2411', border: '1px solid #fbbf24', borderRadius: 8, padding: 12, marginBottom: 16, display: 'flex', gap: 12, alignItems: 'center' }}>
          <span style={{ fontSize: 20 }}>💡</span>
          <div>
            <div style={{ color: '#fbbf24', fontWeight: 600, fontSize: 13 }}>Highest Impact Fix</div>
            <div style={{ color: '#e2e8f0', fontSize: 13 }}>{recommended.message} — fixing <code style={{ color: '#a78bfa' }}>{recommended.cve_id}</code> eliminates the most attack paths</div>
          </div>
        </div>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {chains.slice(0, 10).map((chain: any, i: number) => (
          <div key={i} style={{ background: '#1a1a2e', border: `1px solid ${chain.has_kev ? '#ef444433' : '#2d2d4e'}`, borderRadius: 8, padding: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                {chain.path_labels.map((label: string, idx: number) => (
                  <span key={idx} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={{ background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 4, padding: '2px 8px', fontSize: 12, color: '#e2e8f0' }}>{label}</span>
                    {idx < chain.path_labels.length - 1 && <span style={{ color: '#ef4444', fontSize: 14 }}>→</span>}
                  </span>
                ))}
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                {chain.has_kev && <span style={{ background: '#dc262633', color: '#f87171', border: '1px solid #dc2626', borderRadius: 12, padding: '1px 6px', fontSize: 10 }}>KEV</span>}
                <span style={{ color: '#94a3b8', fontSize: 12 }}>{chain.hop_count} hop{chain.hop_count > 1 ? 's' : ''}</span>
                <span style={{ color: '#f59e0b', fontSize: 13, fontWeight: 700 }}>Risk: {chain.chain_risk_score}</span>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {chain.shared_cves.map((cve: string) => (
                <span key={cve} style={{ background: '#7c3aed22', color: '#a78bfa', border: '1px solid #7c3aed44', borderRadius: 4, padding: '1px 6px', fontSize: 11, fontFamily: 'monospace' }}>{cve}</span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function VprTable() {
  const { data, isLoading } = useVprScores(20);
  if (isLoading || !data?.findings?.length) return null;

  return (
    <div style={{ marginTop: 32 }}>
      <h2 style={{ color: '#fff', fontSize: 18, fontWeight: 700, marginBottom: 4 }}>VPR — Vulnerability Priority Rating</h2>
      <p style={{ color: '#94a3b8', fontSize: 13, marginBottom: 16 }}>
        Composite score: CVSS × EPSS × KEV × exploit availability × asset criticality. Normalized to 0–10.
      </p>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ background: '#0d0d1f' }}>
              {['VPR', 'Finding', 'CVE', 'Severity', 'CVSS', 'EPSS', 'Asset', 'KEV', 'Exploit'].map(h => (
                <th key={h} style={{ padding: '10px 12px', color: '#94a3b8', textAlign: 'left', borderBottom: '1px solid #2d2d4e', fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.findings.map((f: any) => (
              <tr key={f.finding_id} style={{ borderBottom: '1px solid #1a1a2e' }}>
                <td style={{ padding: '8px 12px' }}>
                  <span style={{ background: f.vpr_score >= 8 ? '#ef444422' : f.vpr_score >= 5 ? '#f59e0b22' : '#22c55e22', color: f.vpr_score >= 8 ? '#f87171' : f.vpr_score >= 5 ? '#fbbf24' : '#4ade80', fontWeight: 700, borderRadius: 4, padding: '2px 8px' }}>
                    {f.vpr_score}
                  </span>
                </td>
                <td style={{ padding: '8px 12px', color: '#e2e8f0', maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</td>
                <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#a78bfa', fontSize: 11 }}>{f.cve_id || '—'}</td>
                <td style={{ padding: '8px 12px' }}>
                  <span style={{ color: f.severity === 'critical' ? '#f87171' : f.severity === 'high' ? '#fb923c' : f.severity === 'medium' ? '#fbbf24' : '#94a3b8' }}>
                    {f.severity}
                  </span>
                </td>
                <td style={{ padding: '8px 12px', color: '#94a3b8' }}>{f.cvss_score || '—'}</td>
                <td style={{ padding: '8px 12px', color: '#94a3b8' }}>{f.epss_score ? (f.epss_score * 100).toFixed(1) + '%' : '—'}</td>
                <td style={{ padding: '8px 12px', color: '#94a3b8', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.asset_name || '—'}</td>
                <td style={{ padding: '8px 12px' }}>{f.is_known_exploited ? <span style={{ color: '#f87171' }}>⚠ KEV</span> : <span style={{ color: '#4b5563' }}>—</span>}</td>
                <td style={{ padding: '8px 12px' }}>{f.exploit_available ? <span style={{ color: '#fb923c' }}>✓</span> : <span style={{ color: '#4b5563' }}>—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
