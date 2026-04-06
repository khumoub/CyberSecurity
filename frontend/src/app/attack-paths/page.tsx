'use client';

import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { useAttackPaths } from '@/lib/hooks';

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
    </DashboardLayout>
  );
}
