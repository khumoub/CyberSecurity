'use client';

import { useState } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';

type RiskTier = 'critical' | 'high' | 'medium' | 'low';
type VendorStatus = 'assessed' | 'pending' | 'overdue' | 'never';

interface Vendor {
  id: string;
  name: string;
  domain: string;
  tier: RiskTier;
  techRiskScore: number;
  dataAccess: string;
  lastAssessed: string;
  status: VendorStatus;
  findings: { critical: number; high: number; medium: number };
}

const vendors: Vendor[] = [
  {
    id: 'v1', name: 'Salesforce', domain: 'salesforce.com', tier: 'critical',
    techRiskScore: 3.2, dataAccess: 'CRM, PII', lastAssessed: '2026-03-01', status: 'assessed',
    findings: { critical: 0, high: 1, medium: 4 },
  },
  {
    id: 'v2', name: 'AWS', domain: 'aws.amazon.com', tier: 'critical',
    techRiskScore: 2.8, dataAccess: 'Cloud Infrastructure', lastAssessed: '2026-02-15', status: 'assessed',
    findings: { critical: 0, high: 0, medium: 2 },
  },
  {
    id: 'v3', name: 'Okta', domain: 'okta.com', tier: 'critical',
    techRiskScore: 4.1, dataAccess: 'Identity & Access', lastAssessed: '2026-01-20', status: 'overdue',
    findings: { critical: 1, high: 2, medium: 3 },
  },
  {
    id: 'v4', name: 'Slack', domain: 'slack.com', tier: 'high',
    techRiskScore: 3.7, dataAccess: 'Internal Comms', lastAssessed: '2026-02-28', status: 'assessed',
    findings: { critical: 0, high: 1, medium: 5 },
  },
  {
    id: 'v5', name: 'GitHub', domain: 'github.com', tier: 'high',
    techRiskScore: 3.5, dataAccess: 'Source Code', lastAssessed: '2026-03-10', status: 'assessed',
    findings: { critical: 0, high: 2, medium: 6 },
  },
  {
    id: 'v6', name: 'Zendesk', domain: 'zendesk.com', tier: 'high',
    techRiskScore: 4.8, dataAccess: 'Customer Data', lastAssessed: '2025-11-15', status: 'overdue',
    findings: { critical: 0, high: 3, medium: 8 },
  },
  {
    id: 'v7', name: 'Stripe', domain: 'stripe.com', tier: 'critical',
    techRiskScore: 2.1, dataAccess: 'Payment Processing', lastAssessed: '2026-03-22', status: 'assessed',
    findings: { critical: 0, high: 0, medium: 1 },
  },
  {
    id: 'v8', name: 'DocuSign', domain: 'docusign.com', tier: 'medium',
    techRiskScore: 3.3, dataAccess: 'Contract Documents', lastAssessed: '2025-09-05', status: 'overdue',
    findings: { critical: 0, high: 1, medium: 3 },
  },
  {
    id: 'v9', name: 'Zoom', domain: 'zoom.us', tier: 'medium',
    techRiskScore: 4.4, dataAccess: 'Internal Video', lastAssessed: '—', status: 'never',
    findings: { critical: 0, high: 0, medium: 0 },
  },
  {
    id: 'v10', name: 'Datadog', domain: 'datadoghq.com', tier: 'high',
    techRiskScore: 3.9, dataAccess: 'Logs, Metrics', lastAssessed: '2026-01-08', status: 'pending',
    findings: { critical: 0, high: 2, medium: 4 },
  },
];

const tierColors: Record<RiskTier, { badge: string; bar: string }> = {
  critical: { badge: 'text-[#ff3b3b] bg-[rgba(255,59,59,0.1)] border-[rgba(255,59,59,0.3)]', bar: '#ff3b3b' },
  high: { badge: 'text-[#ff6b35] bg-[rgba(255,107,53,0.1)] border-[rgba(255,107,53,0.3)]', bar: '#ff6b35' },
  medium: { badge: 'text-[#ffcc00] bg-[rgba(255,204,0,0.1)] border-[rgba(255,204,0,0.3)]', bar: '#ffcc00' },
  low: { badge: 'text-[#4fc3f7] bg-[rgba(79,195,247,0.1)] border-[rgba(79,195,247,0.3)]', bar: '#4fc3f7' },
};

const statusColors: Record<VendorStatus, string> = {
  assessed: 'text-[#00ff88] bg-[rgba(0,255,136,0.1)] border-[rgba(0,255,136,0.3)]',
  pending: 'text-[#ffcc00] bg-[rgba(255,204,0,0.1)] border-[rgba(255,204,0,0.3)]',
  overdue: 'text-[#ff3b3b] bg-[rgba(255,59,59,0.1)] border-[rgba(255,59,59,0.3)]',
  never: 'text-[#8892a4] bg-[rgba(136,146,164,0.1)] border-[rgba(136,146,164,0.3)]',
};

export default function TPRMPage() {
  const [search, setSearch] = useState('');
  const [tierFilter, setTierFilter] = useState<'all' | RiskTier>('all');

  const filtered = vendors.filter((v) => {
    if (tierFilter !== 'all' && v.tier !== tierFilter) return false;
    if (search && !v.name.toLowerCase().includes(search.toLowerCase()) && !v.domain.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const criticalCount = vendors.filter((v) => v.tier === 'critical').length;
  const overdueCount = vendors.filter((v) => v.status === 'overdue').length;
  const highRisk = vendors.filter((v) => v.techRiskScore >= 4).length;

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6 min-h-full">
        {/* Header */}
        <div>
          <h1 className="text-xl font-bold text-[#e8eaf0]">Third Party Risk Management</h1>
          <p className="text-[#8892a4] text-sm mt-0.5">Vendor inventory, tech risk scoring and assessment tracking</p>
        </div>

        {/* Summary stats */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: 'Total Vendors', value: vendors.length, color: '#00d4ff' },
            { label: 'Critical Tier', value: criticalCount, color: '#ff3b3b' },
            { label: 'Overdue Assessments', value: overdueCount, color: '#ffcc00' },
            { label: 'High Tech Risk (≥4.0)', value: highRisk, color: '#ff6b35' },
          ].map((stat) => (
            <div key={stat.label} className="bg-[#111318] border border-[#1e2028] rounded-lg p-4">
              <div className="text-[#8892a4] text-xs uppercase tracking-wider mb-2">{stat.label}</div>
              <div className="text-2xl font-bold" style={{ color: stat.color }}>{stat.value}</div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3">
          <input
            type="text"
            placeholder="Search vendor name or domain..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2 text-sm text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff] w-64"
          />
          <div className="flex gap-1 bg-[#111318] border border-[#1e2028] rounded-lg p-1">
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map((t) => (
              <button
                key={t}
                onClick={() => setTierFilter(t)}
                className={`text-xs font-medium px-3 py-1.5 rounded-md capitalize transition-all ${
                  tierFilter === t ? 'bg-[#1a1f2e] text-[#00d4ff]' : 'text-[#8892a4] hover:text-[#e8eaf0]'
                }`}
              >
                {t}
              </button>
            ))}
          </div>
          <button className="cyber-btn text-sm ml-auto">+ Add Vendor</button>
        </div>

        {/* Vendor table */}
        <div className="bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2028]">
                {['Vendor', 'Domain', 'Risk Tier', 'Tech Risk Score', 'Data Access', 'Last Assessed', 'Assessment Status', 'Findings', ''].map((h) => (
                  <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((vendor) => (
                <tr key={vendor.id} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                  <td className="px-4 py-3">
                    <div className="text-sm font-semibold text-[#e8eaf0]">{vendor.name}</div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-[#4fc3f7]">{vendor.domain}</td>
                  <td className="px-4 py-3">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wide ${tierColors[vendor.tier].badge}`}>
                      {vendor.tier}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span
                        className="text-sm font-bold"
                        style={{ color: vendor.techRiskScore >= 4 ? '#ff3b3b' : vendor.techRiskScore >= 3 ? '#ff6b35' : '#00ff88' }}
                      >
                        {vendor.techRiskScore.toFixed(1)}
                      </span>
                      <div className="w-12 h-1.5 bg-[#1e2028] rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${(vendor.techRiskScore / 10) * 100}%`,
                            background: tierColors[vendor.tier].bar,
                          }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-[#8892a4]">{vendor.dataAccess}</td>
                  <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">{vendor.lastAssessed}</td>
                  <td className="px-4 py-3">
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border uppercase tracking-wide ${statusColors[vendor.status]}`}>
                      {vendor.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-2 text-xs font-mono">
                      {vendor.findings.critical > 0 && (
                        <span className="text-[#ff3b3b] font-bold">C:{vendor.findings.critical}</span>
                      )}
                      {vendor.findings.high > 0 && (
                        <span className="text-[#ff6b35] font-bold">H:{vendor.findings.high}</span>
                      )}
                      {vendor.findings.medium > 0 && (
                        <span className="text-[#ffcc00] font-bold">M:{vendor.findings.medium}</span>
                      )}
                      {vendor.findings.critical === 0 && vendor.findings.high === 0 && vendor.findings.medium === 0 && (
                        <span className="text-[#00ff88]">Clean</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <button className="text-xs text-[#00d4ff] border border-[rgba(0,212,255,0.3)] px-2 py-1 rounded hover:bg-[rgba(0,212,255,0.1)] transition-colors">
                      Scan
                    </button>
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
