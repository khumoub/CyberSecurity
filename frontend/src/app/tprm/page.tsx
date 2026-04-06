'use client';

import { useState } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { useVendors, useCreateVendor, useGenerateQuestionnaire } from '@/lib/hooks';

type RiskTier = 'critical' | 'high' | 'medium' | 'low';

const tierColors: Record<RiskTier, { badge: string; bar: string }> = {
  critical: { badge: 'text-[#ff3b3b] bg-[rgba(255,59,59,0.1)] border-[rgba(255,59,59,0.3)]', bar: '#ff3b3b' },
  high: { badge: 'text-[#ff6b35] bg-[rgba(255,107,53,0.1)] border-[rgba(255,107,53,0.3)]', bar: '#ff6b35' },
  medium: { badge: 'text-[#ffcc00] bg-[rgba(255,204,0,0.1)] border-[rgba(255,204,0,0.3)]', bar: '#ffcc00' },
  low: { badge: 'text-[#4fc3f7] bg-[rgba(79,195,247,0.1)] border-[rgba(79,195,247,0.3)]', bar: '#4fc3f7' },
};

const assessmentColors: Record<string, string> = {
  assessed: 'text-[#00ff88] bg-[rgba(0,255,136,0.1)] border-[rgba(0,255,136,0.3)]',
  pending: 'text-[#ffcc00] bg-[rgba(255,204,0,0.1)] border-[rgba(255,204,0,0.3)]',
  overdue: 'text-[#ff3b3b] bg-[rgba(255,59,59,0.1)] border-[rgba(255,59,59,0.3)]',
  never: 'text-[#8892a4] bg-[rgba(136,146,164,0.1)] border-[rgba(136,146,164,0.3)]',
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

interface AddVendorModalProps {
  onClose: () => void;
  onSave: (data: { name: string; domain: string; contact_email: string; risk_tier: string }) => void;
}

function AddVendorModal({ onClose, onSave }: AddVendorModalProps) {
  const [form, setForm] = useState({ name: '', domain: '', contact_email: '', risk_tier: 'medium' });
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
      <div className="bg-[#111318] border border-[#1e2028] rounded-xl p-6 w-full max-w-md">
        <h2 className="text-lg font-bold text-[#e8eaf0] mb-4">Add Vendor</h2>
        <div className="space-y-3">
          {[
            { label: 'Vendor Name', key: 'name', placeholder: 'e.g. Salesforce' },
            { label: 'Domain', key: 'domain', placeholder: 'e.g. salesforce.com' },
            { label: 'Contact Email', key: 'contact_email', placeholder: 'security@vendor.com' },
          ].map(({ label, key, placeholder }) => (
            <div key={key}>
              <label className="block text-xs text-[#8892a4] mb-1">{label}</label>
              <input
                type="text"
                placeholder={placeholder}
                value={(form as any)[key]}
                onChange={(e) => setForm((f) => ({ ...f, [key]: e.target.value }))}
                className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-3 py-2 text-sm text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff]"
              />
            </div>
          ))}
          <div>
            <label className="block text-xs text-[#8892a4] mb-1">Risk Tier</label>
            <select
              value={form.risk_tier}
              onChange={(e) => setForm((f) => ({ ...f, risk_tier: e.target.value }))}
              className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-3 py-2 text-sm text-[#e8eaf0] focus:outline-none focus:border-[#00d4ff]"
            >
              {['critical', 'high', 'medium', 'low'].map((t) => (
                <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="flex gap-3 mt-5">
          <button onClick={onClose} className="flex-1 border border-[#1e2028] text-[#8892a4] rounded-lg py-2 text-sm hover:border-[#2a2d3a] transition-colors">
            Cancel
          </button>
          <button
            onClick={() => { onSave(form); onClose(); }}
            disabled={!form.name}
            className="flex-1 cyber-btn text-sm py-2"
          >
            Add Vendor
          </button>
        </div>
      </div>
    </div>
  );
}

interface QuestionnaireModalProps {
  vendor: any;
  questions: any[];
  onClose: () => void;
}

function QuestionnaireModal({ vendor, questions, onClose }: QuestionnaireModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 overflow-y-auto py-8">
      <div className="bg-[#111318] border border-[#1e2028] rounded-xl p-6 w-full max-w-2xl mx-4">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-bold text-[#e8eaf0]">AI Security Questionnaire</h2>
            <p className="text-xs text-[#8892a4] mt-0.5">Generated for {vendor.name}</p>
          </div>
          <button onClick={onClose} className="text-[#8892a4] hover:text-[#e8eaf0] text-xl">×</button>
        </div>
        <div className="space-y-4 max-h-[60vh] overflow-y-auto pr-2">
          {questions.map((q: any, i: number) => (
            <div key={i} className="bg-[#0d0f14] border border-[#1e2028] rounded-lg p-4">
              <div className="flex items-start gap-3">
                <span className="text-[#00d4ff] font-bold text-sm shrink-0">{i + 1}.</span>
                <div className="space-y-2">
                  <p className="text-sm text-[#e8eaf0]">{q.question}</p>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-[rgba(0,212,255,0.1)] border border-[rgba(0,212,255,0.3)] text-[#00d4ff]">
                      {q.category}
                    </span>
                  </div>
                  {q.rationale && (
                    <p className="text-xs text-[#8892a4]"><span className="text-[#ffcc00]">Why:</span> {q.rationale}</p>
                  )}
                  {q.expected_answer && (
                    <p className="text-xs text-[#8892a4]"><span className="text-[#00ff88]">Expected:</span> {q.expected_answer}</p>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
        <button onClick={onClose} className="mt-4 w-full border border-[#1e2028] text-[#8892a4] rounded-lg py-2 text-sm hover:border-[#2a2d3a] transition-colors">
          Close
        </button>
      </div>
    </div>
  );
}

export default function TPRMPage() {
  const [search, setSearch] = useState('');
  const [tierFilter, setTierFilter] = useState<'all' | RiskTier>('all');
  const [showAddModal, setShowAddModal] = useState(false);
  const [questionnaire, setQuestionnaire] = useState<{ vendor: any; questions: any[] } | null>(null);
  const [generating, setGenerating] = useState<string | null>(null);

  const { data, isLoading } = useVendors();
  const createVendor = useCreateVendor();
  const generateQ = useGenerateQuestionnaire();

  const vendors: any[] = data?.vendors ?? data ?? [];

  const filtered = vendors.filter((v: any) => {
    if (tierFilter !== 'all' && v.risk_tier !== tierFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      if (!v.name?.toLowerCase().includes(q) && !v.domain?.toLowerCase().includes(q)) return false;
    }
    return true;
  });

  const criticalCount = vendors.filter((v: any) => v.risk_tier === 'critical').length;
  const overdueCount = vendors.filter((v: any) => v.assessment_status === 'overdue').length;
  const highRisk = vendors.filter((v: any) => (v.technical_risk_score ?? 0) >= 4).length;

  const handleGenerateQuestionnaire = async (vendor: any) => {
    setGenerating(vendor.id);
    try {
      const result = await generateQ.mutateAsync(vendor.id);
      setQuestionnaire({ vendor, questions: result.questions ?? [] });
    } catch (err) {
      console.error('Failed to generate questionnaire', err);
    } finally {
      setGenerating(null);
    }
  };

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6 min-h-full">
        <div>
          <h1 className="text-xl font-bold text-[#e8eaf0]">Third Party Risk Management</h1>
          <p className="text-[#8892a4] text-sm mt-0.5">Vendor inventory, tech risk scoring and assessment tracking</p>
        </div>

        {/* Summary stats */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: 'Total Vendors', value: isLoading ? '—' : vendors.length, color: '#00d4ff' },
            { label: 'Critical Tier', value: isLoading ? '—' : criticalCount, color: '#ff3b3b' },
            { label: 'Overdue Assessments', value: isLoading ? '—' : overdueCount, color: '#ffcc00' },
            { label: 'High Tech Risk (≥4.0)', value: isLoading ? '—' : highRisk, color: '#ff6b35' },
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
          <button onClick={() => setShowAddModal(true)} className="cyber-btn text-sm ml-auto">+ Add Vendor</button>
        </div>

        {/* Vendor table */}
        <div className="bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2028]">
                {['Vendor', 'Domain', 'Risk Tier', 'Tech Risk Score', 'Last Assessed', 'Status', 'Critical', 'High', ''].map((h) => (
                  <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading
                ? Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} cols={9} />)
                : filtered.length === 0
                ? (
                  <tr>
                    <td colSpan={9} className="px-4 py-8 text-center text-[#8892a4]">
                      No vendors yet. Add your first vendor above.
                    </td>
                  </tr>
                )
                : filtered.map((vendor: any) => {
                  const tier = (vendor.risk_tier ?? 'medium') as RiskTier;
                  const tc = tierColors[tier] ?? tierColors.medium;
                  const score = vendor.technical_risk_score ?? 0;
                  const status = vendor.assessment_status ?? 'pending';
                  return (
                    <tr key={vendor.id} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                      <td className="px-4 py-3">
                        <div className="text-sm font-semibold text-[#e8eaf0]">{vendor.name}</div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-[#4fc3f7]">{vendor.domain ?? '—'}</td>
                      <td className="px-4 py-3">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wide ${tc.badge}`}>
                          {tier}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span
                            className="text-sm font-bold"
                            style={{ color: score >= 4 ? '#ff3b3b' : score >= 3 ? '#ff6b35' : '#00ff88' }}
                          >
                            {score > 0 ? score.toFixed(1) : '—'}
                          </span>
                          {score > 0 && (
                            <div className="w-12 h-1.5 bg-[#1e2028] rounded-full overflow-hidden">
                              <div
                                className="h-full rounded-full"
                                style={{ width: `${(score / 10) * 100}%`, background: tc.bar }}
                              />
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">
                        {vendor.last_assessed_at
                          ? new Date(vendor.last_assessed_at).toLocaleDateString()
                          : '—'}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border uppercase tracking-wide ${assessmentColors[status] ?? assessmentColors.pending}`}>
                          {status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs font-bold text-[#ff3b3b]">
                        {vendor.critical_findings > 0 ? vendor.critical_findings : '—'}
                      </td>
                      <td className="px-4 py-3 text-xs font-bold text-[#ff6b35]">
                        {vendor.high_findings > 0 ? vendor.high_findings : '—'}
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => handleGenerateQuestionnaire(vendor)}
                          disabled={generating === vendor.id}
                          className="text-xs text-[#00d4ff] border border-[rgba(0,212,255,0.3)] px-2 py-1 rounded hover:bg-[rgba(0,212,255,0.1)] transition-colors disabled:opacity-50"
                        >
                          {generating === vendor.id ? 'Generating...' : 'Questionnaire'}
                        </button>
                      </td>
                    </tr>
                  );
                })
              }
            </tbody>
          </table>
        </div>
      </div>

      {showAddModal && (
        <AddVendorModal
          onClose={() => setShowAddModal(false)}
          onSave={(data) => createVendor.mutate(data)}
        />
      )}

      {questionnaire && (
        <QuestionnaireModal
          vendor={questionnaire.vendor}
          questions={questionnaire.questions}
          onClose={() => setQuestionnaire(null)}
        />
      )}
    </DashboardLayout>
  );
}
