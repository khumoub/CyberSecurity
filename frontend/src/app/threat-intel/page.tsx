'use client';

import { useState, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { useCveLookup, useExploitSearch, useCisaKev, useVprScores } from '@/lib/hooks';

// ── Severity badge ────────────────────────────────────────────────────────────
function SevBadge({ score }: { score?: number | null }) {
  if (score == null) return <span className="text-[#8892a4] text-xs">N/A</span>;
  const color =
    score >= 9 ? 'bg-[rgba(255,59,59,0.2)] text-[#ff3b3b] border-[rgba(255,59,59,0.4)]' :
    score >= 7 ? 'bg-[rgba(255,165,0,0.2)] text-[#ffa500] border-[rgba(255,165,0,0.4)]' :
    score >= 4 ? 'bg-[rgba(255,214,0,0.2)] text-[#ffd600] border-[rgba(255,214,0,0.4)]' :
                 'bg-[rgba(0,212,255,0.1)] text-[#00d4ff] border-[rgba(0,212,255,0.3)]';
  return (
    <span className={`inline-block px-2 py-0.5 rounded border text-xs font-bold ${color}`}>
      {score.toFixed(1)}
    </span>
  );
}

// ── CVE Lookup Panel ──────────────────────────────────────────────────────────
function CveLookupPanel({ initialCve }: { initialCve?: string }) {
  const [query, setQuery] = useState(initialCve ?? '');
  const [submitted, setSubmitted] = useState(initialCve ?? '');

  const { data, isLoading, isError } = useCveLookup(submitted);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const val = query.trim().toUpperCase();
    if (val.startsWith('CVE-')) setSubmitted(val);
  };

  const cve = data?.cve;

  return (
    <div className="bg-[#0d0f14] border border-[#1e2028] rounded-lg p-5">
      <h2 className="text-sm font-bold text-[#e8eaf0] mb-4 uppercase tracking-wider">CVE Lookup</h2>
      <form onSubmit={handleSubmit} className="flex gap-2 mb-5">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="CVE-2024-12345"
          className="flex-1 bg-[#161b27] border border-[#2a2d3a] rounded px-3 py-2 text-sm text-[#e8eaf0] placeholder-[#8892a4] focus:outline-none focus:border-[#00d4ff]"
        />
        <button
          type="submit"
          className="px-4 py-2 bg-[#00d4ff] hover:bg-[#00b8d9] text-[#0a0b0d] text-sm font-bold rounded transition-colors"
        >
          Lookup
        </button>
      </form>

      {isLoading && (
        <div className="flex items-center gap-2 text-[#8892a4] text-sm py-4">
          <div className="w-4 h-4 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
          Fetching CVE data...
        </div>
      )}
      {isError && (
        <div className="text-[#ff3b3b] text-sm py-4">CVE not found or service unavailable.</div>
      )}
      {cve && (
        <div className="space-y-4">
          <div className="flex items-start gap-3">
            <div>
              <div className="text-base font-bold text-[#00d4ff]">{cve.id}</div>
              <div className="text-xs text-[#8892a4] mt-0.5">{cve.published}</div>
            </div>
            <div className="ml-auto flex gap-2">
              {cve.metrics?.cvssMetricV31?.[0]?.cvssData && (
                <SevBadge score={cve.metrics.cvssMetricV31[0].cvssData.baseScore} />
              )}
              {cve.metrics?.cvssMetricV2?.[0]?.cvssData && (
                <SevBadge score={cve.metrics.cvssMetricV2[0].cvssData.baseScore} />
              )}
            </div>
          </div>
          <p className="text-sm text-[#b0b8c8] leading-relaxed">
            {cve.descriptions?.find((d: { lang: string }) => d.lang === 'en')?.value ?? 'No description available.'}
          </p>
          {cve.weaknesses && cve.weaknesses.length > 0 && (
            <div>
              <div className="text-xs font-bold text-[#8892a4] uppercase mb-1">Weaknesses (CWE)</div>
              <div className="flex flex-wrap gap-2">
                {cve.weaknesses.flatMap((w: { description: { value: string }[] }) =>
                  w.description.map((d: { value: string }) => (
                    <span key={d.value} className="text-xs px-2 py-0.5 bg-[#1a1f2e] border border-[#2a2d3a] rounded text-[#8892a4]">
                      {d.value}
                    </span>
                  ))
                )}
              </div>
            </div>
          )}
          {cve.references && cve.references.length > 0 && (
            <div>
              <div className="text-xs font-bold text-[#8892a4] uppercase mb-1">References</div>
              <ul className="space-y-1">
                {cve.references.slice(0, 5).map((ref: { url: string }, i: number) => (
                  <li key={i} className="text-xs text-[#00d4ff] truncate">
                    {ref.url}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
      {!isLoading && !isError && !cve && submitted && (
        <div className="text-[#8892a4] text-sm py-4">No data found for {submitted}.</div>
      )}
    </div>
  );
}

// ── Exploit Search Panel ──────────────────────────────────────────────────────
function ExploitSearchPanel() {
  const [query, setQuery] = useState('');
  const [submitted, setSubmitted] = useState('');

  const { data, isLoading } = useExploitSearch(submitted);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (query.trim().length > 2) setSubmitted(query.trim());
  };

  const results: { id?: number | string; title?: string; cve?: string; author?: string; date?: string; type?: string }[] = data?.results ?? [];

  return (
    <div className="bg-[#0d0f14] border border-[#1e2028] rounded-lg p-5">
      <h2 className="text-sm font-bold text-[#e8eaf0] mb-4 uppercase tracking-wider">Exploit Search</h2>
      <form onSubmit={handleSubmit} className="flex gap-2 mb-5">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Apache struts RCE..."
          className="flex-1 bg-[#161b27] border border-[#2a2d3a] rounded px-3 py-2 text-sm text-[#e8eaf0] placeholder-[#8892a4] focus:outline-none focus:border-[#00d4ff]"
        />
        <button
          type="submit"
          className="px-4 py-2 bg-[#00d4ff] hover:bg-[#00b8d9] text-[#0a0b0d] text-sm font-bold rounded transition-colors"
        >
          Search
        </button>
      </form>

      {isLoading && (
        <div className="flex items-center gap-2 text-[#8892a4] text-sm py-4">
          <div className="w-4 h-4 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
          Searching exploit database...
        </div>
      )}
      {results.length > 0 && (
        <div className="space-y-2 max-h-80 overflow-y-auto">
          {results.map((r, i) => (
            <div key={i} className="bg-[#161b27] border border-[#1e2028] rounded p-3">
              <div className="flex items-start justify-between gap-2">
                <div className="text-sm font-medium text-[#e8eaf0]">{r.title ?? 'Unknown'}</div>
                {r.cve && (
                  <span className="text-xs text-[#00d4ff] whitespace-nowrap">{r.cve}</span>
                )}
              </div>
              <div className="flex gap-3 mt-1 text-xs text-[#8892a4]">
                {r.id && <span>EDB-{r.id}</span>}
                {r.author && <span>{r.author}</span>}
                {r.date && <span>{r.date}</span>}
                {r.type && (
                  <span className="px-1.5 py-0.5 bg-[#1a1f2e] border border-[#2a2d3a] rounded uppercase tracking-wider">
                    {r.type}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      {!isLoading && submitted && results.length === 0 && (
        <div className="text-[#8892a4] text-sm py-4">No exploits found for "{submitted}".</div>
      )}
    </div>
  );
}

// ── CISA KEV Panel ────────────────────────────────────────────────────────────
function CisaKevPanel() {
  const [page, setPage] = useState(1);
  const { data, isLoading } = useCisaKev(page);

  const entries: { cveID?: string; vendorProject?: string; product?: string; vulnerabilityName?: string; dateAdded?: string; shortDescription?: string; requiredAction?: string; dueDate?: string }[] = data?.vulnerabilities ?? [];
  const total: number = data?.total ?? 0;
  const pageSize = 20;
  const totalPages = Math.ceil(total / pageSize);

  return (
    <div className="bg-[#0d0f14] border border-[#1e2028] rounded-lg p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-sm font-bold text-[#e8eaf0] uppercase tracking-wider">CISA KEV Catalog</h2>
          <p className="text-xs text-[#8892a4] mt-0.5">Known Exploited Vulnerabilities requiring remediation</p>
        </div>
        {total > 0 && (
          <span className="text-xs text-[#8892a4]">{total.toLocaleString()} entries</span>
        )}
      </div>

      {isLoading && (
        <div className="flex items-center gap-2 text-[#8892a4] text-sm py-4">
          <div className="w-4 h-4 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
          Loading KEV catalog...
        </div>
      )}

      {!isLoading && entries.length > 0 && (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#1e2028]">
                  <th className="text-left py-2 pr-3 font-semibold text-[#8892a4] uppercase tracking-wider">CVE ID</th>
                  <th className="text-left py-2 pr-3 font-semibold text-[#8892a4] uppercase tracking-wider">Vendor / Product</th>
                  <th className="text-left py-2 pr-3 font-semibold text-[#8892a4] uppercase tracking-wider">Vulnerability</th>
                  <th className="text-left py-2 pr-3 font-semibold text-[#8892a4] uppercase tracking-wider">Date Added</th>
                  <th className="text-left py-2 font-semibold text-[#8892a4] uppercase tracking-wider">Due Date</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e, i) => (
                  <tr key={i} className="border-b border-[#161b27] hover:bg-[#161b27] transition-colors">
                    <td className="py-2.5 pr-3 font-mono text-[#00d4ff]">{e.cveID ?? '—'}</td>
                    <td className="py-2.5 pr-3 text-[#b0b8c8]">
                      {e.vendorProject}
                      {e.product && <span className="text-[#8892a4]"> / {e.product}</span>}
                    </td>
                    <td className="py-2.5 pr-3 text-[#e8eaf0] max-w-xs truncate">{e.vulnerabilityName}</td>
                    <td className="py-2.5 pr-3 text-[#8892a4] whitespace-nowrap">{e.dateAdded}</td>
                    <td className="py-2.5 text-[#ffd600] whitespace-nowrap">{e.dueDate}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-3 pt-3 border-t border-[#1e2028]">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="text-xs px-3 py-1 bg-[#161b27] border border-[#2a2d3a] rounded text-[#8892a4] hover:text-[#e8eaf0] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                Previous
              </button>
              <span className="text-xs text-[#8892a4]">
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="text-xs px-3 py-1 bg-[#161b27] border border-[#2a2d3a] rounded text-[#8892a4] hover:text-[#e8eaf0] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── VPR Scores Panel ──────────────────────────────────────────────────────────
function VprPanel() {
  const { data, isLoading } = useVprScores(50);

  const items: { cve_id?: string; vpr_score?: number; cvss_score?: number; title?: string; asset_count?: number }[] = data?.items ?? [];

  return (
    <div className="bg-[#0d0f14] border border-[#1e2028] rounded-lg p-5">
      <div className="mb-4">
        <h2 className="text-sm font-bold text-[#e8eaf0] uppercase tracking-wider">Vulnerability Priority Rating</h2>
        <p className="text-xs text-[#8892a4] mt-0.5">Top vulnerabilities by VPR score (contextual risk)</p>
      </div>

      {isLoading && (
        <div className="flex items-center gap-2 text-[#8892a4] text-sm py-4">
          <div className="w-4 h-4 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
          Calculating VPR scores...
        </div>
      )}

      {!isLoading && items.length === 0 && (
        <div className="text-[#8892a4] text-sm py-4">No VPR data available. Run vulnerability scans to generate scores.</div>
      )}

      {!isLoading && items.length > 0 && (
        <div className="space-y-2 max-h-80 overflow-y-auto">
          {items.map((item, i) => (
            <div key={i} className="flex items-center gap-3 bg-[#161b27] border border-[#1e2028] rounded p-3">
              <div className="text-xs text-[#8892a4] w-5 shrink-0">{i + 1}</div>
              <div className="flex-1 min-w-0">
                <div className="text-sm text-[#e8eaf0] truncate">{item.title ?? item.cve_id ?? '—'}</div>
                {item.cve_id && (
                  <div className="text-xs text-[#00d4ff] mt-0.5">{item.cve_id}</div>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {item.asset_count != null && (
                  <span className="text-xs text-[#8892a4]">{item.asset_count} assets</span>
                )}
                {item.cvss_score != null && (
                  <span className="text-xs text-[#8892a4]">CVSS: {item.cvss_score}</span>
                )}
                <SevBadge score={item.vpr_score} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function ThreatIntelPage() {
  const searchParams = useSearchParams();
  const initialCve = searchParams.get('cve') ?? '';

  const [activeTab, setActiveTab] = useState<'cve' | 'exploits' | 'kev' | 'vpr'>(
    initialCve ? 'cve' : 'kev'
  );

  useEffect(() => {
    if (initialCve) setActiveTab('cve');
  }, [initialCve]);

  const tabs = [
    { id: 'kev', label: 'CISA KEV' },
    { id: 'cve', label: 'CVE Lookup' },
    { id: 'exploits', label: 'Exploit Search' },
    { id: 'vpr', label: 'VPR Scores' },
  ] as const;

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-xl font-bold text-[#e8eaf0] tracking-wide">Threat Intelligence</h1>
          <p className="text-sm text-[#8892a4] mt-1">
            CVE database, CISA KEV catalog, exploit search, and vulnerability priority ratings
          </p>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 bg-[#0d0f14] border border-[#1e2028] rounded-lg p-1 w-fit">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
                activeTab === tab.id
                  ? 'bg-[#1a1f2e] text-[#00d4ff]'
                  : 'text-[#8892a4] hover:text-[#e8eaf0]'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Panel */}
        <div>
          {activeTab === 'kev' && <CisaKevPanel />}
          {activeTab === 'cve' && <CveLookupPanel initialCve={initialCve} />}
          {activeTab === 'exploits' && <ExploitSearchPanel />}
          {activeTab === 'vpr' && <VprPanel />}
        </div>
      </div>
    </DashboardLayout>
  );
}
