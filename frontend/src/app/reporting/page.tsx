'use client';

import { useState } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';

interface ScheduledReport {
  id: string;
  name: string;
  type: 'executive' | 'technical' | 'compliance';
  frequency: 'daily' | 'weekly' | 'monthly';
  recipients: string;
  lastRun: string;
  nextRun: string;
  enabled: boolean;
}

interface Webhook {
  id: string;
  name: string;
  url: string;
  events: string[];
  status: 'active' | 'error' | 'disabled';
  lastDelivery: string;
}

const scheduledReports: ScheduledReport[] = [
  { id: 'sr1', name: 'Weekly Executive Summary', type: 'executive', frequency: 'weekly', recipients: 'ciso@corp.com, cto@corp.com', lastRun: '2026-03-30', nextRun: '2026-04-06', enabled: true },
  { id: 'sr2', name: 'Daily Findings Digest', type: 'technical', frequency: 'daily', recipients: 'soc-team@corp.com', lastRun: '2026-04-04', nextRun: '2026-04-05', enabled: true },
  { id: 'sr3', name: 'Monthly Compliance Report', type: 'compliance', frequency: 'monthly', recipients: 'compliance@corp.com', lastRun: '2026-03-01', nextRun: '2026-05-01', enabled: true },
  { id: 'sr4', name: 'Quarterly TPRM Summary', type: 'executive', frequency: 'monthly', recipients: 'board@corp.com', lastRun: '2026-01-01', nextRun: '2026-07-01', enabled: false },
];

const webhooks: Webhook[] = [
  { id: 'wh1', name: 'Slack #security-alerts', url: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXX', events: ['critical_finding', 'scan_complete'], status: 'active', lastDelivery: '2026-04-05 13:42' },
  { id: 'wh2', name: 'PagerDuty On-Call', url: 'https://events.pagerduty.com/integration/XXXXX/enqueue', events: ['critical_finding', 'high_finding'], status: 'active', lastDelivery: '2026-04-05 02:11' },
  { id: 'wh3', name: 'Jira Ticketing', url: 'https://jira.corp.com/webhook/receive/abc123', events: ['new_finding', 'scan_complete'], status: 'error', lastDelivery: '2026-04-03 09:00' },
  { id: 'wh4', name: 'SIEM Syslog Forwarder', url: 'http://siem.corp.com:9200/api/events', events: ['all'], status: 'active', lastDelivery: '2026-04-05 14:30' },
];

const reportTypeColors = {
  executive: 'text-[#00d4ff] bg-[rgba(0,212,255,0.1)] border-[rgba(0,212,255,0.3)]',
  technical: 'text-[#00ff88] bg-[rgba(0,255,136,0.1)] border-[rgba(0,255,136,0.3)]',
  compliance: 'text-[#ffcc00] bg-[rgba(255,204,0,0.1)] border-[rgba(255,204,0,0.3)]',
};

const webhookStatusColors = {
  active: 'text-[#00ff88] bg-[rgba(0,255,136,0.1)] border-[rgba(0,255,136,0.3)]',
  error: 'text-[#ff3b3b] bg-[rgba(255,59,59,0.1)] border-[rgba(255,59,59,0.3)]',
  disabled: 'text-[#8892a4] bg-[rgba(136,146,164,0.1)] border-[rgba(136,146,164,0.3)]',
};

export default function ReportingPage() {
  const [generating, setGenerating] = useState<string | null>(null);
  const [schedules, setSchedules] = useState(scheduledReports);

  const handleGenerate = (type: string) => {
    setGenerating(type);
    setTimeout(() => setGenerating(null), 2500);
  };

  const toggleSchedule = (id: string) => {
    setSchedules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r))
    );
  };

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6 min-h-full">
        <div>
          <h1 className="text-xl font-bold text-[#e8eaf0]">Reporting & Exports</h1>
          <p className="text-[#8892a4] text-sm mt-0.5">Generate PDF reports, configure scheduled delivery and webhook integrations</p>
        </div>

        {/* Report generation buttons */}
        <div className="grid grid-cols-2 gap-4">
          {/* Executive Report */}
          <div className="bg-[#111318] border border-[#1e2028] rounded-lg p-6">
            <div className="flex items-center gap-4 mb-4">
              <div className="w-12 h-12 rounded-lg bg-[rgba(0,212,255,0.1)] flex items-center justify-center">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#00d4ff" strokeWidth="1.5">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                  <polyline points="14 2 14 8 20 8" />
                  <line x1="16" y1="13" x2="8" y2="13" />
                  <line x1="16" y1="17" x2="8" y2="17" />
                </svg>
              </div>
              <div>
                <h3 className="text-sm font-bold text-[#e8eaf0]">Executive Summary PDF</h3>
                <p className="text-xs text-[#8892a4]">High-level risk posture for CISO/Board. No technical jargon.</p>
              </div>
            </div>
            <div className="text-xs text-[#8892a4] mb-4 space-y-1">
              <div className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-[#00d4ff]" />
                <span>Organization risk score & trend</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-[#00d4ff]" />
                <span>Critical & high finding summary</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-[#00d4ff]" />
                <span>Remediation progress metrics</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-[#00d4ff]" />
                <span>Top 5 recommended actions</span>
              </div>
            </div>
            <button
              onClick={() => handleGenerate('executive')}
              disabled={generating !== null}
              className="cyber-btn text-sm w-full flex items-center justify-center gap-2"
            >
              {generating === 'executive' ? (
                <>
                  <svg className="animate-spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                  </svg>
                  Generating...
                </>
              ) : (
                <>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="7 10 12 15 17 10" />
                    <line x1="12" y1="15" x2="12" y2="3" />
                  </svg>
                  Download Executive PDF
                </>
              )}
            </button>
          </div>

          {/* Technical Report */}
          <div className="bg-[#111318] border border-[#1e2028] rounded-lg p-6">
            <div className="flex items-center gap-4 mb-4">
              <div className="w-12 h-12 rounded-lg bg-[rgba(0,255,136,0.1)] flex items-center justify-center">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#00ff88" strokeWidth="1.5">
                  <polyline points="4 17 10 11 4 5" />
                  <line x1="12" y1="19" x2="20" y2="19" />
                </svg>
              </div>
              <div>
                <h3 className="text-sm font-bold text-[#e8eaf0]">Technical Report PDF</h3>
                <p className="text-xs text-[#8892a4]">Full findings with CVE details, CVSS scores and remediation steps.</p>
              </div>
            </div>
            <div className="text-xs text-[#8892a4] mb-4 space-y-1">
              <div className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-[#00ff88]" />
                <span>All findings with CVE/CVSS data</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-[#00ff88]" />
                <span>Asset inventory & exposure map</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-[#00ff88]" />
                <span>Scan output appendices</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-[#00ff88]" />
                <span>Step-by-step remediation guides</span>
              </div>
            </div>
            <button
              onClick={() => handleGenerate('technical')}
              disabled={generating !== null}
              className="w-full py-2 px-4 text-sm font-semibold rounded-md border border-[rgba(0,255,136,0.4)] text-[#00ff88] bg-[rgba(0,255,136,0.1)] hover:bg-[rgba(0,255,136,0.15)] transition-colors flex items-center justify-center gap-2"
            >
              {generating === 'technical' ? (
                <>
                  <svg className="animate-spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                  </svg>
                  Generating...
                </>
              ) : (
                <>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="7 10 12 15 17 10" />
                    <line x1="12" y1="15" x2="12" y2="3" />
                  </svg>
                  Download Technical PDF
                </>
              )}
            </button>
          </div>
        </div>

        {/* Scheduled Reports */}
        <div className="bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2028]">
            <h2 className="text-sm font-semibold text-[#e8eaf0]">Scheduled Reports</h2>
            <button className="cyber-btn text-xs py-1.5 px-3">+ New Schedule</button>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2028]">
                {['Name', 'Type', 'Frequency', 'Recipients', 'Last Run', 'Next Run', 'Enabled'].map((h) => (
                  <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {schedules.map((report) => (
                <tr key={report.id} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                  <td className="px-4 py-3 text-xs font-medium text-[#e8eaf0]">{report.name}</td>
                  <td className="px-4 py-3">
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border uppercase ${reportTypeColors[report.type]}`}>
                      {report.type}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-[#8892a4] capitalize">{report.frequency}</td>
                  <td className="px-4 py-3 text-xs text-[#8892a4] max-w-[200px] truncate">{report.recipients}</td>
                  <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">{report.lastRun}</td>
                  <td className="px-4 py-3 font-mono text-xs text-[#4fc3f7]">{report.nextRun}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => toggleSchedule(report.id)}
                      className={`relative w-10 h-5 rounded-full transition-colors ${report.enabled ? 'bg-[#00d4ff]' : 'bg-[#1e2028]'}`}
                    >
                      <span
                        className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${report.enabled ? 'left-5.5 translate-x-1' : 'left-0.5'}`}
                      />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Webhooks */}
        <div className="bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2028]">
            <div>
              <h2 className="text-sm font-semibold text-[#e8eaf0]">Webhook Integrations</h2>
              <p className="text-xs text-[#8892a4] mt-0.5">Push events to Slack, PagerDuty, Jira and SIEM systems</p>
            </div>
            <button className="cyber-btn text-xs py-1.5 px-3">+ Add Webhook</button>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2028]">
                {['Name', 'URL', 'Events', 'Status', 'Last Delivery', ''].map((h) => (
                  <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {webhooks.map((wh) => (
                <tr key={wh.id} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                  <td className="px-4 py-3 text-xs font-medium text-[#e8eaf0]">{wh.name}</td>
                  <td className="px-4 py-3 font-mono text-xs text-[#8892a4] max-w-[200px] truncate">{wh.url}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {wh.events.map((ev) => (
                        <span key={ev} className="text-[9px] px-1.5 py-0.5 rounded bg-[#1e2028] text-[#8892a4]">{ev}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border uppercase ${webhookStatusColors[wh.status]}`}>
                      {wh.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">{wh.lastDelivery}</td>
                  <td className="px-4 py-3 flex gap-2">
                    <button className="text-xs text-[#00d4ff] hover:underline">Test</button>
                    <button className="text-xs text-[#8892a4] hover:text-[#ff3b3b] transition-colors">Delete</button>
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
