'use client';
import { useState } from 'react';
import { useIntegrationStatus, useJiraConfig, useSaveJiraConfig, useJiraIssues, useSlackConfig, useSaveSlackConfig, useComplianceFrameworks, useGenerateComplianceReport } from '@/lib/hooks';
import { DashboardLayout } from '@/components/layout/DashboardLayout';

type Tab = 'jira' | 'slack' | 'compliance' | 'overview';

export default function IntegrationsPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const { data: integrationStatus = [] } = useIntegrationStatus();
  const { data: jiraConfig } = useJiraConfig();
  const { data: jiraIssues = [] } = useJiraIssues();
  const { data: slackConfig } = useSlackConfig();
  const { data: frameworks = [] } = useComplianceFrameworks();

  const saveJira = useSaveJiraConfig();
  const saveSlack = useSaveSlackConfig();
  const generateCompliance = useGenerateComplianceReport();

  const [jiraForm, setJiraForm] = useState({ base_url: '', email: '', api_token: '', project_key: '', issue_type: 'Bug' });
  const [slackForm, setSlackForm] = useState({ webhook_url: '', channel: '', severity_threshold: 'high' });
  const [selectedFramework, setSelectedFramework] = useState('pci-dss');
  const [jiraSaved, setJiraSaved] = useState(false);
  const [slackSaved, setSlackSaved] = useState(false);

  async function handleSaveJira() {
    await saveJira.mutateAsync(jiraForm);
    setJiraSaved(true);
    setTimeout(() => setJiraSaved(false), 3000);
  }

  async function handleSaveSlack() {
    await saveSlack.mutateAsync(slackForm);
    setSlackSaved(true);
    setTimeout(() => setSlackSaved(false), 3000);
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'jira', label: 'Jira' },
    { id: 'slack', label: 'Slack' },
    { id: 'compliance', label: 'Compliance Reports' },
  ];

  const INTEGRATION_ICONS: Record<string, string> = { jira: '🔵', slack: '💬', splunk: '🔴', elastic: '🟡', teams: '🟣', pagerduty: '🟢' };

  return (
    <DashboardLayout>
    <div style={{ padding: '32px', background: '#0a0a1a', minHeight: '100vh', color: '#e2e8f0' }}>
      <div style={{ maxWidth: 1100, margin: '0 auto' }}>
        <div style={{ marginBottom: 32 }}>
          <h1 style={{ fontSize: 28, fontWeight: 700, color: '#fff', margin: 0 }}>Integrations</h1>
          <p style={{ color: '#94a3b8', margin: '4px 0 0' }}>Connect Leruo with your existing security and development toolchain</p>
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid #2d2d4e', marginBottom: 32 }}>
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              style={{ background: 'none', border: 'none', borderBottom: tab === t.id ? '2px solid #6366f1' : '2px solid transparent', color: tab === t.id ? '#fff' : '#94a3b8', padding: '10px 20px', cursor: 'pointer', fontWeight: 500, fontSize: 14 }}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Overview */}
        {tab === 'overview' && (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
              {integrationStatus.map((intg: any) => (
                <div key={intg.type} style={{ background: '#1a1a2e', border: `1px solid ${intg.configured ? '#6366f133' : '#2d2d4e'}`, borderRadius: 12, padding: 20 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                    <span style={{ fontSize: 24 }}>{INTEGRATION_ICONS[intg.type] || '🔧'}</span>
                    <span style={{ background: intg.configured ? (intg.enabled ? '#16a34a22' : '#71717a22') : '#1e293b', color: intg.configured ? (intg.enabled ? '#22c55e' : '#94a3b8') : '#475569', border: `1px solid ${intg.configured ? (intg.enabled ? '#16a34a' : '#52525b') : '#334155'}`, borderRadius: 12, padding: '2px 8px', fontSize: 11 }}>
                      {intg.configured ? (intg.enabled ? 'Connected' : 'Disabled') : 'Not configured'}
                    </span>
                  </div>
                  <div style={{ color: '#fff', fontWeight: 600, fontSize: 15, textTransform: 'capitalize' }}>{intg.type}</div>
                  {intg.last_updated && <div style={{ color: '#64748b', fontSize: 12, marginTop: 4 }}>Updated: {new Date(intg.last_updated).toLocaleDateString()}</div>}
                  {!intg.configured && (
                    <button onClick={() => setTab(intg.type as Tab)}
                      style={{ marginTop: 12, width: '100%', background: 'transparent', border: '1px solid #6366f1', color: '#6366f1', borderRadius: 6, padding: '6px', cursor: 'pointer', fontSize: 13 }}>
                      Configure
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Jira */}
        {tab === 'jira' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
            <div style={{ background: '#1a1a2e', border: '1px solid #2d2d4e', borderRadius: 12, padding: 24 }}>
              <h2 style={{ color: '#fff', margin: '0 0 20px', fontSize: 18 }}>Jira Configuration</h2>
              {jiraConfig?.configured && (
                <div style={{ background: '#16a34a11', border: '1px solid #16a34a33', borderRadius: 8, padding: 12, marginBottom: 20, color: '#22c55e', fontSize: 13 }}>
                  ✓ Jira connected to {jiraConfig.base_url} (project: {jiraConfig.project_key})
                </div>
              )}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {[
                  { key: 'base_url', label: 'Jira Base URL', placeholder: 'https://yourorg.atlassian.net' },
                  { key: 'email', label: 'Account Email', placeholder: 'you@company.com' },
                  { key: 'api_token', label: 'API Token', placeholder: 'Your Jira API token', type: 'password' },
                  { key: 'project_key', label: 'Project Key', placeholder: 'SEC' },
                  { key: 'issue_type', label: 'Issue Type', placeholder: 'Bug' },
                ].map(({ key, label, placeholder, type }) => (
                  <div key={key}>
                    <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>{label}</label>
                    <input type={type || 'text'} value={(jiraForm as any)[key]} onChange={e => setJiraForm(f => ({ ...f, [key]: e.target.value }))}
                      placeholder={placeholder} style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0', boxSizing: 'border-box' }} />
                  </div>
                ))}
                <button onClick={handleSaveJira} disabled={saveJira.isPending}
                  style={{ background: jiraSaved ? '#059669' : '#6366f1', color: '#fff', border: 'none', borderRadius: 8, padding: '10px', cursor: 'pointer', fontWeight: 600 }}>
                  {saveJira.isPending ? 'Connecting...' : jiraSaved ? '✓ Connected!' : 'Save & Test Connection'}
                </button>
              </div>
            </div>

            <div style={{ background: '#1a1a2e', border: '1px solid #2d2d4e', borderRadius: 12, padding: 24 }}>
              <h2 style={{ color: '#fff', margin: '0 0 16px', fontSize: 18 }}>Linked Issues</h2>
              {jiraIssues.length === 0 ? (
                <p style={{ color: '#94a3b8', fontSize: 14 }}>No Jira issues linked yet. Go to Findings to create issues from vulnerabilities.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {jiraIssues.slice(0, 10).map((issue: any) => (
                    <div key={issue.jira_issue_key} style={{ background: '#0d0d1f', borderRadius: 8, padding: 12 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div>
                          <a href={issue.jira_issue_url} target="_blank" rel="noreferrer" style={{ color: '#6366f1', fontWeight: 600, fontSize: 13, textDecoration: 'none' }}>{issue.jira_issue_key}</a>
                          <div style={{ color: '#e2e8f0', fontSize: 13, marginTop: 2 }}>{issue.finding_title}</div>
                        </div>
                        <span style={{ fontSize: 11, color: '#94a3b8' }}>{issue.jira_status}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Slack */}
        {tab === 'slack' && (
          <div style={{ background: '#1a1a2e', border: '1px solid #2d2d4e', borderRadius: 12, padding: 24, maxWidth: 500 }}>
            <h2 style={{ color: '#fff', margin: '0 0 20px', fontSize: 18 }}>Slack Configuration</h2>
            {slackConfig?.configured && (
              <div style={{ background: '#16a34a11', border: '1px solid #16a34a33', borderRadius: 8, padding: 12, marginBottom: 20, color: '#22c55e', fontSize: 13 }}>
                ✓ Slack connected (channel: {slackConfig.channel || 'default'}, threshold: {slackConfig.severity_threshold})
              </div>
            )}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>Incoming Webhook URL</label>
                <input value={slackForm.webhook_url} onChange={e => setSlackForm(f => ({ ...f, webhook_url: e.target.value }))}
                  placeholder="https://hooks.slack.com/services/..." style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0', boxSizing: 'border-box' }} />
                <p style={{ color: '#64748b', fontSize: 12, margin: '4px 0 0' }}>Create at api.slack.com/apps → Incoming Webhooks</p>
              </div>
              <div>
                <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>Channel (optional)</label>
                <input value={slackForm.channel} onChange={e => setSlackForm(f => ({ ...f, channel: e.target.value }))}
                  placeholder="#security-alerts" style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0', boxSizing: 'border-box' }} />
              </div>
              <div>
                <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>Alert on severity</label>
                <select value={slackForm.severity_threshold} onChange={e => setSlackForm(f => ({ ...f, severity_threshold: e.target.value }))}
                  style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0' }}>
                  <option value="critical">Critical only</option>
                  <option value="high">High and above</option>
                  <option value="medium">Medium and above</option>
                </select>
              </div>
              <button onClick={handleSaveSlack} disabled={saveSlack.isPending}
                style={{ background: slackSaved ? '#059669' : '#6366f1', color: '#fff', border: 'none', borderRadius: 8, padding: '10px', cursor: 'pointer', fontWeight: 600 }}>
                {saveSlack.isPending ? 'Testing...' : slackSaved ? '✓ Connected!' : 'Save & Test Webhook'}
              </button>
            </div>
          </div>
        )}

        {/* Compliance Reports */}
        {tab === 'compliance' && (
          <div>
            <div style={{ marginBottom: 24 }}>
              <h2 style={{ color: '#fff', margin: '0 0 8px', fontSize: 20 }}>Compliance Report Generator</h2>
              <p style={{ color: '#94a3b8', margin: 0 }}>Generate audit-ready compliance gap reports mapped to regulatory frameworks</p>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 16 }}>
              {frameworks.map((fw: any) => (
                <div key={fw.id} style={{ background: '#1a1a2e', border: `1px solid ${selectedFramework === fw.id ? '#6366f1' : '#2d2d4e'}`, borderRadius: 12, padding: 20, cursor: 'pointer' }}
                  onClick={() => setSelectedFramework(fw.id)}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                      <div style={{ color: '#fff', fontWeight: 700, fontSize: 15, marginBottom: 4 }}>{fw.name}</div>
                      <div style={{ color: '#94a3b8', fontSize: 13 }}>{fw.requirement_count} controls</div>
                    </div>
                    {selectedFramework === fw.id && <span style={{ color: '#6366f1', fontSize: 18 }}>✓</span>}
                  </div>
                  <button onClick={(e) => { e.stopPropagation(); generateCompliance.mutate({ framework: fw.id, options: { framework: fw.id } }); }}
                    disabled={generateCompliance.isPending}
                    style={{ marginTop: 16, width: '100%', background: '#6366f1', color: '#fff', border: 'none', borderRadius: 8, padding: '8px', cursor: 'pointer', fontSize: 13, fontWeight: 600 }}>
                    {generateCompliance.isPending ? 'Generating...' : '⬇ Download Report'}
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
    </DashboardLayout>
  );
}
