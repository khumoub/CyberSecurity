'use client';
import { useState } from 'react';
import { useScanPolicies, useCreateScanPolicy, useUpdateScanPolicy, useDeleteScanPolicy, useRunScanPolicyNow, useScanPolicyPresets } from '@/lib/hooks';
import { TerminalOutput } from '@/components/ui/TerminalOutput';
import { DashboardLayout } from '@/components/layout/DashboardLayout';

const TOOL_OPTIONS = [
  'nmap', 'nuclei', 'nikto', 'masscan', 'sslscan', 'whatweb',
  'headers', 'gobuster', 'wfuzz', 'wpscan', 'subdomain-enum',
  'dns-analysis', 'credentialed-scan',
];

export default function ScanPoliciesPage() {
  const { data: policies = [], isLoading } = useScanPolicies();
  const { data: presets } = useScanPolicyPresets();
  const createPolicy = useCreateScanPolicy();
  const updatePolicy = useUpdateScanPolicy();
  const deletePolicy = useDeleteScanPolicy();
  const runNow = useRunScanPolicyNow();

  const [showCreate, setShowCreate] = useState(false);
  const [runResult, setRunResult] = useState<{ scan_ids: string[]; policy_id: string } | null>(null);
  const [form, setForm] = useState({
    name: '',
    description: '',
    cron_expression: 'daily',
    tools: [] as string[],
    scan_all_assets: true,
    enabled: true,
    notify_email: '',
  });

  function toggleTool(tool: string) {
    setForm(f => ({
      ...f,
      tools: f.tools.includes(tool) ? f.tools.filter(t => t !== tool) : [...f.tools, tool],
    }));
  }

  async function handleCreate() {
    if (!form.name || form.tools.length === 0) return;
    await createPolicy.mutateAsync({
      ...form,
      notify_email: form.notify_email || undefined,
    });
    setShowCreate(false);
    setForm({ name: '', description: '', cron_expression: 'daily', tools: [], scan_all_assets: true, enabled: true, notify_email: '' });
  }

  async function handleRunNow(policyId: string) {
    const result = await runNow.mutateAsync(policyId);
    setRunResult({ scan_ids: result.scan_ids, policy_id: policyId });
  }

  const cronPresets = presets?.cron_presets || {
    hourly: '0 * * * *', daily: '0 2 * * *', weekly: '0 2 * * 1', monthly: '0 2 1 * *',
  };

  return (
    <DashboardLayout>
    <div style={{ padding: '32px', background: '#0a0a1a', minHeight: '100vh', color: '#e2e8f0' }}>
      <div style={{ maxWidth: 1100, margin: '0 auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 32 }}>
          <div>
            <h1 style={{ fontSize: 28, fontWeight: 700, color: '#fff', margin: 0 }}>Scan Policies</h1>
            <p style={{ color: '#94a3b8', margin: '4px 0 0' }}>Schedule automated recurring scans across your asset inventory</p>
          </div>
          <button onClick={() => setShowCreate(true)} style={{ background: '#6366f1', color: '#fff', border: 'none', borderRadius: 8, padding: '10px 20px', cursor: 'pointer', fontWeight: 600 }}>
            + New Policy
          </button>
        </div>

        {/* Create Modal */}
        {showCreate && (
          <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ background: '#1a1a2e', border: '1px solid #2d2d4e', borderRadius: 12, padding: 32, width: 600, maxHeight: '85vh', overflowY: 'auto' }}>
              <h2 style={{ color: '#fff', margin: '0 0 24px', fontSize: 20 }}>Create Scan Policy</h2>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                <div>
                  <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>Policy Name *</label>
                  <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                    placeholder="e.g. Daily Production Scan" style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0', boxSizing: 'border-box' }} />
                </div>
                <div>
                  <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>Description</label>
                  <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                    placeholder="Optional description" style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0', boxSizing: 'border-box' }} />
                </div>
                <div>
                  <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>Schedule</label>
                  <select value={form.cron_expression} onChange={e => setForm(f => ({ ...f, cron_expression: e.target.value }))}
                    style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0' }}>
                    {Object.entries(cronPresets).map(([key, val]) => (
                      <option key={key} value={key}>{key.charAt(0).toUpperCase() + key.slice(1).replace('_', ' ')} ({val as string})</option>
                    ))}
                    <option value="0 */6 * * *">Every 6 hours (0 */6 * * *)</option>
                    <option value="0 2 * * 1,4">Twice weekly (Mon + Thu)</option>
                  </select>
                </div>
                <div>
                  <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 8 }}>Tools to Run *</label>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    {TOOL_OPTIONS.map(tool => (
                      <button key={tool} onClick={() => toggleTool(tool)}
                        style={{ padding: '4px 12px', borderRadius: 20, border: '1px solid', fontSize: 12, cursor: 'pointer',
                          background: form.tools.includes(tool) ? '#6366f1' : 'transparent',
                          borderColor: form.tools.includes(tool) ? '#6366f1' : '#2d2d4e',
                          color: form.tools.includes(tool) ? '#fff' : '#94a3b8' }}>
                        {tool}
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>Notification Email</label>
                  <input value={form.notify_email} onChange={e => setForm(f => ({ ...f, notify_email: e.target.value }))}
                    placeholder="security@yourorg.com" type="email"
                    style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0', boxSizing: 'border-box' }} />
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#94a3b8', fontSize: 13, cursor: 'pointer' }}>
                  <input type="checkbox" checked={form.enabled} onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))} />
                  Enable policy immediately
                </label>
              </div>

              <div style={{ display: 'flex', gap: 12, marginTop: 24 }}>
                <button onClick={handleCreate} disabled={createPolicy.isPending}
                  style={{ flex: 1, background: '#6366f1', color: '#fff', border: 'none', borderRadius: 8, padding: '10px', cursor: 'pointer', fontWeight: 600 }}>
                  {createPolicy.isPending ? 'Creating...' : 'Create Policy'}
                </button>
                <button onClick={() => setShowCreate(false)}
                  style={{ flex: 1, background: 'transparent', color: '#94a3b8', border: '1px solid #2d2d4e', borderRadius: 8, padding: '10px', cursor: 'pointer' }}>
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Run result terminal */}
        {runResult && runResult.scan_ids.length > 0 && (
          <div style={{ background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 8, padding: 16, marginBottom: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={{ color: '#22c55e', fontSize: 14, fontWeight: 600 }}>Policy triggered: {runResult.scan_ids.length} scan(s) launched</span>
              <button onClick={() => setRunResult(null)} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}>✕</button>
            </div>
            {runResult.scan_ids.slice(0, 3).map(sid => (
              <TerminalOutput key={sid} taskId={sid} height={180} />
            ))}
          </div>
        )}

        {/* Policies List */}
        {isLoading ? (
          <div style={{ color: '#94a3b8', textAlign: 'center', padding: 40 }}>Loading policies...</div>
        ) : policies.length === 0 ? (
          <div style={{ background: '#1a1a2e', border: '1px solid #2d2d4e', borderRadius: 12, padding: 60, textAlign: 'center' }}>
            <div style={{ fontSize: 40, marginBottom: 12 }}>⏰</div>
            <h3 style={{ color: '#fff', margin: '0 0 8px' }}>No scan policies yet</h3>
            <p style={{ color: '#94a3b8', margin: 0 }}>Create a policy to automate recurring scans across your assets</p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {policies.map((policy: any) => (
              <div key={policy.id} style={{ background: '#1a1a2e', border: '1px solid #2d2d4e', borderRadius: 12, padding: 20 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                      <span style={{ color: '#fff', fontWeight: 700, fontSize: 16 }}>{policy.name}</span>
                      <span style={{ background: policy.enabled ? '#16a34a22' : '#71717a22', color: policy.enabled ? '#22c55e' : '#94a3b8', border: `1px solid ${policy.enabled ? '#16a34a' : '#52525b'}`, borderRadius: 12, padding: '2px 8px', fontSize: 11 }}>
                        {policy.enabled ? 'Active' : 'Disabled'}
                      </span>
                    </div>
                    {policy.description && <p style={{ color: '#94a3b8', fontSize: 13, margin: '0 0 8px' }}>{policy.description}</p>}
                    <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                      <span style={{ color: '#94a3b8', fontSize: 13 }}>⏱ {policy.cron_expression}</span>
                      <span style={{ color: '#94a3b8', fontSize: 13 }}>🛠 {(policy.tools || []).join(', ')}</span>
                      {policy.last_run_at && <span style={{ color: '#94a3b8', fontSize: 13 }}>Last: {new Date(policy.last_run_at).toLocaleDateString()}</span>}
                      {policy.next_run_at && <span style={{ color: '#6366f1', fontSize: 13 }}>Next: {new Date(policy.next_run_at).toLocaleDateString()}</span>}
                      <span style={{ color: '#94a3b8', fontSize: 13 }}>Runs: {policy.run_count || 0}</span>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={() => handleRunNow(policy.id)} disabled={runNow.isPending}
                      style={{ background: '#059669', color: '#fff', border: 'none', borderRadius: 6, padding: '6px 14px', cursor: 'pointer', fontSize: 13 }}>
                      ▶ Run Now
                    </button>
                    <button onClick={() => updatePolicy.mutate({ id: policy.id, enabled: !policy.enabled })}
                      style={{ background: 'transparent', color: '#94a3b8', border: '1px solid #2d2d4e', borderRadius: 6, padding: '6px 14px', cursor: 'pointer', fontSize: 13 }}>
                      {policy.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button onClick={() => { if (confirm(`Delete policy "${policy.name}"?`)) deletePolicy.mutate(policy.id); }}
                      style={{ background: 'transparent', color: '#ef4444', border: '1px solid #7f1d1d', borderRadius: 6, padding: '6px 14px', cursor: 'pointer', fontSize: 13 }}>
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
    </DashboardLayout>
  );
}
