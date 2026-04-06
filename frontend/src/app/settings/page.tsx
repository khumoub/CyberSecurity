'use client';

import { useState, useEffect } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { roleColors, roleLabels, type UserRole } from '@/lib/auth';
import { useBillingPlans, useSubscription } from '@/lib/hooks';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';

const roles: UserRole[] = ['admin', 'analyst', 'junior_analyst', 'tprm_manager', 'read_only'];

function authHeaders() {
  const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// ── Hooks ─────────────────────────────────────────────────────────────────────

function useUsers() {
  return useQuery({
    queryKey: ['users'],
    queryFn: async () => {
      const res = await axios.get('/api/v1/users/', { headers: authHeaders() });
      return res.data;
    },
  });
}

function useUpdateRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ userId, role }: { userId: string; role: string }) => {
      const res = await axios.patch(`/api/v1/users/${userId}/role`, { role }, { headers: authHeaders() });
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  });
}

function useToggleActive() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ userId, is_active }: { userId: string; is_active: boolean }) => {
      const res = await axios.patch(`/api/v1/users/${userId}/active`, { is_active }, { headers: authHeaders() });
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  });
}

function useInviteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (data: { email: string; full_name: string; role: string }) => {
      const res = await axios.post('/api/v1/users/invite', data, { headers: authHeaders() });
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  });
}

function useApiKeys() {
  return useQuery({
    queryKey: ['api-keys'],
    queryFn: async () => {
      const res = await axios.get('/api/v1/users/api-keys', { headers: authHeaders() });
      return res.data;
    },
  });
}

function useCreateApiKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (data: { name: string; scopes: string[] }) => {
      const res = await axios.post('/api/v1/users/api-keys', data, { headers: authHeaders() });
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['api-keys'] }),
  });
}

function useRevokeApiKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (keyId: string) => {
      await axios.delete(`/api/v1/users/api-keys/${keyId}`, { headers: authHeaders() });
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['api-keys'] }),
  });
}

function useSaveOrg() {
  return useMutation({
    mutationFn: async (data: { name: string; domain: string; timezone: string }) => {
      const res = await axios.patch('/api/v1/auth/organization', data, { headers: authHeaders() });
      return res.data;
    },
  });
}

// ── Invite Modal ──────────────────────────────────────────────────────────────

function InviteModal({ onClose }: { onClose: () => void }) {
  const [form, setForm] = useState({ email: '', full_name: '', role: 'analyst' });
  const [result, setResult] = useState<any>(null);
  const invite = useInviteUser();

  const handleSubmit = async () => {
    try {
      const data = await invite.mutateAsync(form);
      setResult(data);
    } catch (err: any) {
      alert(err?.response?.data?.detail ?? 'Invite failed');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
      <div className="bg-[#111318] border border-[#1e2028] rounded-xl p-6 w-full max-w-md">
        <h2 className="text-lg font-bold text-[#e8eaf0] mb-4">Invite User</h2>
        {result ? (
          <div className="space-y-3">
            <div className="bg-[rgba(0,255,136,0.08)] border border-[rgba(0,255,136,0.3)] rounded-lg p-4 text-sm text-[#e8eaf0]">
              <div className="text-[#00ff88] font-bold mb-2">User invited successfully</div>
              <div>Email: <span className="font-mono text-[#4fc3f7]">{result.email}</span></div>
              {result.temp_password && (
                <div className="mt-2">
                  Temp password: <span className="font-mono text-[#ffcc00]">{result.temp_password}</span>
                  <div className="text-xs text-[#8892a4] mt-1">Share this securely — it will not be shown again.</div>
                </div>
              )}
            </div>
            <button onClick={onClose} className="w-full cyber-btn text-sm">Done</button>
          </div>
        ) : (
          <div className="space-y-3">
            {[
              { label: 'Full Name', key: 'full_name', placeholder: 'Alice Johnson' },
              { label: 'Email', key: 'email', placeholder: 'alice@corp.com' },
            ].map(({ label, key, placeholder }) => (
              <div key={key}>
                <label className="block text-xs text-[#8892a4] mb-1">{label}</label>
                <input
                  type="text" placeholder={placeholder}
                  value={(form as any)[key]}
                  onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                  className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-3 py-2 text-sm text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff]"
                />
              </div>
            ))}
            <div>
              <label className="block text-xs text-[#8892a4] mb-1">Role</label>
              <select value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
                className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-3 py-2 text-sm text-[#e8eaf0] focus:outline-none focus:border-[#00d4ff]">
                {roles.map(r => <option key={r} value={r}>{roleLabels[r]}</option>)}
              </select>
            </div>
            <div className="flex gap-3 pt-2">
              <button onClick={onClose} className="flex-1 border border-[#1e2028] text-[#8892a4] rounded-lg py-2 text-sm">Cancel</button>
              <button
                onClick={handleSubmit}
                disabled={!form.email || !form.full_name || invite.isPending}
                className="flex-1 cyber-btn text-sm"
              >
                {invite.isPending ? 'Inviting…' : 'Send Invite'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Create API Key Modal ───────────────────────────────────────────────────────

function CreateKeyModal({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState(['scan:read', 'finding:read']);
  const [result, setResult] = useState<any>(null);
  const createKey = useCreateApiKey();
  const allScopes = ['scan:read', 'finding:read', 'asset:read', 'report:write', 'finding:write', 'asset:write'];

  const toggle = (s: string) => setScopes(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]);

  const handleCreate = async () => {
    try {
      const data = await createKey.mutateAsync({ name, scopes });
      setResult(data);
    } catch (err: any) {
      alert(err?.response?.data?.detail ?? 'Create failed');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
      <div className="bg-[#111318] border border-[#1e2028] rounded-xl p-6 w-full max-w-md">
        <h2 className="text-lg font-bold text-[#e8eaf0] mb-4">Create API Key</h2>
        {result ? (
          <div className="space-y-3">
            <div className="bg-[rgba(255,204,0,0.08)] border border-[rgba(255,204,0,0.3)] rounded-lg p-4">
              <div className="text-[#ffcc00] font-bold text-sm mb-2">Save this key — shown once only</div>
              <div className="font-mono text-xs text-[#e8eaf0] bg-[#0d0f14] rounded p-2 break-all select-all">{result.key}</div>
            </div>
            <button onClick={onClose} className="w-full cyber-btn text-sm">Done</button>
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-[#8892a4] mb-1">Key Name</label>
              <input type="text" value={name} onChange={e => setName(e.target.value)} placeholder="e.g. CI/CD Pipeline"
                className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-3 py-2 text-sm text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff]"
              />
            </div>
            <div>
              <label className="block text-xs text-[#8892a4] mb-2">Scopes</label>
              <div className="flex flex-wrap gap-2">
                {allScopes.map(s => (
                  <button key={s} onClick={() => toggle(s)}
                    className={`text-[10px] px-2 py-1 rounded border transition-all ${scopes.includes(s) ? 'text-[#00d4ff] bg-[rgba(0,212,255,0.15)] border-[rgba(0,212,255,0.4)]' : 'text-[#8892a4] border-[#1e2028]'}`}>
                    {s}
                  </button>
                ))}
              </div>
            </div>
            <div className="flex gap-3 pt-2">
              <button onClick={onClose} className="flex-1 border border-[#1e2028] text-[#8892a4] rounded-lg py-2 text-sm">Cancel</button>
              <button
                onClick={handleCreate}
                disabled={!name || createKey.isPending}
                className="flex-1 cyber-btn text-sm"
              >
                {createKey.isPending ? 'Creating…' : 'Create Key'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<'org' | 'users' | 'api' | 'billing'>('org');
  const [orgName, setOrgName]     = useState('');
  const [orgDomain, setOrgDomain] = useState('');
  const [orgTz, setOrgTz]         = useState('UTC');
  const [saveMsg, setSaveMsg]     = useState('');
  const [showInvite, setShowInvite]   = useState(false);
  const [showCreateKey, setShowCreateKey] = useState(false);

  const usersQ   = useUsers();
  const apiKeysQ = useApiKeys();
  const saveOrg  = useSaveOrg();
  const updateRole   = useUpdateRole();
  const toggleActive = useToggleActive();
  const revokeKey    = useRevokeApiKey();
  const plansQ   = useBillingPlans();
  const subQ     = useSubscription();

  const users: any[]   = usersQ.data?.users ?? [];
  const apiKeys: any[] = apiKeysQ.data?.api_keys ?? [];
  const plans: any[]   = plansQ.data?.plans ?? [];
  const sub: any       = subQ.data ?? {};

  // Pre-fill org form from subscription data
  useEffect(() => {
    if (sub?.org_name && !orgName)   setOrgName(sub.org_name);
    if (sub?.org_domain && !orgDomain) setOrgDomain(sub.org_domain);
  }, [sub]);

  const handleSaveOrg = async () => {
    try {
      await saveOrg.mutateAsync({ name: orgName, domain: orgDomain, timezone: orgTz });
      setSaveMsg('Saved successfully');
      setTimeout(() => setSaveMsg(''), 3000);
    } catch {
      setSaveMsg('Save failed');
    }
  };

  const tabs = [
    { id: 'org' as const, label: 'Organization' },
    { id: 'users' as const, label: 'User Management' },
    { id: 'api' as const, label: 'API Keys' },
    { id: 'billing' as const, label: 'Billing & Plan' },
  ];

  return (
    <DashboardLayout>
      <div className="p-6 space-y-5 min-h-full">
        <div>
          <h1 className="text-xl font-bold text-[#e8eaf0]">Settings</h1>
          <p className="text-[#8892a4] text-sm mt-0.5">Organization configuration, user management and API access</p>
        </div>

        {/* Tab bar */}
        <div className="flex gap-1 bg-[#111318] border border-[#1e2028] rounded-lg p-1 w-fit">
          {tabs.map(tab => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${activeTab === tab.id ? 'bg-[#1a1f2e] text-[#00d4ff]' : 'text-[#8892a4] hover:text-[#e8eaf0]'}`}>
              {tab.label}
            </button>
          ))}
        </div>

        {/* Organization */}
        {activeTab === 'org' && (
          <div className="max-w-xl space-y-4">
            <div className="bg-[#111318] border border-[#1e2028] rounded-lg p-6 space-y-4">
              <h3 className="text-sm font-semibold text-[#e8eaf0]">Organization Details</h3>
              {[
                { label: 'Organization Name', value: orgName, set: setOrgName, mono: false, placeholder: 'ACME Corp' },
                { label: 'Primary Domain', value: orgDomain, set: setOrgDomain, mono: true, placeholder: 'corp.com' },
              ].map(({ label, value, set, mono, placeholder }) => (
                <div key={label}>
                  <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">{label}</label>
                  <input type="text" value={value} onChange={e => set(e.target.value)} placeholder={placeholder}
                    className={`w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm text-[#e8eaf0] focus:outline-none focus:border-[#00d4ff] ${mono ? 'font-mono' : ''}`}
                  />
                </div>
              ))}
              <div>
                <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">Timezone</label>
                <select value={orgTz} onChange={e => setOrgTz(e.target.value)}
                  className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm text-[#e8eaf0] focus:outline-none focus:border-[#00d4ff]">
                  {['UTC','America/New_York','America/Los_Angeles','Europe/London','Europe/Berlin','Asia/Tokyo'].map(tz =>
                    <option key={tz} value={tz}>{tz}</option>
                  )}
                </select>
              </div>
              <div className="flex items-center gap-3">
                <button onClick={handleSaveOrg} disabled={saveOrg.isPending} className="cyber-btn text-sm">
                  {saveOrg.isPending ? 'Saving…' : 'Save Changes'}
                </button>
                {saveMsg && <span className={`text-xs ${saveMsg.includes('fail') ? 'text-[#ff3b3b]' : 'text-[#00ff88]'}`}>{saveMsg}</span>}
              </div>
            </div>

            <div className="bg-[#111318] border border-[rgba(255,59,59,0.3)] rounded-lg p-6 space-y-3">
              <h3 className="text-sm font-semibold text-[#ff3b3b]">Danger Zone</h3>
              <p className="text-xs text-[#8892a4]">Permanently delete your organization and all associated data. This action cannot be undone.</p>
              <button className="text-sm font-semibold px-4 py-2 rounded-md border border-[rgba(255,59,59,0.4)] text-[#ff3b3b] hover:bg-[rgba(255,59,59,0.1)] transition-colors">
                Delete Organization
              </button>
            </div>
          </div>
        )}

        {/* User Management */}
        {activeTab === 'users' && (
          <div className="space-y-4">
            <div className="flex justify-end">
              <button onClick={() => setShowInvite(true)} className="cyber-btn text-sm">+ Invite User</button>
            </div>
            <div className="bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2028]">
                    {['Name', 'Email', 'Role', 'Last Login', 'Active'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {usersQ.isLoading
                    ? Array.from({length: 4}).map((_, i) => (
                        <tr key={i}><td colSpan={5} className="px-4 py-3"><div className="h-4 bg-[#1e2028] rounded animate-pulse" /></td></tr>
                      ))
                    : users.map((user: any) => (
                      <tr key={user.id} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="w-7 h-7 rounded-full bg-[#1e2028] flex items-center justify-center text-xs font-bold text-[#00d4ff]">
                              {(user.full_name ?? user.email ?? '?').charAt(0).toUpperCase()}
                            </div>
                            <span className="text-xs font-medium text-[#e8eaf0]">{user.full_name}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-xs text-[#8892a4] font-mono">{user.email}</td>
                        <td className="px-4 py-3">
                          <select value={user.role}
                            onChange={e => updateRole.mutate({ userId: user.id, role: e.target.value })}
                            className="bg-[#0d0f14] border border-[#1e2028] rounded px-2 py-1 text-xs text-[#e8eaf0] focus:outline-none focus:border-[#00d4ff]">
                            {roles.map(r => <option key={r} value={r}>{roleLabels[r]}</option>)}
                          </select>
                          <span className={`ml-2 text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${roleColors[user.role as UserRole] ?? ''}`}>
                            {roleLabels[user.role as UserRole] ?? user.role}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">
                          {user.last_login ? new Date(user.last_login).toLocaleString() : '—'}
                        </td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => toggleActive.mutate({ userId: user.id, is_active: !user.is_active })}
                            className={`relative w-10 h-5 rounded-full transition-colors ${user.is_active ? 'bg-[#00d4ff]' : 'bg-[#1e2028]'}`}
                          >
                            <span className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-all duration-150 ${user.is_active ? 'left-[22px]' : 'left-0.5'}`} />
                          </button>
                        </td>
                      </tr>
                    ))
                  }
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* API Keys */}
        {activeTab === 'api' && (
          <div className="space-y-4">
            <div className="flex justify-end">
              <button onClick={() => setShowCreateKey(true)} className="cyber-btn text-sm">+ Create API Key</button>
            </div>
            <div className="bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-[#1e2028]">
                <h3 className="text-sm font-semibold text-[#e8eaf0]">Active API Keys</h3>
                <p className="text-xs text-[#8892a4] mt-0.5">API keys provide programmatic access. Never commit to source control.</p>
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2028]">
                    {['Name', 'Key Prefix', 'Created', 'Last Used', 'Scopes', ''].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {apiKeysQ.isLoading
                    ? Array.from({length: 3}).map((_, i) => (
                        <tr key={i}><td colSpan={6} className="px-4 py-3"><div className="h-4 bg-[#1e2028] rounded animate-pulse" /></td></tr>
                      ))
                    : apiKeys.length === 0
                    ? <tr><td colSpan={6} className="px-4 py-8 text-center text-xs text-[#8892a4]">No API keys yet.</td></tr>
                    : apiKeys.map((key: any) => (
                      <tr key={key.id} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                        <td className="px-4 py-3 text-xs font-medium text-[#e8eaf0]">{key.name}</td>
                        <td className="px-4 py-3 font-mono text-xs text-[#4fc3f7]">{key.prefix}</td>
                        <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">{key.created_at ? new Date(key.created_at).toLocaleDateString() : '—'}</td>
                        <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">{key.last_used_at ? new Date(key.last_used_at).toLocaleDateString() : '—'}</td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {(key.scopes ?? []).map((s: string) => (
                              <span key={s} className="text-[9px] px-1.5 py-0.5 rounded bg-[rgba(0,212,255,0.1)] text-[#00d4ff] border border-[rgba(0,212,255,0.2)]">{s}</span>
                            ))}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => { if (confirm('Revoke this key?')) revokeKey.mutate(key.id); }}
                            className="text-xs text-[#ff3b3b] hover:underline"
                          >
                            Revoke
                          </button>
                        </td>
                      </tr>
                    ))
                  }
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Billing */}
        {activeTab === 'billing' && (
          <div className="max-w-2xl space-y-4">
            {/* Current plan */}
            <div className="bg-[#111318] border border-[rgba(0,212,255,0.3)] rounded-lg p-6">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-lg font-bold text-[#e8eaf0]">{sub?.plan_name ?? 'Loading…'}</h3>
                    <span className="text-xs font-bold text-[#00d4ff] bg-[rgba(0,212,255,0.15)] border border-[rgba(0,212,255,0.3)] px-2 py-0.5 rounded uppercase">
                      Current
                    </span>
                  </div>
                  <p className="text-[#8892a4] text-sm">{sub?.description ?? 'Your current subscription plan'}</p>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-bold text-[#e8eaf0]">
                    {sub?.price_monthly != null ? `$${sub.price_monthly}` : '—'}
                    <span className="text-sm text-[#8892a4] font-normal">/mo</span>
                  </div>
                </div>
              </div>
              <div className="mt-4 pt-4 border-t border-[#1e2028] grid grid-cols-3 gap-4 text-xs">
                {[
                  { label: 'Assets Used', value: sub?.usage?.assets != null ? `${sub.usage.assets} / ${sub?.limits?.assets ?? '∞'}` : '—' },
                  { label: 'Users', value: sub?.usage?.users != null ? `${sub.usage.users} / ${sub?.limits?.users ?? '∞'}` : '—' },
                  { label: 'Next Billing', value: sub?.next_billing ? new Date(sub.next_billing).toLocaleDateString() : '—' },
                ].map(item => (
                  <div key={item.label}>
                    <div className="text-[#8892a4] uppercase tracking-wider text-[10px]">{item.label}</div>
                    <div className="text-[#e8eaf0] font-semibold mt-0.5">{item.value}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Plan comparison */}
            <div className="bg-[#111318] border border-[#1e2028] rounded-lg p-6 space-y-4">
              <h3 className="text-sm font-semibold text-[#e8eaf0]">Available Plans</h3>
              <div className="space-y-3">
                {(plans.length > 0 ? plans : [
                  { name: 'Community', price_monthly: 0, color: '#4fc3f7', assets: '10 assets', users: '2 users' },
                  { name: 'Professional', price_monthly: 149, color: '#00d4ff', assets: '500 assets', users: '10 users' },
                  { name: 'Enterprise', price_monthly: null, color: '#ffcc00', assets: 'Unlimited', users: 'Unlimited' },
                ]).map((plan: any) => {
                  const color = plan.color ?? '#00d4ff';
                  const isCurrent = (sub?.plan_name ?? '').toLowerCase() === plan.name.toLowerCase();
                  return (
                    <div key={plan.name}
                      className={`flex items-center justify-between p-4 rounded-lg border transition-colors ${isCurrent ? 'border-[rgba(0,212,255,0.4)] bg-[rgba(0,212,255,0.05)]' : 'border-[#1e2028] hover:border-[#2a2d3a]'}`}>
                      <div className="flex items-center gap-3">
                        <div className="w-2 h-2 rounded-full" style={{ background: color }} />
                        <div>
                          <div className="text-sm font-semibold text-[#e8eaf0]">{plan.name}</div>
                          <div className="text-xs text-[#8892a4]">
                            {plan.assets ?? `${plan.limits?.assets ?? '∞'} assets`} · {plan.users ?? `${plan.limits?.users ?? '∞'} users`}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-sm font-bold" style={{ color }}>
                          {plan.price_monthly != null ? `$${plan.price_monthly}/mo` : 'Custom'}
                        </div>
                        {isCurrent ? (
                          <span className="text-xs text-[#00d4ff]">Current</span>
                        ) : (
                          <button
                            onClick={() => alert(plan.name === 'Enterprise' ? 'Contact sales@leruo.io for enterprise pricing.' : 'Stripe checkout coming soon.')}
                            className="text-xs px-3 py-1.5 rounded-md border transition-all"
                            style={{ color, borderColor: `${color}40`, background: `${color}10` }}
                          >
                            {plan.name === 'Enterprise' ? 'Contact Sales' : 'Upgrade'}
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>

      {showInvite && <InviteModal onClose={() => setShowInvite(false)} />}
      {showCreateKey && <CreateKeyModal onClose={() => setShowCreateKey(false)} />}
    </DashboardLayout>
  );
}
