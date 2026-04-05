'use client';

import { useState } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { roleColors, roleLabels, type UserRole } from '@/lib/auth';

interface OrgUser {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  active: boolean;
  lastLogin: string;
}

interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  created: string;
  lastUsed: string;
  scopes: string[];
}

const initialUsers: OrgUser[] = [
  { id: 'u1', name: 'Alice Johnson', email: 'alice@corp.com', role: 'admin', active: true, lastLogin: '2026-04-05 09:14' },
  { id: 'u2', name: 'Bob Smith', email: 'bob@corp.com', role: 'analyst', active: true, lastLogin: '2026-04-05 07:42' },
  { id: 'u3', name: 'Carol White', email: 'carol@corp.com', role: 'junior_analyst', active: true, lastLogin: '2026-04-04 16:30' },
  { id: 'u4', name: 'Dave Brown', email: 'dave@corp.com', role: 'tprm_manager', active: true, lastLogin: '2026-04-03 11:20' },
  { id: 'u5', name: 'Eve Davis', email: 'eve@corp.com', role: 'read_only', active: false, lastLogin: '2026-03-28 14:05' },
];

const apiKeys: ApiKey[] = [
  { id: 'k1', name: 'CI/CD Pipeline', prefix: 'lrsk_live_CIcd...', created: '2026-01-15', lastUsed: '2026-04-05', scopes: ['scan:read', 'finding:read'] },
  { id: 'k2', name: 'SIEM Integration', prefix: 'lrsk_live_SIem...', created: '2026-02-01', lastUsed: '2026-04-05', scopes: ['finding:read', 'asset:read'] },
  { id: 'k3', name: 'Reporting Bot', prefix: 'lrsk_live_RPbt...', created: '2026-03-10', lastUsed: '2026-04-04', scopes: ['report:write', 'finding:read'] },
];

const roles: UserRole[] = ['admin', 'analyst', 'junior_analyst', 'tprm_manager', 'read_only'];

export default function SettingsPage() {
  const [users, setUsers] = useState<OrgUser[]>(initialUsers);
  const [activeTab, setActiveTab] = useState<'org' | 'users' | 'api' | 'billing'>('org');

  const [orgName, setOrgName] = useState('ACME Corporation');
  const [orgDomain, setOrgDomain] = useState('corp.com');
  const [orgTimezone, setOrgTimezone] = useState('UTC');

  const toggleUser = (id: string) => {
    setUsers((prev) => prev.map((u) => (u.id === id ? { ...u, active: !u.active } : u)));
  };

  const changeRole = (id: string, role: UserRole) => {
    setUsers((prev) => prev.map((u) => (u.id === id ? { ...u, role } : u)));
  };

  const tabs: { id: 'org' | 'users' | 'api' | 'billing'; label: string }[] = [
    { id: 'org', label: 'Organization' },
    { id: 'users', label: 'User Management' },
    { id: 'api', label: 'API Keys' },
    { id: 'billing', label: 'Billing & Plan' },
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
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
                activeTab === tab.id ? 'bg-[#1a1f2e] text-[#00d4ff]' : 'text-[#8892a4] hover:text-[#e8eaf0]'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Organization */}
        {activeTab === 'org' && (
          <div className="max-w-xl space-y-4">
            <div className="bg-[#111318] border border-[#1e2028] rounded-lg p-6 space-y-4">
              <h3 className="text-sm font-semibold text-[#e8eaf0]">Organization Details</h3>
              <div>
                <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">Organization Name</label>
                <input
                  type="text"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm text-[#e8eaf0] focus:outline-none focus:border-[#00d4ff]"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">Primary Domain</label>
                <input
                  type="text"
                  value={orgDomain}
                  onChange={(e) => setOrgDomain(e.target.value)}
                  className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm text-[#e8eaf0] font-mono focus:outline-none focus:border-[#00d4ff]"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">Timezone</label>
                <select
                  value={orgTimezone}
                  onChange={(e) => setOrgTimezone(e.target.value)}
                  className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm text-[#e8eaf0] focus:outline-none focus:border-[#00d4ff]"
                >
                  {['UTC', 'America/New_York', 'America/Los_Angeles', 'Europe/London', 'Europe/Berlin', 'Asia/Tokyo'].map((tz) => (
                    <option key={tz} value={tz}>{tz}</option>
                  ))}
                </select>
              </div>
              <button className="cyber-btn text-sm">Save Changes</button>
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
              <button className="cyber-btn text-sm">+ Invite User</button>
            </div>
            <div className="bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2028]">
                    {['Name', 'Email', 'Role', 'Last Login', 'Active'].map((h) => (
                      <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr key={user.id} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-7 h-7 rounded-full bg-[#1e2028] flex items-center justify-center text-xs font-bold text-[#00d4ff]">
                            {user.name.charAt(0)}
                          </div>
                          <span className="text-xs font-medium text-[#e8eaf0]">{user.name}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-[#8892a4] font-mono">{user.email}</td>
                      <td className="px-4 py-3">
                        <select
                          value={user.role}
                          onChange={(e) => changeRole(user.id, e.target.value as UserRole)}
                          className="bg-[#0d0f14] border border-[#1e2028] rounded px-2 py-1 text-xs text-[#e8eaf0] focus:outline-none focus:border-[#00d4ff]"
                        >
                          {roles.map((r) => (
                            <option key={r} value={r}>{roleLabels[r]}</option>
                          ))}
                        </select>
                        <span className={`ml-2 text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${roleColors[user.role]}`}>
                          {roleLabels[user.role]}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">{user.lastLogin}</td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => toggleUser(user.id)}
                          className={`relative w-10 h-5 rounded-full transition-colors ${user.active ? 'bg-[#00d4ff]' : 'bg-[#1e2028]'}`}
                        >
                          <span
                            className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-all duration-150 ${user.active ? 'left-[22px]' : 'left-0.5'}`}
                          />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* API Keys */}
        {activeTab === 'api' && (
          <div className="space-y-4">
            <div className="flex justify-end">
              <button className="cyber-btn text-sm">+ Create API Key</button>
            </div>

            <div className="bg-[#111318] border border-[#1e2028] rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-[#1e2028]">
                <h3 className="text-sm font-semibold text-[#e8eaf0]">Active API Keys</h3>
                <p className="text-xs text-[#8892a4] mt-0.5">API keys provide programmatic access. Treat them like passwords — never commit to source control.</p>
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2028]">
                    {['Name', 'Key Prefix', 'Created', 'Last Used', 'Scopes', ''].map((h) => (
                      <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-[#8892a4] uppercase tracking-wider">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {apiKeys.map((key) => (
                    <tr key={key.id} className="border-b border-[#1e2028] hover:bg-[#161b27] transition-colors">
                      <td className="px-4 py-3 text-xs font-medium text-[#e8eaf0]">{key.name}</td>
                      <td className="px-4 py-3 font-mono text-xs text-[#4fc3f7]">{key.prefix}</td>
                      <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">{key.created}</td>
                      <td className="px-4 py-3 font-mono text-xs text-[#8892a4]">{key.lastUsed}</td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {key.scopes.map((s) => (
                            <span key={s} className="text-[9px] px-1.5 py-0.5 rounded bg-[rgba(0,212,255,0.1)] text-[#00d4ff] border border-[rgba(0,212,255,0.2)]">
                              {s}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <button className="text-xs text-[#ff3b3b] hover:underline">Revoke</button>
                      </td>
                    </tr>
                  ))}
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
                    <h3 className="text-lg font-bold text-[#e8eaf0]">Professional Plan</h3>
                    <span className="text-xs font-bold text-[#00d4ff] bg-[rgba(0,212,255,0.15)] border border-[rgba(0,212,255,0.3)] px-2 py-0.5 rounded uppercase">
                      Current
                    </span>
                  </div>
                  <p className="text-[#8892a4] text-sm">Up to 500 assets, 5 analysts, all modules included</p>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-bold text-[#e8eaf0]">$499<span className="text-sm text-[#8892a4] font-normal">/mo</span></div>
                  <div className="text-xs text-[#8892a4]">Billed annually</div>
                </div>
              </div>
              <div className="mt-4 pt-4 border-t border-[#1e2028] grid grid-cols-3 gap-4 text-xs">
                {[
                  { label: 'Assets Used', value: '342 / 500' },
                  { label: 'Analysts', value: '4 / 5' },
                  { label: 'Next Billing', value: 'May 1, 2026' },
                ].map((item) => (
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
                {[
                  { name: 'Starter', price: '$99/mo', assets: '50 assets', analysts: '2 analysts', color: '#4fc3f7' },
                  { name: 'Professional', price: '$499/mo', assets: '500 assets', analysts: '5 analysts', color: '#00d4ff', current: true },
                  { name: 'Enterprise', price: 'Custom', assets: 'Unlimited', analysts: 'Unlimited', color: '#ffcc00' },
                ].map((plan) => (
                  <div
                    key={plan.name}
                    className={`flex items-center justify-between p-4 rounded-lg border ${plan.current ? 'border-[rgba(0,212,255,0.4)] bg-[rgba(0,212,255,0.05)]' : 'border-[#1e2028] hover:border-[#2a2d3a]'} transition-colors`}
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-2 h-2 rounded-full" style={{ background: plan.color }} />
                      <div>
                        <div className="text-sm font-semibold text-[#e8eaf0]">{plan.name}</div>
                        <div className="text-xs text-[#8892a4]">{plan.assets} · {plan.analysts}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-sm font-bold" style={{ color: plan.color }}>{plan.price}</div>
                      {plan.current ? (
                        <span className="text-xs text-[#00d4ff]">Current</span>
                      ) : (
                        <button
                          className="text-xs px-3 py-1.5 rounded-md border transition-all"
                          style={{
                            color: plan.color,
                            borderColor: `${plan.color}40`,
                            background: `${plan.color}10`,
                          }}
                        >
                          {plan.name === 'Enterprise' ? 'Contact Sales' : 'Upgrade'}
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
