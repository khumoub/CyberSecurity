'use client';
import { useState } from 'react';
import { useRunContainerScan, useRunCisAudit, useRunEasm, useScans } from '@/lib/hooks';
import { TerminalOutput } from '@/components/ui/TerminalOutput';

type Tool = 'container' | 'cis' | 'easm';

export default function ContainerSecurityPage() {
  const [activeTool, setActiveTool] = useState<Tool>('container');
  const [taskId, setTaskId] = useState<string | null>(null);

  const containerScan = useRunContainerScan();
  const cisAudit = useRunCisAudit();
  const easm = useRunEasm();

  // Container form
  const [image, setImage] = useState('');
  const [scanType, setScanType] = useState('image');

  // CIS form
  const [cisTarget, setCisTarget] = useState('');
  const [cisUser, setCisUser] = useState('root');
  const [cisPassword, setCisPassword] = useState('');
  const [cisKeyPath, setCisKeyPath] = useState('');

  // EASM form
  const [domain, setDomain] = useState('');
  const [autoAdd, setAutoAdd] = useState(true);

  async function handleContainerScan() {
    const result = await containerScan.mutateAsync({ image, scan_type: scanType });
    setTaskId(result.scan_id);
  }

  async function handleCisAudit() {
    const result = await cisAudit.mutateAsync({ target: cisTarget, username: cisUser, password: cisPassword || undefined, ssh_key_path: cisKeyPath || undefined });
    setTaskId(result.scan_id);
  }

  async function handleEasm() {
    const result = await easm.mutateAsync({ domain, auto_add_assets: autoAdd, port_scan: true, alert_new: true });
    setTaskId(result.scan_id);
  }

  const tools: { id: Tool; label: string; desc: string; icon: string }[] = [
    { id: 'container', label: 'Container Scanner', desc: 'Scan Docker images for CVEs', icon: '📦' },
    { id: 'cis', label: 'CIS Benchmark Audit', desc: 'SSH-based host hardening check', icon: '🛡️' },
    { id: 'easm', label: 'Attack Surface', desc: 'External asset discovery', icon: '🌐' },
  ];

  return (
    <div style={{ padding: '32px', background: '#0a0a1a', minHeight: '100vh', color: '#e2e8f0' }}>
      <div style={{ maxWidth: 1000, margin: '0 auto' }}>
        <div style={{ marginBottom: 32 }}>
          <h1 style={{ fontSize: 28, fontWeight: 700, color: '#fff', margin: 0 }}>Modern Security Scanning</h1>
          <p style={{ color: '#94a3b8', margin: '4px 0 0' }}>Container security, CIS compliance auditing, and external attack surface management</p>
        </div>

        {/* Tool selector */}
        <div style={{ display: 'flex', gap: 12, marginBottom: 32 }}>
          {tools.map(t => (
            <button key={t.id} onClick={() => { setActiveTool(t.id); setTaskId(null); }}
              style={{ flex: 1, background: activeTool === t.id ? '#1e1b4b' : '#1a1a2e', border: `1px solid ${activeTool === t.id ? '#6366f1' : '#2d2d4e'}`, borderRadius: 12, padding: '16px 20px', cursor: 'pointer', textAlign: 'left' }}>
              <div style={{ fontSize: 24, marginBottom: 6 }}>{t.icon}</div>
              <div style={{ color: '#fff', fontWeight: 600, fontSize: 14 }}>{t.label}</div>
              <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 2 }}>{t.desc}</div>
            </button>
          ))}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: taskId ? '1fr 1fr' : '1fr', gap: 24 }}>
          {/* Forms */}
          <div style={{ background: '#1a1a2e', border: '1px solid #2d2d4e', borderRadius: 12, padding: 24 }}>
            {activeTool === 'container' && (
              <>
                <h2 style={{ color: '#fff', margin: '0 0 20px', fontSize: 18 }}>Container Image Scanner</h2>
                <p style={{ color: '#94a3b8', fontSize: 13, margin: '0 0 20px' }}>
                  Uses Trivy (primary) and Grype (fallback) to detect CVEs in container images, base OS packages, and language libraries.
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <div>
                    <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>Image Name</label>
                    <input value={image} onChange={e => setImage(e.target.value)} placeholder="nginx:1.21, ubuntu:22.04, myapp:latest"
                      style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0', boxSizing: 'border-box' }} />
                  </div>
                  <div>
                    <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>Scan Type</label>
                    <select value={scanType} onChange={e => setScanType(e.target.value)}
                      style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0' }}>
                      <option value="image">Image (pull and scan)</option>
                      <option value="fs">Filesystem (local path)</option>
                      <option value="repo">Repository (Git URL)</option>
                    </select>
                  </div>
                  <div style={{ background: '#0d0d1f', borderRadius: 8, padding: 12 }}>
                    <div style={{ color: '#94a3b8', fontSize: 12 }}>
                      <strong style={{ color: '#e2e8f0' }}>What it checks:</strong><br/>
                      • OS packages (apt/yum/apk) vs CVE database<br/>
                      • Language libraries (pip, npm, gem, cargo, go)<br/>
                      • Container misconfigurations (Dockerfile issues)<br/>
                      • Secret/credential exposure in layers
                    </div>
                  </div>
                  <button onClick={handleContainerScan} disabled={!image || containerScan.isPending}
                    style={{ background: '#6366f1', color: '#fff', border: 'none', borderRadius: 8, padding: '10px', cursor: image ? 'pointer' : 'not-allowed', opacity: image ? 1 : 0.5, fontWeight: 600 }}>
                    {containerScan.isPending ? 'Scanning...' : 'Scan Image'}
                  </button>
                </div>
              </>
            )}

            {activeTool === 'cis' && (
              <>
                <h2 style={{ color: '#fff', margin: '0 0 20px', fontSize: 18 }}>CIS Benchmark Audit</h2>
                <p style={{ color: '#94a3b8', fontSize: 13, margin: '0 0 20px' }}>
                  SSH into the target host and run 37 CIS Benchmark checks covering filesystem, SSH config, PAM, logging, network, and services.
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  <div>
                    <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>Target Host IP / Hostname</label>
                    <input value={cisTarget} onChange={e => setCisTarget(e.target.value)} placeholder="192.168.1.10"
                      style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0', boxSizing: 'border-box' }} />
                  </div>
                  <div>
                    <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>SSH Username</label>
                    <input value={cisUser} onChange={e => setCisUser(e.target.value)} placeholder="root"
                      style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0', boxSizing: 'border-box' }} />
                  </div>
                  <div>
                    <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>SSH Key Path (preferred)</label>
                    <input value={cisKeyPath} onChange={e => setCisKeyPath(e.target.value)} placeholder="/root/.ssh/id_rsa"
                      style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0', boxSizing: 'border-box' }} />
                  </div>
                  <div>
                    <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>Password (if no key)</label>
                    <input type="password" value={cisPassword} onChange={e => setCisPassword(e.target.value)} placeholder="SSH password"
                      style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0', boxSizing: 'border-box' }} />
                  </div>
                  <div style={{ background: '#0d0d1f', borderRadius: 8, padding: 12 }}>
                    <div style={{ color: '#94a3b8', fontSize: 12 }}>
                      <strong style={{ color: '#e2e8f0' }}>Checks include:</strong> Filesystem noexec/nosuid, kernel params (IP forwarding, redirects), SSH hardening (PermitRoot, MaxAuthTries, IgnoreRhosts), PAM password policy, auditd, rsyslog, firewall status, NIS/rsh removal
                    </div>
                  </div>
                  <button onClick={handleCisAudit} disabled={!cisTarget || cisAudit.isPending}
                    style={{ background: '#6366f1', color: '#fff', border: 'none', borderRadius: 8, padding: '10px', cursor: cisTarget ? 'pointer' : 'not-allowed', opacity: cisTarget ? 1 : 0.5, fontWeight: 600 }}>
                    {cisAudit.isPending ? 'Auditing...' : 'Run CIS Audit'}
                  </button>
                </div>
              </>
            )}

            {activeTool === 'easm' && (
              <>
                <h2 style={{ color: '#fff', margin: '0 0 20px', fontSize: 18 }}>External Attack Surface Management</h2>
                <p style={{ color: '#94a3b8', fontSize: 13, margin: '0 0 20px' }}>
                  Discover all externally-visible assets for a domain. Uses certificate transparency logs, DNS brute force, and port scanning to map your internet exposure.
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  <div>
                    <label style={{ color: '#94a3b8', fontSize: 13, display: 'block', marginBottom: 6 }}>Organization Domain</label>
                    <input value={domain} onChange={e => setDomain(e.target.value)} placeholder="yourcompany.com"
                      style={{ width: '100%', background: '#0d0d1f', border: '1px solid #2d2d4e', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0', boxSizing: 'border-box' }} />
                  </div>
                  <label style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#94a3b8', fontSize: 13, cursor: 'pointer' }}>
                    <input type="checkbox" checked={autoAdd} onChange={e => setAutoAdd(e.target.checked)} />
                    Automatically add new discoveries to asset inventory
                  </label>
                  <div style={{ background: '#0d0d1f', borderRadius: 8, padding: 12 }}>
                    <div style={{ color: '#94a3b8', fontSize: 12 }}>
                      <strong style={{ color: '#e2e8f0' }}>Discovers:</strong><br/>
                      • Subdomains via crt.sh (Certificate Transparency)<br/>
                      • Subdomains via subfinder/theHarvester DNS brute force<br/>
                      • Open ports on each discovered host<br/>
                      • New assets not in your inventory<br/>
                      • Risky exposed services (RDP, Redis, MongoDB, etc.)
                    </div>
                  </div>
                  <button onClick={handleEasm} disabled={!domain || easm.isPending}
                    style={{ background: '#6366f1', color: '#fff', border: 'none', borderRadius: 8, padding: '10px', cursor: domain ? 'pointer' : 'not-allowed', opacity: domain ? 1 : 0.5, fontWeight: 600 }}>
                    {easm.isPending ? 'Scanning...' : 'Start EASM Scan'}
                  </button>
                </div>
              </>
            )}
          </div>

          {/* Terminal output */}
          {taskId && (
            <div>
              <h3 style={{ color: '#94a3b8', fontSize: 14, margin: '0 0 12px' }}>Live Output</h3>
              <TerminalOutput taskId={taskId} height={500} />
              <div style={{ marginTop: 12, padding: 12, background: '#1a1a2e', border: '1px solid #2d2d4e', borderRadius: 8, fontSize: 12, color: '#64748b' }}>
                Scan ID: <span style={{ color: '#6366f1', fontFamily: 'monospace' }}>{taskId}</span>
                <br/>Findings will appear in Vulnerability Management when complete.
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
