'use client';

import { useState } from 'react';

export type ScanType = 'nmap' | 'nuclei' | 'nikto' | 'sslscan' | 'full' | 'custom';

export interface NmapOptions {
  portRange: string;
  osDetection: boolean;
  serviceDetection: boolean;
  scanType: 'syn' | 'connect' | 'udp' | 'comprehensive';
}

export interface NucleiOptions {
  templates: ('cve' | 'misconfig' | 'web' | 'exposure')[];
  severityFilter: ('critical' | 'high' | 'medium' | 'low' | 'info')[];
  rateLimit: number;
}

export interface NiktoOptions {
  ssl: boolean;
  tuning: string[];
}

export interface ScanConfig {
  target: string;
  scanType: ScanType;
  nmapOptions?: NmapOptions;
  nucleiOptions?: NucleiOptions;
  niktoOptions?: NiktoOptions;
}

export interface ScanLaunchModalProps {
  asset?: string;
  onLaunch: (config: ScanConfig) => void;
  onClose: () => void;
}

const scanTypes: { value: ScanType; label: string; description: string; color: string }[] = [
  { value: 'nmap', label: 'Nmap', description: 'Port scan + service/OS detection', color: '#00d4ff' },
  { value: 'nuclei', label: 'Nuclei', description: 'Template-based vulnerability scanner', color: '#ff6b35' },
  { value: 'nikto', label: 'Nikto', description: 'Web server vulnerability scanner', color: '#ffcc00' },
  { value: 'sslscan', label: 'SSLScan', description: 'SSL/TLS cipher & certificate audit', color: '#00ff88' },
  { value: 'full', label: 'Full Scan', description: 'Run all scanners in sequence', color: '#ff3b3b' },
  { value: 'custom', label: 'Custom', description: 'Specify custom command', color: '#8892a4' },
];

const NIKTO_TUNING_OPTIONS = [
  { value: '1', label: 'Interesting files / seen in logs' },
  { value: '2', label: 'Misconfiguration / default files' },
  { value: '3', label: 'Info disclosure' },
  { value: '4', label: 'Injection (XSS/Script/HTML)' },
  { value: '5', label: 'Remote file retrieval' },
  { value: '6', label: 'Denial of Service' },
  { value: '7', label: 'Remote file retrieval — server root' },
  { value: '8', label: 'Command execution / remote shell' },
];

function NmapOptionsPanel({ opts, onChange }: { opts: NmapOptions; onChange: (o: NmapOptions) => void }) {
  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">Port Range</label>
        <input
          type="text"
          value={opts.portRange}
          onChange={(e) => onChange({ ...opts, portRange: e.target.value })}
          placeholder="e.g. 1-65535, 80,443,8080"
          className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-3 py-2 text-sm text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff]"
        />
      </div>
      <div>
        <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-2">Scan Type</label>
        <div className="grid grid-cols-2 gap-2">
          {(['syn', 'connect', 'udp', 'comprehensive'] as const).map((t) => (
            <label key={t} className="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                name="nmapScanType"
                checked={opts.scanType === t}
                onChange={() => onChange({ ...opts, scanType: t })}
                className="accent-[#00d4ff]"
              />
              <span className="text-sm text-[#e8eaf0] capitalize">{t} {t === 'syn' ? '(-sS)' : t === 'connect' ? '(-sT)' : t === 'udp' ? '(-sU)' : '(-A)'}</span>
            </label>
          ))}
        </div>
      </div>
      <div className="flex gap-6">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={opts.osDetection}
            onChange={(e) => onChange({ ...opts, osDetection: e.target.checked })}
            className="accent-[#00d4ff]"
          />
          <span className="text-sm text-[#e8eaf0]">OS Detection (-O)</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={opts.serviceDetection}
            onChange={(e) => onChange({ ...opts, serviceDetection: e.target.checked })}
            className="accent-[#00d4ff]"
          />
          <span className="text-sm text-[#e8eaf0]">Service Detection (-sV)</span>
        </label>
      </div>
    </div>
  );
}

function NucleiOptionsPanel({ opts, onChange }: { opts: NucleiOptions; onChange: (o: NucleiOptions) => void }) {
  const toggleTemplate = (t: NucleiOptions['templates'][number]) => {
    const next = opts.templates.includes(t) ? opts.templates.filter((x) => x !== t) : [...opts.templates, t];
    onChange({ ...opts, templates: next });
  };
  const toggleSeverity = (s: NucleiOptions['severityFilter'][number]) => {
    const next = opts.severityFilter.includes(s) ? opts.severityFilter.filter((x) => x !== s) : [...opts.severityFilter, s];
    onChange({ ...opts, severityFilter: next });
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-2">Templates</label>
        <div className="flex flex-wrap gap-2">
          {(['cve', 'misconfig', 'web', 'exposure'] as const).map((t) => (
            <label
              key={t}
              className={`flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded border cursor-pointer transition-all capitalize ${
                opts.templates.includes(t)
                  ? 'bg-[rgba(0,212,255,0.15)] text-[#00d4ff] border-[rgba(0,212,255,0.4)]'
                  : 'text-[#8892a4] border-[#1e2028] hover:border-[#2a2d3a]'
              }`}
            >
              <input type="checkbox" className="hidden" checked={opts.templates.includes(t)} onChange={() => toggleTemplate(t)} />
              {t}
            </label>
          ))}
        </div>
      </div>
      <div>
        <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-2">Severity Filter</label>
        <div className="flex flex-wrap gap-2">
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => (
            <label
              key={s}
              className={`flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded border cursor-pointer transition-all capitalize badge-${s}`}
              style={{ opacity: opts.severityFilter.includes(s) ? 1 : 0.35 }}
            >
              <input type="checkbox" className="hidden" checked={opts.severityFilter.includes(s)} onChange={() => toggleSeverity(s)} />
              {s}
            </label>
          ))}
        </div>
      </div>
      <div>
        <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">
          Rate Limit — <span className="text-[#e8eaf0]">{opts.rateLimit} req/s</span>
        </label>
        <input
          type="range"
          min={50} max={1000} step={50}
          value={opts.rateLimit}
          onChange={(e) => onChange({ ...opts, rateLimit: Number(e.target.value) })}
          className="w-full accent-[#00d4ff]"
        />
        <div className="flex justify-between text-[10px] text-[#3a3d4a]">
          <span>50</span><span>500</span><span>1000</span>
        </div>
      </div>
    </div>
  );
}

function NiktoOptionsPanel({ opts, onChange }: { opts: NiktoOptions; onChange: (o: NiktoOptions) => void }) {
  const toggleTuning = (v: string) => {
    const next = opts.tuning.includes(v) ? opts.tuning.filter((x) => x !== v) : [...opts.tuning, v];
    onChange({ ...opts, tuning: next });
  };
  return (
    <div className="space-y-4">
      <label className="flex items-center gap-2 cursor-pointer">
        <input
          type="checkbox"
          checked={opts.ssl}
          onChange={(e) => onChange({ ...opts, ssl: e.target.checked })}
          className="accent-[#00d4ff]"
        />
        <span className="text-sm text-[#e8eaf0]">Force SSL (-ssl)</span>
      </label>
      <div>
        <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-2">Tuning Options (-Tuning)</label>
        <div className="space-y-1.5 max-h-40 overflow-y-auto">
          {NIKTO_TUNING_OPTIONS.map((o) => (
            <label key={o.value} className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={opts.tuning.includes(o.value)}
                onChange={() => toggleTuning(o.value)}
                className="accent-[#ffcc00]"
              />
              <span className="text-xs text-[#e8eaf0]">{o.value} — {o.label}</span>
            </label>
          ))}
        </div>
      </div>
    </div>
  );
}

export function ScanLaunchModal({ asset, onLaunch, onClose }: ScanLaunchModalProps) {
  const [target, setTarget] = useState(asset || '');
  const [scanType, setScanType] = useState<ScanType>('nmap');
  const [customCmd, setCustomCmd] = useState('');
  const [nmapOpts, setNmapOpts] = useState<NmapOptions>({
    portRange: '1-10000',
    osDetection: true,
    serviceDetection: true,
    scanType: 'syn',
  });
  const [nucleiOpts, setNucleiOpts] = useState<NucleiOptions>({
    templates: ['cve', 'misconfig'],
    severityFilter: ['critical', 'high', 'medium'],
    rateLimit: 150,
  });
  const [niktoOpts, setNiktoOpts] = useState<NiktoOptions>({
    ssl: false,
    tuning: ['2', '3', '4'],
  });

  const handleLaunch = () => {
    if (!target.trim()) return;
    const config: ScanConfig = {
      target: target.trim(),
      scanType,
      ...(scanType === 'nmap' && { nmapOptions: nmapOpts }),
      ...(scanType === 'nuclei' && { nucleiOptions: nucleiOpts }),
      ...(scanType === 'nikto' && { niktoOptions: niktoOpts }),
    };
    onLaunch(config);
  };

  const selected = scanTypes.find((t) => t.value === scanType);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#111318] border border-[#1e2028] rounded-xl w-full max-w-2xl shadow-2xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2028] shrink-0">
          <div>
            <h3 className="text-base font-bold text-[#e8eaf0]">Launch New Scan</h3>
            <p className="text-xs text-[#8892a4] mt-0.5">Configure target and scan parameters</p>
          </div>
          <button onClick={onClose} className="text-[#8892a4] hover:text-[#e8eaf0] transition-colors">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Target */}
          <div>
            <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-1.5">Target</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="IP, domain, URL, or CIDR (e.g. 192.168.1.0/24)"
              className="w-full bg-[#0d0f14] border border-[#1e2028] rounded-lg px-4 py-2.5 text-sm text-[#e8eaf0] placeholder-[#3a3d4a] focus:outline-none focus:border-[#00d4ff]"
            />
          </div>

          {/* Scan type selector */}
          <div>
            <label className="block text-xs font-medium text-[#8892a4] uppercase tracking-wider mb-2">Scan Type</label>
            <div className="grid grid-cols-3 gap-2">
              {scanTypes.map((t) => (
                <button
                  key={t.value}
                  onClick={() => setScanType(t.value)}
                  className={`text-left px-3 py-2.5 rounded-lg border transition-all ${
                    scanType === t.value
                      ? 'border-current bg-opacity-10'
                      : 'border-[#1e2028] hover:border-[#2a2d3a]'
                  }`}
                  style={
                    scanType === t.value
                      ? { color: t.color, borderColor: t.color + '60', background: t.color + '10' }
                      : {}
                  }
                >
                  <div className={`text-sm font-bold ${scanType === t.value ? '' : 'text-[#e8eaf0]'}`}>{t.label}</div>
                  <div className="text-[10px] text-[#8892a4] mt-0.5 leading-tight">{t.description}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Dynamic options panel */}
          {scanType === 'nmap' && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <div className="w-1 h-4 rounded-full bg-[#00d4ff]" />
                <h4 className="text-xs font-semibold text-[#00d4ff] uppercase tracking-wider">Nmap Options</h4>
              </div>
              <div className="bg-[#0d0f14] border border-[#1e2028] rounded-lg p-4">
                <NmapOptionsPanel opts={nmapOpts} onChange={setNmapOpts} />
              </div>
            </div>
          )}
          {scanType === 'nuclei' && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <div className="w-1 h-4 rounded-full bg-[#ff6b35]" />
                <h4 className="text-xs font-semibold text-[#ff6b35] uppercase tracking-wider">Nuclei Options</h4>
              </div>
              <div className="bg-[#0d0f14] border border-[#1e2028] rounded-lg p-4">
                <NucleiOptionsPanel opts={nucleiOpts} onChange={setNucleiOpts} />
              </div>
            </div>
          )}
          {scanType === 'nikto' && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <div className="w-1 h-4 rounded-full bg-[#ffcc00]" />
                <h4 className="text-xs font-semibold text-[#ffcc00] uppercase tracking-wider">Nikto Options</h4>
              </div>
              <div className="bg-[#0d0f14] border border-[#1e2028] rounded-lg p-4">
                <NiktoOptionsPanel opts={niktoOpts} onChange={setNiktoOpts} />
              </div>
            </div>
          )}
          {scanType === 'custom' && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <div className="w-1 h-4 rounded-full bg-[#8892a4]" />
                <h4 className="text-xs font-semibold text-[#8892a4] uppercase tracking-wider">Custom Command</h4>
              </div>
              <div className="bg-[#0d0f14] border border-[#1e2028] rounded-lg p-4">
                <input
                  type="text"
                  value={customCmd}
                  onChange={(e) => setCustomCmd(e.target.value)}
                  placeholder="e.g. nmap -sV -p 80,443 --script vuln {target}"
                  className="w-full bg-[#0a0b0d] border border-[#1e2028] rounded-lg px-3 py-2 text-sm font-mono text-[#00ff88] placeholder-[#3a3d4a] focus:outline-none focus:border-[#8892a4]"
                />
                <p className="text-xs text-[#8892a4] mt-1.5">Use <code className="text-[#ffcc00]">{'{target}'}</code> as placeholder for the target.</p>
              </div>
            </div>
          )}
          {(scanType === 'sslscan' || scanType === 'full') && (
            <div className="bg-[rgba(0,255,136,0.05)] border border-[rgba(0,255,136,0.2)] rounded-lg p-4">
              <p className="text-sm text-[#00ff88]">
                {scanType === 'sslscan'
                  ? 'SSLScan will test all cipher suites, protocols, certificate validity and OCSP on the target.'
                  : 'Full scan runs: Nmap (comprehensive), Nuclei (all templates), Nikto, and SSLScan in sequence.'}
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-[#1e2028] shrink-0">
          <div className="text-xs text-[#8892a4]">
            Scan type: <span style={{ color: selected?.color }} className="font-semibold">{selected?.label}</span>
            {target && <> · Target: <span className="text-[#4fc3f7] font-mono">{target}</span></>}
          </div>
          <div className="flex gap-3">
            <button onClick={onClose} className="cyber-btn-ghost text-sm">Cancel</button>
            <button
              onClick={handleLaunch}
              disabled={!target.trim()}
              className="cyber-btn text-sm disabled:opacity-40 disabled:cursor-not-allowed"
              style={selected && target ? { background: selected.color, color: selected.value === 'sslscan' || selected.value === 'nmap' ? '#000' : '#000' } : {}}
            >
              Launch Scan
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
