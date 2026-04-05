import React from 'react';

interface StatCardProps {
  label: string;
  value: string | number;
  sub?: string;
  icon?: React.ReactNode;
  trend?: { value: number; direction: 'up' | 'down' };
  accentColor?: string;
}

export function StatCard({ label, value, sub, icon, trend, accentColor = '#00d4ff' }: StatCardProps) {
  return (
    <div className="bg-[#111318] border border-[#1e2028] rounded-lg p-5 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <span className="text-[#8892a4] text-sm font-medium uppercase tracking-wider">{label}</span>
        {icon && (
          <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: `${accentColor}18` }}>
            <span style={{ color: accentColor }}>{icon}</span>
          </div>
        )}
      </div>
      <div className="flex items-end justify-between">
        <div>
          <div className="text-3xl font-bold text-[#e8eaf0] leading-none">{value}</div>
          {sub && <div className="text-xs text-[#8892a4] mt-1">{sub}</div>}
        </div>
        {trend && (
          <div
            className={`flex items-center gap-1 text-sm font-semibold ${
              trend.direction === 'up' ? 'text-[#ff3b3b]' : 'text-[#00ff88]'
            }`}
          >
            {trend.direction === 'up' ? (
              <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
                <path d="M6 1l5 5H7v5H5V6H1z" />
              </svg>
            ) : (
              <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
                <path d="M6 11L1 6h4V1h2v5h4z" />
              </svg>
            )}
            {Math.abs(trend.value)}%
          </div>
        )}
      </div>
    </div>
  );
}
