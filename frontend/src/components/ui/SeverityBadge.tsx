type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge-${severity} text-xs font-semibold px-2 py-0.5 rounded uppercase tracking-wide`}>
      {severity}
    </span>
  );
}
