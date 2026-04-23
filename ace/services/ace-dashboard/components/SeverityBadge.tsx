const colors: Record<string, string> = {
  critical: 'bg-red-900 text-red-300 border-red-700',
  high:     'bg-orange-900 text-orange-300 border-orange-700',
  medium:   'bg-yellow-900 text-yellow-300 border-yellow-700',
  low:      'bg-blue-900 text-blue-300 border-blue-700',
  info:     'bg-slate-700 text-slate-300 border-slate-600',
};

export default function SeverityBadge({ severity }: { severity: string }) {
  const cls = colors[severity?.toLowerCase()] ?? colors.info;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${cls}`}>
      {severity?.toUpperCase() ?? 'UNKNOWN'}
    </span>
  );
}
