interface Props {
  label: string;
  value: number | string;
  color?: string;
  sub?: string;
}

export default function StatCard({ label, value, color = 'text-white', sub }: Props) {
  return (
    <div className="bg-ace-card border border-ace-border rounded-lg p-6">
      <p className="text-sm text-slate-400 mb-1">{label}</p>
      <p className={`text-3xl font-bold ${color}`}>{value}</p>
      {sub && <p className="text-xs text-slate-500 mt-1">{sub}</p>}
    </div>
  );
}
