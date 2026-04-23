import { apiFetch, Summary } from '@/lib/api';
import StatCard from '@/components/StatCard';
import SeverityBadge from '@/components/SeverityBadge';

async function getSummary(): Promise<Summary> {
  try {
    return await apiFetch<Summary>('/api/v1/summary', true);
  } catch {
    return { total_assets: 0, total_alerts: 0, total_techniques: 0, active_feeds: 0 };
  }
}

async function getAlerts(): Promise<any[]> {
  try {
    return await apiFetch<any[]>('/api/v1/alerts', true);
  } catch {
    return [];
  }
}

export default async function OverviewPage() {
  const [summary, alerts] = await Promise.all([getSummary(), getAlerts()]);
  const recent = alerts.slice(-10).reverse();

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold mb-1">Platform Overview</h1>
        <p className="text-slate-400 text-sm">ACE — Adaptive Cyber Exposure</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Assets" value={summary.total_assets} color="text-blue-400" />
        <StatCard label="Active Alerts" value={summary.total_alerts} color="text-red-400" />
        <StatCard label="MITRE Techniques" value={summary.total_techniques} color="text-purple-400" />
        <StatCard label="Active Feeds" value={summary.active_feeds} color="text-green-400" />
      </div>

      <div className="bg-ace-card border border-ace-border rounded-lg">
        <div className="px-6 py-4 border-b border-ace-border">
          <h2 className="font-semibold">Recent Alerts</h2>
        </div>
        {recent.length === 0 ? (
          <p className="px-6 py-8 text-slate-500 text-sm text-center">
            No alerts yet — events will appear here as they are correlated.
          </p>
        ) : (
          <div className="divide-y divide-ace-border">
            {recent.map((a, i) => (
              <div key={a.alert_id ?? i} className="px-6 py-3 flex items-center gap-4">
                <SeverityBadge severity={a.severity ?? 'info'} />
                <span className="text-sm flex-1">{a.title ?? a.rule_name ?? 'Alert'}</span>
                <span className="text-xs text-slate-500">
                  {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : ''}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
