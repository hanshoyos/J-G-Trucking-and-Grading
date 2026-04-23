'use client';
import { useEffect, useState } from 'react';
import SeverityBadge from '@/components/SeverityBadge';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface Alert {
  alert_id?: string;
  rule_name?: string;
  severity?: string;
  title?: string;
  description?: string;
  timestamp?: string;
  threat_score?: number;
  tenant_id?: string;
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const es = new EventSource(`${API}/api/v1/alerts/stream`);
    es.onopen = () => setConnected(true);
    es.onmessage = e => {
      try {
        const alert = JSON.parse(e.data) as Alert;
        setAlerts(prev => [alert, ...prev].slice(0, 200));
      } catch {}
    };
    es.onerror = () => setConnected(false);
    return () => es.close();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold mb-1">Alerts</h1>
          <p className="text-slate-400 text-sm">{alerts.length} alerts in session</p>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`}></span>
          <span className="text-slate-400">{connected ? 'Live' : 'Reconnecting…'}</span>
        </div>
      </div>

      <div className="bg-ace-card border border-ace-border rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-ace-border text-slate-400 text-xs uppercase">
              <th className="px-4 py-3 text-left">Severity</th>
              <th className="px-4 py-3 text-left">Title</th>
              <th className="px-4 py-3 text-left">Rule</th>
              <th className="px-4 py-3 text-right">Score</th>
              <th className="px-4 py-3 text-right">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ace-border">
            {alerts.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-12 text-center text-slate-500">
                  {connected ? 'Waiting for alerts…' : 'Connecting to alert stream…'}
                </td>
              </tr>
            ) : (
              alerts.map((a, i) => (
                <tr key={a.alert_id ?? i} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3">
                    <SeverityBadge severity={a.severity ?? 'info'} />
                  </td>
                  <td className="px-4 py-3 font-medium">{a.title ?? a.rule_name ?? 'Alert'}</td>
                  <td className="px-4 py-3 text-slate-400">{a.rule_name ?? '—'}</td>
                  <td className="px-4 py-3 text-right">
                    <span className="text-orange-400 font-mono">{a.threat_score?.toFixed(1) ?? '—'}</span>
                  </td>
                  <td className="px-4 py-3 text-right text-slate-500 text-xs">
                    {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : '—'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
