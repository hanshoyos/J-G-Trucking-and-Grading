import { apiFetch, Asset } from '@/lib/api';
import SeverityBadge from '@/components/SeverityBadge';

async function getAssets() {
  try {
    const data = await apiFetch<{ assets: Asset[]; total: number }>('/api/v1/assets?page_size=100', true);
    return data.assets ?? [];
  } catch {
    return [];
  }
}

const domainColors: Record<string, string> = {
  it: 'text-blue-400',
  ot: 'text-orange-400',
  cloud: 'text-purple-400',
};

const purdueLabels: Record<number, string> = {
  0: 'L0 Field', 1: 'L1 Control', 2: 'L2 Supervisory',
  3: 'L3 Site Ops', 4: 'L4 Site Business', 5: 'L5 Enterprise', '-1': 'Cloud/IT',
};

export default async function AssetsPage() {
  const assets = await getAssets();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-1">Asset Inventory</h1>
        <p className="text-slate-400 text-sm">{assets.length} assets discovered</p>
      </div>

      <div className="bg-ace-card border border-ace-border rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-ace-border text-slate-400 text-xs uppercase">
              <th className="px-4 py-3 text-left">Name / ID</th>
              <th className="px-4 py-3 text-left">Type</th>
              <th className="px-4 py-3 text-left">Domain</th>
              <th className="px-4 py-3 text-left">Purdue</th>
              <th className="px-4 py-3 text-left">IP Addresses</th>
              <th className="px-4 py-3 text-left">Last Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ace-border">
            {assets.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                  No assets yet — assets are discovered automatically from network events.
                </td>
              </tr>
            ) : (
              assets.map(a => (
                <tr key={a.asset_id} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3">
                    <p className="font-medium">{a.name || a.asset_id.slice(0, 8)}</p>
                    <p className="text-xs text-slate-500">{a.asset_id.slice(0, 12)}…</p>
                  </td>
                  <td className="px-4 py-3 text-slate-300">{a.asset_type}</td>
                  <td className={`px-4 py-3 font-medium ${domainColors[a.domain?.toLowerCase()] ?? 'text-slate-300'}`}>
                    {a.domain?.toUpperCase()}
                  </td>
                  <td className="px-4 py-3 text-slate-400 text-xs">
                    {purdueLabels[a.purdue_level] ?? `L${a.purdue_level}`}
                  </td>
                  <td className="px-4 py-3 text-slate-400 text-xs">
                    {(a.ip_addresses ?? []).join(', ') || '—'}
                  </td>
                  <td className="px-4 py-3 text-slate-500 text-xs">
                    {a.last_seen ? new Date(a.last_seen).toLocaleDateString() : '—'}
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
