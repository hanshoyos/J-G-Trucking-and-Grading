import { apiFetch } from '@/lib/api';

interface Technique {
  technique_id: string;
  name: string;
  tactic: string;
  seen_count: number;
}

interface CoverageEntry {
  technique_id: string;
  count: number;
}

async function getData() {
  try {
    const [techniques, coverage] = await Promise.all([
      apiFetch<{ techniques: Technique[] }>('/api/v1/techniques?page_size=500&framework=enterprise', true)
        .then(d => d.techniques ?? []).catch(() => []),
      apiFetch<CoverageEntry[]>('/api/v1/coverage', true).catch(() => [] as CoverageEntry[]),
    ]);
    const covMap = new Map((coverage as CoverageEntry[]).map(c => [c.technique_id, c.count]));
    return { techniques: techniques as Technique[], covMap };
  } catch {
    return { techniques: [], covMap: new Map<string, number>() };
  }
}

const tacticOrder = [
  'initial-access','execution','persistence','privilege-escalation',
  'defense-evasion','credential-access','discovery','lateral-movement',
  'collection','command-and-control','exfiltration','impact',
];

function coverageColor(count: number): string {
  if (count === 0) return 'bg-slate-800 text-slate-600';
  if (count < 5) return 'bg-red-950 text-red-400';
  if (count < 20) return 'bg-red-900 text-red-300';
  return 'bg-red-700 text-red-100';
}

export default async function MitrePage() {
  const { techniques, covMap } = await getData();

  const byTactic = new Map<string, Technique[]>();
  for (const t of techniques) {
    const tac = t.tactic?.toLowerCase().replace(/\s+/g, '-') ?? 'unknown';
    if (!byTactic.has(tac)) byTactic.set(tac, []);
    byTactic.get(tac)!.push(t);
  }

  const tactics = tacticOrder.filter(t => byTactic.has(t));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-1">MITRE ATT&amp;CK Coverage</h1>
        <p className="text-slate-400 text-sm">
          {techniques.length} techniques loaded · colored by detection count
        </p>
      </div>

      {techniques.length === 0 ? (
        <div className="bg-ace-card border border-ace-border rounded-lg p-12 text-center">
          <p className="text-slate-400 mb-2">No techniques loaded yet.</p>
          <p className="text-slate-500 text-sm">
            Enable <code className="text-red-400">syncOnStart: true</code> in Helm values or trigger a sync via the API.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <div className="flex gap-1 min-w-max">
            {tactics.map(tac => {
              const techs = byTactic.get(tac) ?? [];
              return (
                <div key={tac} className="w-36">
                  <div className="bg-red-900/40 border border-red-800/50 rounded px-2 py-1 mb-1 text-center">
                    <p className="text-xs font-semibold text-red-300 truncate">
                      {tac.replace(/-/g, ' ')}
                    </p>
                    <p className="text-xs text-red-500">{techs.length}</p>
                  </div>
                  <div className="flex flex-col gap-0.5">
                    {techs.slice(0, 20).map(t => {
                      const count = covMap.get(t.technique_id) ?? 0;
                      return (
                        <div
                          key={t.technique_id}
                          title={`${t.technique_id}: ${t.name} (${count} detections)`}
                          className={`rounded px-1.5 py-1 text-xs truncate cursor-default ${coverageColor(count)}`}
                        >
                          {t.technique_id}
                        </div>
                      );
                    })}
                    {techs.length > 20 && (
                      <p className="text-xs text-slate-600 text-center py-1">+{techs.length - 20}</p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="flex gap-4 text-xs text-slate-500">
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-slate-800 inline-block"></span> No coverage</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-red-950 inline-block"></span> Low</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-red-900 inline-block"></span> Medium</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-red-700 inline-block"></span> High</span>
      </div>
    </div>
  );
}
