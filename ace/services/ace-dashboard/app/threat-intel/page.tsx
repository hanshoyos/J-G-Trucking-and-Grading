'use client';
import { useState } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface IOCResult {
  found: boolean;
  ioc_type?: string;
  value?: string;
  source?: string;
  severity?: string;
  confidence?: number;
  tags?: string[];
}

export default function ThreatIntelPage() {
  const [type, setType] = useState('ip');
  const [value, setValue] = useState('');
  const [result, setResult] = useState<IOCResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function lookup() {
    if (!value.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const res = await fetch(`${API}/api/v1/ioc/lookup?type=${type}&value=${encodeURIComponent(value)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setResult(await res.json());
    } catch (e: any) {
      setError(e.message || 'Lookup failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-1">Threat Intelligence</h1>
        <p className="text-slate-400 text-sm">IOC lookup against CISA KEV, URLhaus, and MalwareBazaar</p>
      </div>

      <div className="bg-ace-card border border-ace-border rounded-lg p-6 space-y-4">
        <h2 className="font-semibold text-sm text-slate-300">IOC Lookup</h2>
        <div className="flex gap-3">
          <select
            value={type}
            onChange={e => setType(e.target.value)}
            className="bg-slate-800 border border-ace-border rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-red-500"
          >
            <option value="ip">IP Address</option>
            <option value="domain">Domain</option>
            <option value="url">URL</option>
            <option value="sha256">SHA-256</option>
            <option value="md5">MD5</option>
            <option value="cve">CVE</option>
          </select>
          <input
            type="text"
            value={value}
            onChange={e => setValue(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && lookup()}
            placeholder="Enter indicator…"
            className="flex-1 bg-slate-800 border border-ace-border rounded px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-red-500"
          />
          <button
            onClick={lookup}
            disabled={loading}
            className="bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded transition-colors"
          >
            {loading ? 'Looking up…' : 'Lookup'}
          </button>
        </div>

        {error && <p className="text-red-400 text-sm">{error}</p>}

        {result && (
          <div className={`rounded-lg border p-4 ${result.found ? 'border-red-700 bg-red-950/30' : 'border-green-800 bg-green-950/30'}`}>
            {result.found ? (
              <div className="space-y-2">
                <p className="font-semibold text-red-400">Indicator FOUND in threat intel</p>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div><span className="text-slate-500">Source:</span> <span className="text-slate-200">{result.source}</span></div>
                  <div><span className="text-slate-500">Severity:</span> <span className="text-orange-400">{result.severity}</span></div>
                  <div><span className="text-slate-500">Confidence:</span> <span className="text-slate-200">{result.confidence}%</span></div>
                  <div><span className="text-slate-500">Tags:</span> <span className="text-slate-200">{(result.tags ?? []).join(', ') || '—'}</span></div>
                </div>
              </div>
            ) : (
              <p className="text-green-400 text-sm font-medium">Indicator not found in threat intel database.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
