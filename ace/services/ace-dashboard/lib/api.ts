const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const SERVER_API = process.env.API_URL || API_BASE;

export async function apiFetch<T>(path: string, server = false): Promise<T> {
  const base = server ? SERVER_API : API_BASE;
  const res = await fetch(`${base}${path}`, {
    next: { revalidate: 30 },
    headers: { 'Content-Type': 'application/json' },
  });
  if (!res.ok) throw new Error(`API ${path} returned ${res.status}`);
  return res.json();
}

export interface Asset {
  asset_id: string;
  name: string;
  domain: string;
  purdue_level: number;
  ip_addresses: string[];
  asset_type: string;
  os?: string;
  tenant_id: string;
  last_seen: string;
}

export interface Technique {
  technique_id: string;
  name: string;
  tactic: string;
  framework: string;
  description?: string;
  seen_count: number;
}

export interface Alert {
  alert_id?: string;
  rule_name?: string;
  severity?: string;
  title?: string;
  timestamp?: string;
  tenant_id?: string;
  threat_score?: number;
}

export interface Summary {
  total_assets: number;
  total_alerts: number;
  total_techniques: number;
  active_feeds: number;
}
