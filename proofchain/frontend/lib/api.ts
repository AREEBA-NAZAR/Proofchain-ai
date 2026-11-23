export const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export type Signal = { id: string; label: string; score: number | null; weight: number; detail: string };

export type Analysis = {
  kind: string;
  analyzed: boolean;
  engine: string | null;
  /** Overall content risk: the worse of AI-generation likelihood and file safety. */
  risk: number | null;
  ai_risk?: number | null;
  safety?: {
    level: "none" | "caution" | "danger";
    findings: { id: string; label: string; severity: "caution" | "danger"; detail: string }[];
  };
  verdict: "no_strong_signals" | "inconclusive" | "elevated" | "not_assessed";
  confidence: string;
  declared_generator: string | null;
  signals: Signal[];
  note?: string;
};

export type RecordInfo = {
  content_hash: string;
  short_id: string;
  creator: string;
  timestamp: number;
  version: number;
  revoked: boolean;
  parent_hash: string | null;
  root_hash: string;
  metadata_uri: string;
  tx_hash: string | null;
  block_number: number | null;
  title: string;
  kind: string | null;
  risk: number | null;
};

export type Flag = {
  id: number;
  content_hash: string;
  short_id: string;
  creator: string;
  kind: string;
  severity: "info" | "medium" | "high";
  detail: string;
  related_hash: string | null;
  created_at: string;
};

export type Identity = { name: string; metadata_uri: string; verified: boolean; registered_at: number };

export type Trust = {
  score: number;
  max: number;
  band: "high" | "moderate" | "low" | "unregistered";
  components: { id: string; label: string; points: number; max: number; detail: string }[];
};

export type Report = {
  content_hash: string;
  short_id: string;
  status: "verified" | "revoked" | "not_found";
  record: RecordInfo | null;
  identity: Identity | null;
  asset: { filename: string; title: string; description: string; mime: string; size: number } | null;
  analysis: Analysis | null;
  lineage: RecordInfo[];
  flags: Flag[];
  trust: Trust;
  verification_count: number;
  chain: { network: string; chainId: number; contract: string };
  verify_url: string;
  disclaimers: string[];
  file_check?: {
    filename: string;
    computed_hash: string;
    match: boolean;
    message: string;
    visual_similarity?: number | null;
  };
};

export type AnalyzeResult = {
  content_hash: string;
  short_id: string;
  filename: string;
  size: number;
  mime: string;
  analysis: Analysis;
  metadata_uri: string;
  already_registered: { creator: string; timestamp: number } | null;
};

export type ChainConfig = { chainId: number; network: string; address: string; abi: any[]; rpcUrl: string | null };

export type Stats = Record<
  "records" | "revoked" | "creators" | "analyzed" | "verifications" | "mismatches" | "flags" | "flags_serious",
  number
>;

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(API_URL + path, init);
  } catch {
    throw new Error(`Cannot reach the ProofChain API at ${API_URL}. Is the backend running?`);
  }
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const detail = body?.detail;
    throw new Error(typeof detail === "string" ? detail : `Request failed (${res.status}).`);
  }
  return body as T;
}

export function postFile<T>(path: string, file: File, fields: Record<string, string> = {}): Promise<T> {
  const form = new FormData();
  form.append("file", file);
  for (const [k, v] of Object.entries(fields)) if (v) form.append(k, v);
  return api<T>(path, { method: "POST", body: form });
}

export const shortAddr = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;
export const shortHash = (h: string) => `${h.slice(0, 10)}…${h.slice(-8)}`;
export const formatTime = (unix: number) => new Date(unix * 1000).toLocaleString();
export function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
