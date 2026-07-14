const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://127.0.0.1:8000';

export interface HealthResponse {
  status: string;
}

export interface Repo {
  id: string;
  owner: string;
  name: string;
  github_url: string;
  status: 'pending' | 'scanning' | 'done' | 'error';
  finding_count: number;
  created_at: string;
  last_scanned_at?: string;
  ai_reasoning?: string;
  report_signature?: string;
  report_payload?: ReportPayload;
}

export interface CreateRepoResponse extends Repo {
  created: boolean;
}

export interface ReportPayload {
  repo_id: string;
  owner: string;
  name: string;
  github_url: string;
  total_findings: number;
  critical_findings: number;
  generated_at: string;
}

export interface ScanResponse {
  repo_id: string;
  github_url: string;
  total: number;
  ai_reasoning: string;
  critical_alerts_enabled: boolean;
  critical_alert_email_sent: boolean;
  critical_alert_error: string | null;
  critical_findings: number;
  report_payload: ReportPayload;
  report_signature: string;
  owasp_context: string;
}

export interface DeleteRepoResponse {
  deleted: boolean;
  repo_id: string;
  github_url: string;
  owner: string;
  name: string;
}

export interface Finding {
  file_path: string;
  line_number: number;
  secret_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  snippet: string;
  secret_hash: string;
  cluster_id: string | null;
  source_type: 'pattern' | 'entropy' | 'semgrep' | 'trivy';
  rule_id: string;
  rule_name: string;
  owasp_category: string | null;
  vulnerability_description: string | null;
  recommendation: string | null;
  ai_suggested_fix: string | null;
  exposure_days: number;
  exposure_score: number;
  found_in: 'current' | 'history';
  commit_hash: string | null;
  detection_method: string | null;
}

export interface ValidatedFinding {
  id: string;
  scanner: string;
  scanner_rule: string;
  status: 'VALIDATED' | 'NEEDS_REVIEW' | 'REJECTED';
  confidence: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  evidence: string;
  code_snippet: string;
  file: string;
  line: number;
  owasp?: string;
  cwe?: string;
  root_cause: string;
  occurrences: any[];
  recommendation: string;
  supporting_scanners?: string[];
  code_flow?: { file: string; line: number; label: string }[];
  engines?: {
    name: string;
    type: string;
    rule: string;
    query?: string;
    severity: string;
  }[];
  line_range?: string;
}

export interface ValidatedFindingsDataset {
  repo_id: string;
  raw_count: number;
  validated_count: number;
  needs_review_count: number;
  rejected_count: number;
  security_score: number;
  findings: ValidatedFinding[];
  clusters: any[];
}

export interface ScoreResponse {
  repo_id: string;
  security_score: number;
  breakdown: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
}

export interface Cluster {
  id: string;
  secret_hash: string;
  secret_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  repo_count: number;
  created_at: string;
}

export interface VerifyReportRequest {
  report: Record<string, any>;
  signature: string;
}

export interface VerifyReportResponse {
  valid: boolean;
}

export interface PublicKeyResponse {
  public_key_pem: string;
}

export interface SampleSignedReportResponse {
  report: ReportPayload;
  signature: string;
}

export interface SignedReportResponse {
  report: ReportPayload;
  signature: string;
  created_at?: string;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE_URL}${path}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers || {}),
    },
  });

  if (!response.ok) {
    let errorMessage = `HTTP error! status: ${response.status}`;
    try {
      const errorJson = await response.json();
      errorMessage = errorJson.detail || errorMessage;
    } catch {
      // ignore
    }
    throw new Error(errorMessage);
  }

  return response.json() as Promise<T>;
}

export const api = {
  getHealth: () => request<HealthResponse>('/health'),
  
  createRepo: (githubUrl: string) => 
    request<CreateRepoResponse>('/repos', {
      method: 'POST',
      body: JSON.stringify({ github_url: githubUrl }),
    }),
    
  listRepos: () => request<Repo[]>('/repos'),
  
  deleteRepo: (repoId: string) => 
    request<DeleteRepoResponse>(`/repos/${repoId}`, {
      method: 'DELETE',
    }),
    
  scanRepo: (repoId: string) => 
    request<ScanResponse>('/scan', {
      method: 'POST',
      body: JSON.stringify({ repo_id: repoId }),
      // Scan can take a while, Next.js fetch defaults to no timeout but browser fetch respects this
    }),
    
  getFindings: (repoId: string) => request<ValidatedFindingsDataset>(`/findings/${repoId}`),
  
  getScore: (repoId: string) => request<ScoreResponse>(`/repos/${repoId}/score`),
  
  getClusters: () => request<Cluster[]>('/clusters'),
  
  verifyReport: (req: VerifyReportRequest) => 
    request<VerifyReportResponse>('/reports/verify', {
      method: 'POST',
      body: JSON.stringify(req),
    }),
    
  getPublicKey: () => request<PublicKeyResponse>('/reports/public-key'),
  getSampleSignedReport: () => request<SampleSignedReportResponse>('/reports/sample'),
  getSignedReport: (repoId: string) => request<SignedReportResponse>(`/repos/${repoId}/signed-report`),
};
