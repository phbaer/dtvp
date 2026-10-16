import { ApiError } from './api'

/** Presentation transport only; workflow rules and authorization live in v3. */
export async function knowledgeApi<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  const csrf = document.cookie.split('; ').find(item => item.startsWith('dtvp_csrf='))?.split('=')[1]
  if (csrf) headers.set('X-CSRF-Token', decodeURIComponent(csrf))
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  const response = await fetch(`/api/v3${path}`, { ...options, headers, credentials: 'same-origin' })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new ApiError(response.status, typeof body.detail === 'string' ? body.detail : `Request failed (${response.status})`)
  }
  return response.status === 204 ? undefined as T : response.json()
}
export type KnowledgeAssessment = { revision: string; stage: string; payload: { assessment_id: string; state: string; rationale: string; justification?: string; author_id?: string; conditions?: string; evidence?: unknown[]; targets?: unknown[] } }
export type KnowledgeProposal = {
  id: string; provider: string; source_label: string; current: boolean; eligible: boolean
  ineligibility_reasons: string[]; report_sha256: string
  proposal: { base_score: number; score: number; base_vector: string; vector: string } | null
  score_input: { base_vector: string; vector: string } | null
}
export type KnowledgeCodeAnalysis = {
  id: string; provider: string; source_label: string; current: boolean
  application_eligible: boolean; rescoring_eligible: boolean; proposal_state: string | null
  summary: string; rationale: string; confidence: string; verdict: string
  ineligibility_reasons: string[]; scoring_blockers: string[]
  report_sha256: string; receipt_sha256: string
  provider_claim?: Record<string, unknown>
  provider_authenticity?: string; job_report_association?: string; repository_authorization?: string
  source_receipt?: { state?: string; context_id?: string; assessment_fingerprint?: string }
  source_proof: { target_claim_consistent: boolean; source_commit_consistent: boolean; consistency_only: boolean; source_binding: { status?: string; expected_commit?: string; requested_commit?: string; resolved_commit?: string; reason?: string } }
}
export type KnowledgeFinding = {
  id: string; context_id: string; vulnerability_id: string; state?: string
  component: { name: string; version?: string; purl?: string }
  context: { root_ref?: string; team_id?: string; status?: string; [key: string]: unknown }
  description: string
  source_ratings: { score?: number | null; vector?: string; method?: string; source?: string | { name?: string; url?: string }; observed_source?: string }[]
  coverage: { status: string; assessment?: KnowledgeAssessment | null; approved_assessment?: KnowledgeAssessment | null; [key: string]: unknown }
  published_score: { score: number; vector: string; current?: boolean } | null
  legacy_evidence?: { id: string; source: string; status: string; legacy_format?: string; proposed_applicability: string | null; conflicting: boolean; raw_text?: string; raw_excerpt?: string; errors: string[]; current_records: { team: string; state: string | null; rationale: string; assessor?: string; reviewer?: string; justification?: string; identity_gaps: string[] }[]; records: unknown[]; comments: unknown[]; scoring_proposals: unknown[] }[]
  curated_metadata?: { revision: string; status: string; applicable: boolean; payload: {
    rationale: string; provenance: { source: string; reference: string }
    annotations: { cybersecurity: { criticality: string; exposure: string; mitigations: string[]; testing_evidence: string[] }; deployment: { environment: string; usage: string; configuration: string }; support: { status: string; supplier: string; support_until: string | null; end_of_life: string | null }; notes: string; properties: Record<string, string> }
  } }
  supplemental_component_evidence?: unknown[]
  scoring_proposals?: KnowledgeProposal[]
  code_analysis?: KnowledgeCodeAnalysis[]
  capabilities: string[]; evidence?: unknown[]; [key: string]: unknown
}
export type KnowledgeWorkspace = { team_labels?: Record<string, string>; baseline_status?: 'withdrawn'; state: string; project_id: string; version: string; items: KnowledgeFinding[]; next_offset: number | null; statistics: { retained_absent_assessments?: number; totals: { context_findings: number; unique_vulnerabilities: number }; by_status: Record<string, number>; by_team: Record<string, { context_findings: number; recorded?: number; approved?: number } | number>; severity: Record<string, number>; recorded: number; submitted: number; approved: number } }
export type KnowledgeScoreInput = {
  request_id: string
  expected_versions: Record<string, string>
  targets: { version: string; context_id: string; vulnerability_id: string }[]
  base_vector: string
  vector: string
  rationale: string
}
export type KnowledgeScorePreview = {
  preview: string
  eligible: boolean
  proposal: { base_vector: string; vector: string; score: number; base_score: number; version: string }
  blocked: { version: string; vulnerability_id: string; missing?: { context_id: string; status?: string }[]; unresolved_components?: unknown[]; [key: string]: unknown }[]
}
