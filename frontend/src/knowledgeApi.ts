import { ApiError } from './api'

/** Presentation transport only; workflow rules and authorization live in v3. */
export async function knowledgeApi<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  const csrf = document.cookie.split('; ').find(item => item.startsWith('dtvp_csrf='))?.split('=')[1]
  if (csrf) headers.set('X-CSRF-Token', decodeURIComponent(csrf))
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')
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
export type KnowledgeFinding = {
  id: string; context_id: string; vulnerability_id: string; state?: string
  component: { name: string; version?: string; purl?: string }
  context: { root_ref?: string; team_id?: string; status?: string; [key: string]: unknown }
  description: string
  source_ratings: { score?: number | null; vector?: string; method?: string; source?: string | { name?: string; url?: string }; observed_source?: string }[]
  coverage: { status: string; assessment?: KnowledgeAssessment | null; approved_assessment?: KnowledgeAssessment | null; [key: string]: unknown }
  published_score: { score: number; vector: string; current?: boolean } | null
  scoring_proposals?: KnowledgeProposal[]
  capabilities: string[]; evidence?: unknown[]; [key: string]: unknown
}
export type KnowledgeWorkspace = { state: string; project_id: string; version: string; items: KnowledgeFinding[]; next_offset: number | null; statistics: { totals: { context_findings: number; unique_vulnerabilities: number }; by_status: Record<string, number>; by_team: Record<string, { context_findings: number; recorded?: number; approved?: number } | number>; severity: Record<string, number>; recorded: number; submitted: number; approved: number } }
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
