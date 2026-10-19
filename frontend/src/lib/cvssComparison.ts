import type { KnowledgeFinding } from '../knowledgeApi'

export type VectorEntry = { id: string; label: string; vector: string; score?: number | null; status: string; baseVector?: string }
export function vectorVersion(vector: string): string {
  const normalized = vector.trim().replace(/^\(|\)$/g, '')
  return normalized.match(/^CVSS:(2\.0|3\.0|3\.1|4\.0)\//)?.[1] || (/^AV:[NAL]\//.test(normalized) ? '2.0' : 'Unknown')
}
export function vectorMetrics(vector: string): Record<string, string> {
  return Object.fromEntries(vector.trim().replace(/^\(|\)$/g, '').split('/').filter(part => !part.startsWith('CVSS:') && part.includes(':')).map(part => { const i = part.indexOf(':'); return [part.slice(0, i), part.slice(i + 1)] }))
}
export function metricDifference(baseline: Record<string, string>, values: Record<string, string>, key: string): string {
  if (values[key] === baseline[key]) return ''
  if (!values[key]) return 'Not supplied'
  return baseline[key] ? `Changed from ${baseline[key]}` : 'Added'
}
export function findingVectors(finding: KnowledgeFinding): VectorEntry[] {
  const entries: VectorEntry[] = finding.source_ratings.filter(r => r.vector).map((r, i) => ({ id: `source-${i}`, label: (typeof r.source === 'string' ? r.source : r.source?.name || r.source?.url) || r.observed_source || 'Unattributed source', vector: r.vector!, score: r.score, status: 'Source rating' }))
  for (const [i, base] of (finding.original_base_vectors || []).entries()) if (!entries.some(e => e.vector === base.vector)) entries.push({ id: `base-${i}`, label: 'Imported source Base', vector: base.vector, score: base.score, status: 'Original Base' })
  for (const proposal of finding.scoring_proposals || []) if (proposal.proposal) entries.push({ id: `proposal-${proposal.id}`, label: proposal.source_label || proposal.provider, vector: proposal.proposal.vector, score: proposal.proposal.score, baseVector: proposal.proposal.base_vector, status: `${proposal.current ? 'Current' : 'Historical'} proposal · ${proposal.eligible ? 'Available for coordinator preview' : 'Withheld'}` })
  for (const contribution of finding.contributions?.vulnerability_analyses || []) if (contribution.proposal?.vector && !entries.some(e => e.id === `proposal-${contribution.claims.proposal_id}`)) entries.push({ id: `analysis-${contribution.id}`, label: contribution.label || contribution.provider, vector: contribution.proposal.vector, score: contribution.proposal.score, baseVector: contribution.proposal.base_vector, status: `${contribution.current === false ? 'Historical' : 'Received'} proposal · ${contribution.status.replaceAll('_', ' ')}` })
  if (finding.published_score?.vector) entries.push({ id: 'published', label: 'Published contextual score', vector: finding.published_score.vector, score: finding.published_score.score, status: finding.published_score.current === false ? 'Outdated publication' : 'Published' })
  return entries
}
