import { describe, expect, it } from 'vitest'
import { findingVectors, metricDifference, vectorMetrics, vectorVersion } from './cvssComparison'
import type { KnowledgeFinding } from '../knowledgeApi'
const base='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
describe('CVSS presentation comparison', () => {
  it('preserves Base and reports added modifiers, changed and missing metrics', () => {
    const original=vectorMetrics(base), candidate=vectorMetrics(base+'/MAV:A/CR:L')
    expect(candidate.AV).toBe('N'); expect(candidate.MAV).toBe('A')
    expect(metricDifference(original,candidate,'MAV')).toBe('Added')
    expect(metricDifference(original,{...candidate,AC:'H'},'AC')).toBe('Changed from L')
    expect(metricDifference(candidate,original,'MAV')).toBe('Not supplied')
    expect(metricDifference(original,candidate,'AV')).toBe('')
  })
  it('keeps CVSS methods distinct and recognizes legacy v2 vectors', () => {
    expect(vectorVersion('(AV:N/AC:L/Au:N/C:P/I:P/A:P)')).toBe('2.0')
    expect(vectorVersion(base)).toBe('3.1');expect(vectorVersion(base.replace('3.1','3.0'))).toBe('3.0')
    expect(vectorVersion('CVSS:4.0/AV:N')).toBe('4.0');expect(vectorVersion('unavailable')).toBe('Unknown')
  })
  it('retains differing providers, a zero-score proposal and outdated publication without inventing missing scores', () => {
    const finding={source_ratings:[{source:'NVD',vector:base,score:9.8},{source:'Supplier',vector:base}],scoring_proposals:[{id:'one',provider:'vscorer',source_label:'Threat model',current:false,eligible:false,proposal:{base_vector:base,vector:base+'/MC:N',score:0}}],published_score:{vector:base,score:4.2,current:false}} as KnowledgeFinding
    const entries=findingVectors(finding)
    expect(entries).toHaveLength(4);expect(entries[1]?.score).toBeUndefined();expect(entries[2]?.score).toBe(0)
    expect(entries[2]?.status).toContain('Historical proposal');expect(entries[3]?.status).toBe('Outdated publication')
  })
})
