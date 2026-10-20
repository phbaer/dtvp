import type { ComputedRef, InjectionKey } from 'vue'

export const productPages = [
  { id: 'Overview', tasks: [{ id: 'Statistics', label: 'Statistics' }] },
  { id: 'Vulnerabilities', tasks: [{ id: 'Findings', label: 'Assess and review' }, { id: 'Discovery', label: 'Discover vulnerabilities' }, { id: 'Enrichment', label: 'Enrich vulnerabilities' }, { id: 'Evidence', label: 'Compare evidence' }] },
  { id: 'Components', tasks: [{ id: 'Inventory', label: 'Component inventory' }, { id: 'Tree', label: 'Dependency tree' }] },
  { id: 'Imports', tasks: [{ id: 'Upload', label: 'Upload SBOM' }, { id: 'Assembly', label: 'Assemble SBOMs' }, { id: 'Observations', label: 'Source observations' }, { id: 'Reconciliation', label: 'Reconcile imports' }, { id: 'Quality', label: 'Input quality' }, { id: 'Evidence files', label: 'VDR and VEX files' }] },
  { id: 'Versions', tasks: [{ id: 'Comparison', label: 'Compare versions' }, { id: 'Retained', label: 'Retained assessments' }] },
  { id: 'Licenses', tasks: [{ id: 'Review', label: 'License review' }] },
  { id: 'Documents', tasks: [{ id: 'Documents', label: 'Documents and approvals' }] },
  { id: 'Settings', tasks: [{ id: 'Ownership', label: 'Component ownership' }, { id: 'Sources', label: 'Source connections' }, { id: 'Pipeline', label: 'Pipeline & threat models' }, { id: 'Scoring', label: 'Scoring policy' }, { id: 'Identity', label: 'CPE identity policy' }, { id: 'Automation', label: 'Automation schedules' }, { id: 'Advisories', label: 'Advisory schedules' }, { id: 'Sharing', label: 'Product access' }] },
] as const
export type ProductView = typeof productPages[number]['id']
export type ProductNavigation = { product: string; name: string; view: ProductView; task: string; locked: boolean }
export function productTask(view: ProductView, value?: string | null): string {
  const group = productPages.find(group => group.id === view)!
  return group.tasks.find(task => task.id === value || task.label === value)?.id || group.tasks[0].id
}
export const taskActive: InjectionKey<ComputedRef<boolean>> = Symbol('product task active')
export const taskReady: InjectionKey<ComputedRef<boolean>> = Symbol('product task ready')
