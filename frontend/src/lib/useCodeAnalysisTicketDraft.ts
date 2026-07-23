import { computed, ref, type ComputedRef, type Ref } from 'vue'
import type { CodeAnalysisAssessResponse, CodeAnalysisResultRecord } from './api'
import { getRuntimeConfig } from './env'

interface TicketDraftContext {
    vulnId: string
    projectName?: string
    cvssVector?: string
}

interface UseCodeAnalysisTicketDraftOptions {
    context: TicketDraftContext
    result: Ref<CodeAnalysisAssessResponse | null>
    hasAffectedResult: ComputedRef<boolean>
    selectedPersistedResult: ComputedRef<CodeAnalysisResultRecord | null>
    selectedComponents: Ref<Set<string>>
    analyzedComponents: Ref<string[]>
    followUpComponent: Ref<string>
    error: Ref<string | null>
}

const uniqueTextValues = (values: Array<string | null | undefined>) => {
    const seen = new Set<string>()
    const result: string[] = []
    for (const value of values) {
        const text = String(value || '').trim()
        const key = text.toLowerCase()
        if (!text || seen.has(key)) continue
        seen.add(key)
        result.push(text)
    }
    return result
}

const ticketBulletList = (values: string[], fallback = 'Not reported') =>
    values.length ? values.map(value => `- ${value}`).join('\n') : `- ${fallback}`

export const stringifyTicketValue = (value: unknown): string => {
    if (value == null || value === '') return ''
    if (typeof value === 'string') return value.trim()
    if (typeof value === 'number' || typeof value === 'boolean') return String(value)
    try {
        return JSON.stringify(value)
    } catch {
        return String(value)
    }
}

const copyTextWithFallback = (text: string) => {
    const textarea = document.createElement('textarea')
    textarea.value = text
    textarea.setAttribute('readonly', 'true')
    textarea.style.position = 'fixed'
    textarea.style.opacity = '0'
    document.body.appendChild(textarea)
    textarea.select()
    const copied = document.execCommand('copy')
    document.body.removeChild(textarea)
    if (!copied) throw new Error('Clipboard copy was not accepted by the browser.')
}

export function useCodeAnalysisTicketDraft({
    context,
    result,
    hasAffectedResult,
    selectedPersistedResult,
    selectedComponents,
    analyzedComponents,
    followUpComponent,
    error,
}: UseCodeAnalysisTicketDraftOptions) {
    const ticketCopyState = ref<'idle' | 'copied' | 'error'>('idle')
    const jiraCreateUrl = getRuntimeConfig('DTVP_JIRA_CREATE_URL', '').trim()

    const ticketContextComponents = computed(() => {
        const rows = selectedPersistedResult.value?.context_summary?.components
        return (Array.isArray(rows) ? rows : [])
            .map((row: Record<string, any>) => {
                const name = stringifyTicketValue(row.component_name)
                const version = stringifyTicketValue(row.component_version)
                const projectVersion = stringifyTicketValue(row.project_version)
                const purl = stringifyTicketValue(row.component_purl)
                const chains = Array.isArray(row.dependency_chains)
                    ? row.dependency_chains.map(stringifyTicketValue).filter(Boolean).slice(0, 2)
                    : []
                return [
                    name ? `${name}${version ? ` ${version}` : ''}` : '',
                    projectVersion ? `project version ${projectVersion}` : '',
                    purl ? `purl ${purl}` : '',
                    chains.length ? `dependency path ${chains.join(' | ')}` : '',
                ].filter(Boolean).join(' - ')
            })
            .filter(Boolean)
            .slice(0, 10)
    })

    const ticketComponents = computed(() => {
        if (!result.value) return []
        return uniqueTextValues([
            ...(result.value.component_results || []).map(entry => entry.component),
            ...analyzedComponents.value,
            followUpComponent.value,
            selectedPersistedResult.value?.component_name,
            ...selectedComponents.value,
        ])
    })

    const ticketText = computed(() => {
        if (!result.value || !hasAffectedResult.value) return ''

        const assessment = result.value.assessment
        const generatedTicket = stringifyTicketValue(assessment.ticket_text)
        if (generatedTicket) return generatedTicket

        const projectName = context.projectName || selectedPersistedResult.value?.project_name || 'the product'
        const components = ticketComponents.value
        const componentLabel = components.length ? components.join(', ') : 'the affected component'
        const versionsChecked = uniqueTextValues(result.value.versions_checked || [])
        const componentResults = (result.value.component_results || []).map(entry => {
            const versions = uniqueTextValues(entry.versions_checked || [])
            const suffix = versions.length ? `, versions ${versions.join(', ')}` : ''
            return `${entry.component}: ${entry.assessment.verdict} (${entry.assessment.confidence} confidence${suffix})`
        })
        const cvss = assessment.adjusted_cvss
        const cvssLines = cvss ? [
            `Original score: ${cvss.original_score}`,
            `Adjusted score: ${cvss.adjusted_score}`,
            cvss.original_vector ? `Original vector: ${cvss.original_vector}` : '',
            cvss.adjusted_vector ? `Adjusted vector: ${cvss.adjusted_vector}` : '',
            cvss.summary ? `CVSS assessment: ${cvss.summary}` : '',
        ].filter(Boolean) : []
        const configuredRemediation = Array.isArray(assessment.remediation_view?.recommendations)
            ? assessment.remediation_view.recommendations.map(stringifyTicketValue).filter(Boolean)
            : []
        const remediation = configuredRemediation.length ? configuredRemediation : [
            `Update the vulnerable dependency to a fixed version or safe range for ${context.vulnId}.`,
            'If the vulnerable dependency is transitive, update or replace the direct parent/intermediary dependency that resolves it, or add an explicit override/exclusion so the vulnerable version is no longer used.',
            'Add component-level validation, configuration guards, or wrappers only when a dependency update is not immediately available or additional mitigation is required.',
        ]

        return [
            `Title: ${context.vulnId} affects ${projectName} via ${componentLabel}`,
            '',
            'Issue',
            `${projectName} was assessed as affected by ${context.vulnId}. The affected target is ${componentLabel}.`,
            '',
            'Analysis',
            `- Verdict: ${assessment.verdict}`,
            `- Confidence: ${assessment.confidence}`,
            `- Exposure: ${assessment.exposure}`,
            `- Summary: ${assessment.summary}`,
            `- Reasoning: ${assessment.reasoning}`,
            `- Versions checked: ${versionsChecked.length ? versionsChecked.join(', ') : 'Not reported'}`,
            ...(context.cvssVector ? [`- Advisory CVSS vector: ${context.cvssVector}`] : []),
            '',
            'Affected Components And Context',
            ticketBulletList(
                ticketContextComponents.value.length ? ticketContextComponents.value : components,
                'No component context was reported',
            ),
            ...(componentResults.length ? ['', 'Component Results', ticketBulletList(componentResults)] : []),
            ...(cvssLines.length ? ['', 'CVSS', ticketBulletList(cvssLines)] : []),
            '',
            'Remediation',
            ticketBulletList(remediation),
            '',
            'Validation',
            `- Rerun the dependency scan and confirm ${context.vulnId} no longer appears for ${projectName}.`,
            '- Rerun the code analysis or equivalent regression tests for the reachable code path described above.',
            '- Attach the updated SBOM/dependency tree and the validation result to this ticket before closure.',
        ].join('\n')
    })

    const copyTicketText = async () => {
        if (!ticketText.value) return
        ticketCopyState.value = 'idle'
        try {
            if (navigator.clipboard?.writeText) {
                await navigator.clipboard.writeText(ticketText.value)
            } else {
                copyTextWithFallback(ticketText.value)
            }
            ticketCopyState.value = 'copied'
            window.setTimeout(() => {
                if (ticketCopyState.value === 'copied') ticketCopyState.value = 'idle'
            }, 2000)
        } catch (err: any) {
            ticketCopyState.value = 'error'
            error.value = err?.message || 'Unable to copy ticket text.'
        }
    }

    const createJiraIssue = async () => {
        if (!ticketText.value || !jiraCreateUrl) return

        let target: URL
        try {
            const baseUrl = window.location.origin === 'null'
                ? 'http://localhost/'
                : `${window.location.origin}/`
            target = new URL(jiraCreateUrl, baseUrl)
            if (!['http:', 'https:'].includes(target.protocol)) {
                throw new Error('Unsupported Jira URL protocol.')
            }
        } catch {
            error.value = 'The configured Jira create URL is invalid.'
            return
        }

        window.open(target.toString(), '_blank', 'noopener,noreferrer')
        await copyTicketText()
    }

    return {
        jiraCreateUrl,
        ticketCopyState,
        ticketText,
        copyTicketText,
        createJiraIssue,
    }
}
