import type { CodeAnalysisAssessResponse, CodeAnalysisComponentResult } from './api'

export interface CodeAnalysisTaggedComponent {
    name: string
    tag: string
}

export interface CodeAnalysisTeamDraft {
    team: string
    state: string
    details: string
    justification: string
    assigned: string[]
}

export interface PreparedCodeAnalysisResult {
    targetState: string
    targetJustification: string
    detailsText: string
    teamDrafts: CodeAnalysisTeamDraft[]
    firstTeam: string | null
    adjustedVector?: string
    adjustedScore?: number
}

const mapVerdictToAssessment = (result: CodeAnalysisAssessResponse) => {
    const verdict = result.assessment.verdict.toLowerCase()

    if (verdict === 'affected') {
        return {
            targetState: 'EXPLOITABLE',
            targetJustification: 'NOT_SET',
        }
    }

    if (verdict === 'not affected' || verdict === 'not_affected') {
        return {
            targetState: 'NOT_AFFECTED',
            targetJustification: result.assessment.exposure === 'none'
                ? 'CODE_NOT_PRESENT'
                : 'CODE_NOT_REACHABLE',
        }
    }

    return {
        targetState: 'IN_TRIAGE',
        targetJustification: 'NOT_SET',
    }
}

const getVersionsChecked = (result: CodeAnalysisAssessResponse) => {
    return (result.versions_checked || []).filter(Boolean)
}

const getComponentResults = (result: CodeAnalysisAssessResponse): CodeAnalysisComponentResult[] => {
    return (result.component_results || []).filter(componentResult => Boolean(componentResult?.component))
}

const buildCweLines = (assessment: CodeAnalysisAssessResponse['assessment']): string[] => {
    const cweIds = (assessment.cwe_ids || []).filter(Boolean)
    const cweDescriptions = assessment.cwe_descriptions || {}
    const described = cweIds
        .map(cweId => cweDescriptions[cweId] ? `${cweId}: ${cweDescriptions[cweId]}` : cweId)

    const extraDescriptions = Object.entries(cweDescriptions)
        .filter(([cweId]) => !cweIds.includes(cweId))
        .map(([cweId, description]) => `${cweId}: ${description}`)

    const allEntries = [...described, ...extraDescriptions]

    if (allEntries.length === 0) {
        return []
    }

    return [
        '',
        'CWEs:',
        ...allEntries.map(entry => `  - ${entry}`),
    ]
}

const buildAdvisorySourceLines = (assessment: CodeAnalysisAssessResponse['assessment']): string[] => {
    const advisorySources = (assessment.advisory_sources || []).filter(Boolean)
    if (advisorySources.length === 0) {
        return []
    }

    return [`Advisory Sources: ${advisorySources.join(', ')}`]
}

const buildCompactComponentSection = (componentResult: CodeAnalysisComponentResult): string[] => {
    const versionsChecked = (componentResult.versions_checked || []).filter(Boolean)
    const lines = [
        `[Component: ${componentResult.component}]`,
        `Verdict: ${componentResult.assessment.verdict} (${componentResult.assessment.confidence} confidence)`,
        `Exposure: ${componentResult.assessment.exposure}`,
        ...buildAdvisorySourceLines(componentResult.assessment),
        `Summary: ${componentResult.assessment.summary}`,
    ]

    if (componentResult.assessment.reasoning) {
        lines.push(`Reasoning: ${componentResult.assessment.reasoning}`)
    }

    lines.push(...buildCweLines(componentResult.assessment))

    if (versionsChecked.length) {
        lines.push(`Versions: ${versionsChecked.join(', ')}`)
    }

    return lines
}

export const buildCodeAnalysisDetails = (
    result: CodeAnalysisAssessResponse,
    justification: string,
    components?: string[],
): string => {
    const cvss = result.assessment.adjusted_cvss
    const versionsChecked = getVersionsChecked(result)
    const requestedComponents = new Set((components || []).map(component => component.toLowerCase()))
    const componentResults = getComponentResults(result)
        .filter(componentResult => requestedComponents.size === 0 || requestedComponents.has(componentResult.component.toLowerCase()))
    const justificationLine = justification === 'NOT_SET' ? [] : [`Justification: ${justification}`]
    const lines = [
        '[Code Analysis]',
        `Verdict: ${result.assessment.verdict} (${result.assessment.confidence} confidence)`,
        `Exposure: ${result.assessment.exposure}`,
        ...buildAdvisorySourceLines(result.assessment),
        ...justificationLine,
        ...(versionsChecked.length
            ? [
                '',
                'Versions Checked:',
                ...versionsChecked.map(version => `  - ${version}`),
            ]
            : []),
        '',
        `Summary: ${result.assessment.summary}`,
        ...(result.assessment.reasoning
            ? ['', `Reasoning: ${result.assessment.reasoning}`]
            : []),
        ...buildCweLines(result.assessment),
        ...(cvss
            ? [
                '',
                `[Rescored: ${cvss.adjusted_score}]`,
                ...(cvss.adjusted_vector ? [`[Rescored Vector: ${cvss.adjusted_vector}]`] : []),
                `CVSS: ${cvss.original_score} → ${cvss.adjusted_score}`,
                ...(cvss.adjusted_vector ? [`Adjusted Vector: ${cvss.adjusted_vector}`] : []),
                ...(cvss.summary ? [`CVSS Summary: ${cvss.summary}`] : []),
                ...(cvss.reasons.length ? [`CVSS Reasons: ${cvss.reasons.join('; ')}`] : []),
            ]
            : []),
        ...(componentResults.length
            ? [
                '',
                'Components:',
                ...componentResults.flatMap(componentResult => [
                    ...buildCompactComponentSection(componentResult),
                    '',
                ]),
            ]
            : []),
    ]

    while (lines.length > 0 && lines.at(-1) === '') {
        lines.pop()
    }

    return lines.join('\n')
}

const groupComponentsByTeam = (
    components: string[],
    taggedComponents: CodeAnalysisTaggedComponent[],
) => {
    const componentTeamMap = new Map<string, string>()

    for (const component of components) {
        const match = taggedComponents.find(tagged => tagged.name.toLowerCase() === component.toLowerCase())
        if (match) {
            componentTeamMap.set(component, match.tag)
        }
    }

    const teamComponents = new Map<string, string[]>()

    for (const component of components) {
        const team = componentTeamMap.get(component) || ''
        if (!team) continue

        const existing = teamComponents.get(team) || []
        teamComponents.set(team, [...existing, component])
    }

    if (teamComponents.size === 0 && taggedComponents.length > 0) {
        const fallback = taggedComponents[0]
        teamComponents.set(fallback.tag, [fallback.name])
    }

    return teamComponents
}

export const prepareCodeAnalysisResult = (
    result: CodeAnalysisAssessResponse,
    components: string[],
    taggedComponents: CodeAnalysisTaggedComponent[],
    assignedUsers: string[],
): PreparedCodeAnalysisResult => {
    const { targetState, targetJustification } = mapVerdictToAssessment(result)
    const detailsText = buildCodeAnalysisDetails(result, targetJustification)
    const teamComponents = groupComponentsByTeam(components, taggedComponents)
    const teamDrafts = [...teamComponents.entries()].map(([team, teamComponentList]) => ({
        team,
        state: targetState,
        details: buildCodeAnalysisDetails(result, targetJustification, teamComponentList),
        justification: targetJustification,
        assigned: [...assignedUsers],
    }))

    const selectedDetailsText = teamDrafts.length === 1
        ? teamDrafts[0].details
        : detailsText

    return {
        targetState,
        targetJustification,
        detailsText: selectedDetailsText,
        teamDrafts,
        firstTeam: teamDrafts[0]?.team ?? null,
        adjustedVector: result.assessment.adjusted_cvss?.adjusted_vector,
        adjustedScore: result.assessment.adjusted_cvss?.adjusted_score,
    }
}