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
    const verdict = result.assessment.verdict
        .trim()
        .toLowerCase()
        .replaceAll('_', ' ')
        .replaceAll('-', ' ')

    if (verdict === 'not affected' || verdict === 'unaffected' || verdict === 'safe') {
        return {
            targetState: 'NOT_AFFECTED',
            targetJustification: result.assessment.exposure.toLowerCase() === 'none'
                ? 'CODE_NOT_PRESENT'
                : 'CODE_NOT_REACHABLE',
        }
    }

    if (
        verdict.includes('probably affected')
        || verdict.includes('likely affected')
        || verdict.includes('uncertain')
        || verdict.includes('inconclusive')
    ) {
        return {
            targetState: 'IN_TRIAGE',
            targetJustification: 'NOT_SET',
        }
    }

    if (verdict === 'affected' || result.assessment.affected === true) {
        return {
            targetState: 'EXPLOITABLE',
            targetJustification: 'NOT_SET',
        }
    }

    return {
        targetState: 'IN_TRIAGE',
        targetJustification: 'NOT_SET',
    }
}

const getVersionsChecked = (result: CodeAnalysisAssessResponse) => {
    return [...new Set((result.versions_checked || []).filter(Boolean))]
}

const getComponentResults = (result: CodeAnalysisAssessResponse): CodeAnalysisComponentResult[] => {
    const unique = new Map<string, CodeAnalysisComponentResult>()
    for (const componentResult of result.component_results || []) {
        const component = String(componentResult?.component || '').trim()
        if (!component) continue
        unique.set(component.toLocaleLowerCase(), componentResult)
    }
    return [...unique.values()]
}

// Summary and rationale text is produced by the analyzer (normally through its
// LLM pipeline). Keep it verbatim here; presentation code must not silently
// remove evidence with character or item-count limits.
const normalizedText = (value: unknown): string => String(value ?? '').trim()

const asRecord = (value: unknown): Record<string, any> | null => (
    value && typeof value === 'object' && !Array.isArray(value)
        ? value as Record<string, any>
        : null
)

const booleanText = (value: unknown): string => value === true ? 'yes' : value === false ? 'no' : ''

const textList = (value: unknown): string[] => {
    if (!Array.isArray(value)) return []
    return [...new Set(value
        .filter(item => item != null && typeof item !== 'object')
        .map(normalizedText)
        .filter(Boolean))]
}

const uniqueUnseen = (values: string[], seenValues: Set<string>): string[] => values.filter(value => {
    const text = normalizedText(value)
    const signature = text.toLocaleLowerCase()
    if (!text || seenValues.has(signature)) return false
    seenValues.add(signature)
    return true
})

const appendSection = (
    lines: string[],
    seenValues: Set<string>,
    title: string,
    paragraphs: string[] = [],
    bullets: string[] = [],
) => {
    const sectionParagraphs = uniqueUnseen(paragraphs, seenValues)
    const sectionBullets = uniqueUnseen(bullets, seenValues)
    if (!sectionParagraphs.length && !sectionBullets.length) return
    lines.push('', `${title}:`)
    lines.push(...sectionParagraphs)
    lines.push(...sectionBullets.map(value => `  - ${value}`))
}

const generatedReport = (value: unknown): boolean => (
    normalizedText(value).toLocaleUpperCase().includes('VULNERABILITY ASSESSMENT REPORT')
)

const hasSemanticNarrative = (assessment: CodeAnalysisAssessResponse['assessment']): boolean => Boolean(
    normalizedText(assessment.summary)
    || normalizedText(assessment.reasoning)
    || assessment.researcher_view
    || assessment.remediation_view
    || assessment.audit_view
)

const buildCweLines = (assessment: CodeAnalysisAssessResponse['assessment']): string[] => {
    const cweIds = [...new Set((assessment.cwe_ids || []).filter(Boolean))]
    const cweDescriptions = assessment.cwe_descriptions || {}
    const described = cweIds
        .map(cweId => cweDescriptions[cweId] ? `${cweId}: ${cweDescriptions[cweId]}` : cweId)

    const extraDescriptions = Object.entries(cweDescriptions)
        .filter(([cweId]) => !cweIds.includes(cweId))
        .map(([cweId, description]) => `${cweId}: ${description}`)

    const allEntries = [...new Set([...described, ...extraDescriptions])]

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
    const advisorySources = [...new Set((assessment.advisory_sources || []).filter(Boolean))]
    if (advisorySources.length === 0) {
        return []
    }

    return [`Advisory Sources: ${advisorySources.join(', ')}`]
}

const buildAssessmentInformationLines = (
    assessment: CodeAnalysisAssessResponse['assessment'],
    seenValues: Set<string>,
): string[] => {
    const lines: string[] = []

    appendSection(lines, seenValues, 'Assessment mapping', [], [
        `Affected: ${booleanText(assessment.affected)}`,
        assessment.analysis ? `Analyzer state: ${assessment.analysis}` : '',
        assessment.justification ? `Analyzer justification: ${assessment.justification}` : '',
        assessment.response ? `Suggested response: ${assessment.response}` : '',
    ])

    const dependency = asRecord(assessment.dependency_presence)
    if (dependency) {
        const basis = normalizedText(dependency.presence_basis)
        const presence = basis === 'direct'
            ? 'Found as a direct dependency.'
            : basis === 'transitive'
                ? 'Found as a transitive dependency.'
                : basis === 'sbom_attributed' || dependency.sbom_attributed === true
                    ? 'Present via SBOM attribution; not rediscovered in repository manifests or lock files.'
                    : dependency.found === false
                        ? 'The vulnerable component was not found in the assessed project.'
                        : dependency.found === true
                            ? 'The vulnerable component is present in the assessed project.'
                            : ''
        appendSection(lines, seenValues, 'Dependency evidence', [presence], [
            dependency.locked_version ? `Resolved version: ${dependency.locked_version}` : '',
            ...textList(dependency.declared_in).map(value => `Declared in: ${value}`),
        ])
    }

    const advisory = asRecord(assessment.advisory_relevance)
    if (advisory) {
        const status = [
            booleanText(advisory.relevant) && `Relevant: ${booleanText(advisory.relevant)}`,
            booleanText(advisory.applies_to_detected_version) && `Applies to detected version: ${booleanText(advisory.applies_to_detected_version)}`,
            advisory.status && `Status: ${advisory.status}`,
            advisory.source && `Source: ${advisory.source}`,
        ].filter(Boolean).join('; ')
        appendSection(lines, seenValues, 'Advisory relevance', status ? [status] : [], textList(advisory.reasons))
    }

    const version = asRecord(assessment.version_analysis)
    if (version) {
        const status = [
            version.detected_version && `Detected version: ${version.detected_version}`,
            version.version_source && `Source: ${version.version_source}`,
            booleanText(version.affected) && `Affected releases found: ${booleanText(version.affected)}`,
            booleanText(version.current_workspace_affected) && `Current workspace affected: ${booleanText(version.current_workspace_affected)}`,
        ].filter(Boolean).join('; ')
        const affectedProductVersions = textList(version.affected_product_versions)
        appendSection(lines, seenValues, 'Version evidence', [
            status,
            normalizedText(version.note),
            normalizedText(version.workspace_note),
        ], affectedProductVersions.length ? [`Affected product versions: ${affectedProductVersions.join(', ')}`] : [])
    }

    const research = asRecord(assessment.researcher_view)
    if (research) {
        const conclusion = normalizedText(research.conclusion)
        appendSection(
            lines,
            seenValues,
            'Research conclusion',
            conclusion ? [conclusion] : [],
            textList(research.findings),
        )
    }

    const remediation = asRecord(assessment.remediation_view)
    if (remediation) {
        const status = remediation.status ? `Status: ${remediation.status}` : ''
        appendSection(
            lines,
            seenValues,
            'Remediation',
            [status, normalizedText(remediation.summary)],
            textList(remediation.recommendations),
        )
    }

    const audit = asRecord(assessment.audit_view)
    if (audit) {
        const status = [
            audit.status && `Status: ${audit.status}`,
            audit.consistency && `Consistency: ${audit.consistency}`,
        ].filter(Boolean).join('; ')
        appendSection(
            lines,
            seenValues,
            'Audit conclusion',
            [status, normalizedText(audit.conclusion)],
            textList(audit.checks),
        )
    }

    if (
        assessment.details
        && (!generatedReport(assessment.details) || !hasSemanticNarrative(assessment))
    ) {
        appendSection(lines, seenValues, 'Additional analysis', [normalizedText(assessment.details)])
    }
    return lines
}

const buildCvssLines = (
    assessment: CodeAnalysisAssessResponse['assessment'],
): string[] => {
    const cvss = assessment.adjusted_cvss
    if (!cvss) return []
    return [
        '',
        `CVSS: ${cvss.original_score.toFixed(1)} → ${cvss.adjusted_score.toFixed(1)}`,
        ...(cvss.adjusted_vector ? [`Adjusted Vector: ${cvss.adjusted_vector}`] : []),
        ...(cvss.summary ? [`CVSS Summary: ${normalizedText(cvss.summary)}`] : []),
        ...(cvss.reasons.length ? [
            'CVSS Reasons:',
            ...cvss.reasons.map(reason => `  - ${normalizedText(reason)}`),
        ] : []),
    ]
}

const buildComponentSection = (
    componentResult: CodeAnalysisComponentResult,
    seenValues: Set<string>,
): string[] => {
    const versionsChecked = [...new Set((componentResult.versions_checked || []).filter(Boolean))]
    const lines = [
        `[Component: ${componentResult.component}]`,
        `Verdict: ${componentResult.assessment.verdict} (${componentResult.assessment.confidence} confidence)`,
        `Exposure: ${componentResult.assessment.exposure}`,
        ...buildAdvisorySourceLines(componentResult.assessment),
    ]

    appendSection(lines, seenValues, 'Summary', [normalizedText(componentResult.assessment.summary)])
    appendSection(lines, seenValues, 'Rationale', [normalizedText(componentResult.assessment.reasoning)])

    lines.push(...buildAssessmentInformationLines(componentResult.assessment, seenValues))
    lines.push(...buildCweLines(componentResult.assessment))
    lines.push(...buildCvssLines(componentResult.assessment))

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
    const versionsChecked = getVersionsChecked(result)
    const requestedComponents = new Set((components || []).map(component => component.toLowerCase()))
    const allComponentResults = getComponentResults(result)
    const componentResults = allComponentResults
        .filter(componentResult => requestedComponents.size === 0 || requestedComponents.has(componentResult.component.toLowerCase()))
    const scopedToComponents = requestedComponents.size > 0 && allComponentResults.length > 0
    const justificationLine = justification === 'NOT_SET' ? [] : [`Justification: ${justification}`]
    const seenValues = new Set<string>()
    if (!scopedToComponents) {
        seenValues.add(normalizedText(result.assessment.summary).toLocaleLowerCase())
        if (result.assessment.reasoning) {
            seenValues.add(normalizedText(result.assessment.reasoning).toLocaleLowerCase())
        }
    }
    const lines = [
        '[Code Analysis]',
        ...(scopedToComponents ? [`Scope: ${componentResults.map(item => item.component).join(', ') || 'Selected components'}`] : []),
        `Overall Verdict: ${result.assessment.verdict} (${result.assessment.confidence} confidence)`,
        `Exposure: ${result.assessment.exposure}`,
        ...buildAdvisorySourceLines(result.assessment),
        ...justificationLine,
        ...(!scopedToComponents && versionsChecked.length
            ? [
                '',
                'Versions Checked:',
                ...versionsChecked.map(version => `  - ${version}`),
            ]
            : []),
        ...(!scopedToComponents ? ['', 'Summary:', normalizedText(result.assessment.summary)] : []),
        ...(!scopedToComponents && result.assessment.reasoning
            ? ['', 'Rationale:', normalizedText(result.assessment.reasoning)]
            : []),
        ...(!scopedToComponents
            ? buildAssessmentInformationLines(result.assessment, seenValues)
            : []),
        ...(!scopedToComponents ? buildCweLines(result.assessment) : []),
        ...(!scopedToComponents ? buildCvssLines(result.assessment) : []),
        ...(componentResults.length
            ? [
                '',
                'Components:',
                ...componentResults.flatMap(componentResult => [
                    ...buildComponentSection(componentResult, seenValues),
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

    for (const component of [...new Set(components.map(value => value.trim()).filter(Boolean))]) {
        const match = taggedComponents.find(tagged => tagged.name.toLowerCase() === component.toLowerCase())
        if (match) {
            componentTeamMap.set(component, match.tag)
        }
    }

    const teamComponents = new Map<string, string[]>()

    for (const component of componentTeamMap.keys()) {
        const team = componentTeamMap.get(component) || ''
        if (!team) continue

        const teamKey = [...teamComponents.keys()]
            .find(value => value.toLocaleLowerCase() === team.toLocaleLowerCase())
            || team.trim()
        const existing = teamComponents.get(teamKey) || []
        if (!existing.some(value => value.toLowerCase() === component.toLowerCase())) {
            teamComponents.set(teamKey, [...existing, component])
        }
    }

    if (teamComponents.size === 0 && taggedComponents.length > 0) {
        const fallback = taggedComponents[0]
        teamComponents.set(fallback.tag.trim(), [fallback.name])
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

    const selectedDetailsText = teamDrafts[0]?.details ?? detailsText

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
