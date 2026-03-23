<script setup lang="ts">
import { ref, computed, watch, inject, onMounted, onUnmounted } from 'vue'
import { updateAssessment, getAssessmentDetails } from '../lib/api'

import type { GroupedVuln, AssessmentPayload } from '../types'
import { ChevronDown, ChevronUp, Shield, RefreshCw, AlertTriangle, Calculator, ExternalLink, CheckCircle, RotateCcw, History } from 'lucide-vue-next'

import { parseAssessmentBlocks, mergeTeamAssessment, constructAssessmentDetails, getConsensusAssessment, parseJustificationFromText, hasGlobalAssessment, getAssessedTeams, isPendingReview as isPendingReviewHelper, getGroupLifecycle, getGroupTechnicalState, tagToString, STATE_PRIORITY, type AssessmentBlock } from '../lib/assessment-helpers'
import { calculateScoreFromVector } from '../lib/cvss'
import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'
import CvssCalculatorV2 from './CvssCalculatorV2.vue'
import CvssCalculatorV3 from './CvssCalculatorV3.vue'
import CvssCalculatorV4 from './CvssCalculatorV4.vue'
import DependencyChainViewer from './DependencyChainViewer.vue'


const props = defineProps<{
  group: GroupedVuln
}>()

const handleCloseOnEscape = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
        if (genericModal.value.show) {
            handleModalResponse(false)
        } else if (showConflictModal.value) {
            showConflictModal.value = false
        } else if (showCalculatorModal.value) {
            showCalculatorModal.value = false
        }
    }
}

onMounted(() => {
    window.addEventListener('keydown', handleCloseOnEscape)
})

onUnmounted(() => {
    window.removeEventListener('keydown', handleCloseOnEscape)
})

const user = inject<any>('user', ref({ role: 'ANALYST' }))
const teamMapping = inject<any>('teamMapping', ref({}))
const rescoreRules = inject<any>('rescoreRules', ref({ transitions: [] }))

const emit = defineEmits(['update', 'update:assessment', 'toggle-expand'])

const ANALYSIS_STATES = [
    { value: 'NOT_SET', label: 'Not Set', description: 'No analysis has been performed yet.' },
    { value: 'NOT_AFFECTED', label: 'Not Affected', description: 'The component is not affected by this vulnerability.' },
    { value: 'EXPLOITABLE', label: 'Exploitable', description: 'The vulnerability is exploitable in this component.' },
    { value: 'IN_TRIAGE', label: 'In Triage', description: 'The vulnerability is currently being investigated.' },
    { value: 'FALSE_POSITIVE', label: 'False Positive', description: 'This finding is a false positive.' },
    { value: 'RESOLVED', label: 'Resolved', description: 'The vulnerability has been resolved or mitigated.' },
]

const JUSTIFICATION_OPTIONS = [
    { value: 'NOT_SET', label: 'Not Set', description: 'No justification provided.' },
    { value: 'CODE_NOT_PRESENT', label: 'Code Not Present', description: 'The vulnerable code is not present in the component.' },
    { value: 'CODE_NOT_REACHABLE', label: 'Code Not Reachable', description: 'The vulnerable code is present but not reachable.' },
    { value: 'REQUIRES_CONFIGURATION', label: 'Requires Configuration', description: 'Exploitation requires a specific non-default configuration.' },
    { value: 'REQUIRES_DEPENDENCY', label: 'Requires Dependency', description: 'Exploitation requires an additional dependency not present.' },
    { value: 'REQUIRES_ENVIRONMENT', label: 'Requires Environment', description: 'Exploitation requires a specific environment.' },
    { value: 'PROTECTED_BY_COMPILER', label: 'Protected by Compiler', description: 'Protected by compiler-level security features.' },
    { value: 'PROTECTED_AT_RUNTIME', label: 'Protected at Runtime', description: 'Protected by runtime mitigation (e.g., ASLR, DEP).' },
    { value: 'PROTECTED_AT_PERIMETER', label: 'Protected at Perimeter', description: 'Protected by network or perimeter security controls.' },
    { value: 'PROTECTED_BY_MITIGATING_CONTROL', label: 'Protected by Mitigating Control', description: 'Protected by other mitigating controls.' },
]

const expanded = ref(false)
const state = ref('NOT_SET')
const details = ref('')
const justification = ref('NOT_SET')
const comment = ref('')
const suppressed = ref(false)
const selectedTeam = ref('')
// Removed onlyTargetSelectedTeam - team selection now automatically targets team instances
const updating = ref(false)
const loadingDetails = ref(false)
const showCalculatorModal = ref(false)
const showConflictModal = ref(false)
const conflictData = ref<any>(null)
const originalAnalysis = ref<Record<string, any>>({}) // Map finding_uuid -> Analysis Object
const showAuditLog = ref(false)
const refreshCounter = ref(0)
const formTouched = ref(false)
const isInternalUpdate = ref(false)

const pendingScore = ref<number | null>(null)
const pendingVector = ref<string>('')
const activeVersion = ref<'4.0' | '3.1' | '3.0' | '2.0'>('3.1')
const cvssInstance = ref<any>(null)
const isManualBaseMode = ref(false)
const initialVector = ref('')
const initialScore = ref<number | null>(null)

const genericModal = ref({
    show: false,
    title: '',
    message: '',
    confirmOnly: false,
    resolve: (_: boolean) => {}
})

const promptConfirm = (title: string, message: string, confirmOnly = false) => {
    genericModal.value = {
        show: true,
        title,
        message,
        confirmOnly,
        resolve: () => {}
    }
    return new Promise<boolean>((resolve) => {
        genericModal.value.resolve = resolve
    })
}

const showAlert = (title: string, message: string) => promptConfirm(title, message, true)

const handleModalResponse = (value: boolean) => {
    genericModal.value.show = false
    genericModal.value.resolve(value)
}

const isReviewer = computed(() => {
    return user?.value?.role === 'REVIEWER'
})

const allInstances = computed(() => {
    // Force reactivity on refresh
    refreshCounter.value
    return props.group.affected_versions?.flatMap(v => v.components) || []
})

const totalTargeted = computed(() => {
    // When a team is selected, automatically target only that team's instances
    if (selectedTeam.value) {
        return allInstances.value.filter(inst => inst.tags && inst.tags.includes(selectedTeam.value)).length
    }
    return allInstances.value.length
})

const displayState = computed(() => {
    return getGroupLifecycle(props.group, props.group.tags || [], teamMapping?.value)
})

const technicalState = computed(() => {
    return getGroupTechnicalState(props.group)
})

const consensusButtonLabel = computed(() => {
    return displayState.value === 'INCOMPLETE' ? 'Sync all' : 'Apply worst assessment'

})

const isAssessed = computed(() => {
    return hasGlobalAssessment(mergedAssessmentData.value.blocks) && !isPendingReview.value
})

const isPendingReview = computed(() => {
    return isPendingReviewHelper(props.group)
})

const canApprove = computed(() => {
    return user?.value?.role === 'REVIEWER' && isPendingReview.value
})

const lastRescoredScore = ref<number | null>(null)

const currentDisplayScore = computed(() => {
    if (pendingScore.value !== null) return pendingScore.value
    return props.group.rescored_cvss ?? (props.group.cvss || props.group.cvss_score) ?? 'N/A'
})

const isRescoredOrModified = computed(() => {
    const base = props.group.cvss || props.group.cvss_score
    const current = currentDisplayScore.value
    if (current === 'N/A' || base === undefined) return false
    return Math.abs(Number(current) - Number(base)) > 0.05
})

const approveAssessment = async (e: Event) => {
    e.stopPropagation() // Prevent card expansion
    if (!await promptConfirm('Approve Assessment', 'Approve this assessment? This will remove the pending status.')) return

    // Get current details from first instance (assuming grouped logic holds)
    const first = allInstances.value[0]
    if (!first) return
    
    // We update using the existing handleUpdate but need to make sure state is set correctly first
    // Since details.value is reactive, handleUpdate will pick it up
    updating.value = true
    try {
        await handleUpdate(true, true) // force=true, isApprove=true
    } finally {
        updating.value = false
    }
}



watch([showCalculatorModal, pendingVector], () => {
    if (showCalculatorModal.value) {
        let v = pendingVector.value?.trim() || ''
        try {
            if (v.startsWith('CVSS:4.0')) {
                activeVersion.value = '4.0'
                cvssInstance.value = new Cvss4P0(v)
            } else if (v.startsWith('CVSS:3.')) {
                activeVersion.value = '3.1'
                if (v.startsWith('CVSS:3.0')) v = v.replace('CVSS:3.0', 'CVSS:3.1')
                cvssInstance.value = new Cvss3P1(v)
            } else if (v.startsWith('CVSS:2.0') || (v.includes('/') && !v.startsWith('CVSS:'))) {
                activeVersion.value = '2.0'
                cvssInstance.value = new Cvss2(v)
            } else {
                activeVersion.value = '3.1'
                cvssInstance.value = new Cvss3P1()
            }
        } catch {
             const fallback = visibleVersions.value[0] || '3.1'
             activeVersion.value = fallback as any
             resetToDefault(fallback)
        }
    }
})

const visibleVersions = computed(() => {
    const v = pendingVector.value || ''
    if (v.startsWith('CVSS:4.0')) return ['4.0']
    if (v.startsWith('CVSS:3.1')) return ['3.1']
    if (v.startsWith('CVSS:3.0')) return ['3.0']
    if (v.startsWith('CVSS:2.0') || (v.includes('/') && !v.startsWith('CVSS:'))) return ['2.0']
    return ['4.0', '3.1', '3.0', '2.0']
})

const switchVersion = (ver: '4.0' | '3.1' | '3.0' | '2.0') => {
    activeVersion.value = ver
    resetToDefault(ver)
}

const resetToDefault = (ver: string) => {
    switch(ver) {
        case '4.0': cvssInstance.value = new Cvss4P0('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N'); break;
        case '3.1': cvssInstance.value = new Cvss3P1('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'); break;
        case '3.0': cvssInstance.value = new Cvss3P0('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'); break;
        case '2.0': cvssInstance.value = new Cvss2('AV:N/AC:L/Au:N/C:N/I:N/A:N'); break;
    }
    updateVectorString()
}

const updateVectorString = () => {
    const raw = cvssInstance.value.toString()
    pendingVector.value = raw.split('/').filter((part: string) => !part.endsWith(':X')).join('/')
}

const updateCalcVector = (componentShortName: string, value: string) => {
    try {
        cvssInstance.value.applyComponentString(componentShortName, value)
        updateVectorString()
        cvssInstance.value = cvssInstance.value 
    } catch (e) {
        console.error(e)
    }
}

const canEditBase = computed(() => {
    if (!isReviewer.value) return false
    
    // If a rescore rule matches the current state, we don't allow manual editing
    // unless the user explicitly cleared/reset it.
    const rules = rescoreRules?.value?.transitions || []
    const hasRuleMatch = rules.some((r: any) => r.trigger.state === state.value)
    
    if (hasRuleMatch && !isManualBaseMode.value) return false
    
    // Explicitly unlocked via Clear
    if (isManualBaseMode.value) return true
    
    // Otherwise, stay read-only
    return false
})

const resetVector = () => {
    isManualBaseMode.value = false
    // Reset to the ORIGINAL baseline from Dependency-Track
    const original = props.group.cvss_vector
    if (original) {
        pendingVector.value = original
        try {
             if (original.startsWith('CVSS:4.0')) {
                 activeVersion.value = '4.0'
                 cvssInstance.value = new Cvss4P0(original)
             } else if (original.includes('3.0')) {
                  activeVersion.value = '3.0'
                  cvssInstance.value = new Cvss3P0(original)
             } else if (original.startsWith('CVSS:3.')) {
                  activeVersion.value = '3.1'
                  cvssInstance.value = new Cvss3P1(original)
             } else {
                 activeVersion.value = '2.0'
                 cvssInstance.value = new Cvss2(original)
             }
        } catch {}
        updateVectorString()
    } else {
        resetToDefault(activeVersion.value)
    }
}

const clearVector = () => {
    isManualBaseMode.value = true
    resetToDefault(activeVersion.value)
    pendingVector.value = ''
}

watch(pendingVector, (newVector) => {
    const score = calculateScoreFromVector(newVector)
    if (score !== null) {
        pendingScore.value = score
    }
})

const mergedAssessmentData = computed(() => {
    // Force reactivity when details are refreshed
    refreshCounter.value 
    
    const allBlocks: AssessmentBlock[] = []
    const teamToIndex = new Map<string, number>()
    const allTags = new Set<string>()
    let isPendingValue = false
    
    for (const inst of allInstances.value) {
        const instDetails = (inst as any).analysis_details || (inst as any).analysisDetails || ''
        if (!instDetails) continue
        
        if ((inst as any).analysis_details?.includes('[Status: Pending Review]') || (inst as any).analysisDetails?.includes('[Status: Pending Review]')) {
            isPendingValue = true
        }

        const blocks = parseAssessmentBlocks(instDetails)
        for (const block of blocks) {
            const teamName = block.team
            const existingIndex = teamToIndex.get(teamName)
            
            if (existingIndex === undefined) {
                teamToIndex.set(teamName, allBlocks.length)
                allBlocks.push(block)
            } else {
                const existingBlock = allBlocks[existingIndex]
                if (existingBlock) {
                    const currentTimestamp = (existingBlock.timestamp as number) || 0
                    const newTimestamp = (block.timestamp as number) || 0
                    
                    if (newTimestamp > currentTimestamp) {
                        allBlocks[existingIndex] = block
                    } else if (newTimestamp === currentTimestamp) {
                        if ((block.details?.length || 0) > (existingBlock.details?.length || 0)) {
                            allBlocks[existingIndex] = block
                        }
                    }
                }
            }
        }
        
        const rescoredMatch = instDetails.match(/\[Rescored:\s*[\d\.]+\]/);
        if (rescoredMatch) allTags.add(rescoredMatch[0]);

    }
    
    return {
        blocks: allBlocks,
        fullText: allBlocks.length > 0 ? constructAssessmentDetails(allBlocks, Array.from(allTags), isPendingValue).text : '',
        isPending: isPendingValue
    }
})

// [Persistence Debug] Watch state and details for changes
watch(state, (val, old) => {
    if (!isInternalUpdate.value && val !== old) {
        formTouched.value = true
        if (window.localStorage?.getItem?.('dtvp_debug_persistence') === 'true') {
            console.log('[Persistence Debug] state touched by user:', val);
        }
    }
})
watch(details, (val, old) => {
    if (!isInternalUpdate.value && val !== old) {
        formTouched.value = true
        if (window.localStorage?.getItem?.('dtvp_debug_persistence') === 'true') {
            console.log('[Persistence Debug] details touched by user:', val.slice(0, 50) + '...');
        }
    }
})

const groupedAssessments = computed(() => {
    const groups: Map<string, {
        state: string,
        details: string,
        isSuppressed: boolean,
        comments: any[],
        instances: {
            project_name: string,
            project_version: string,
            component_name: string,
            component_version: string,
            component_uuid: string,
            project_uuid: string
        }[]
    }> = new Map()

    props.group.affected_versions.forEach(v => {
        v.components.forEach(c => {
            const stateVal = c.analysis_state || 'NOT_SET'
            const detailsVal = c.analysis_details || ''
            const suppressedVal = !!c.is_suppressed
            
            // Key for grouping
            const key = `${stateVal}|${detailsVal}|${suppressedVal}`
            
            if (!groups.has(key)) {
                groups.set(key, {
                    state: stateVal,
                    details: detailsVal,
                    isSuppressed: suppressedVal,
                    comments: [],
                    instances: []
                })
            }
            
            const groupItem = groups.get(key)!;
            
            // Add unique comments
            (c.analysis_comments || []).forEach((comm: any) => {
                const isDuplicate = groupItem.comments.some((gc: any) => 
                    gc.comment === comm.comment && 
                    gc.timestamp === comm.timestamp
                )
                if (!isDuplicate) {
                    groupItem.comments.push(comm)
                }
            })

            groupItem.instances.push({
                project_name: v.project_name,
                project_version: v.project_version,
                component_name: c.component_name,
                component_version: c.component_version,
                component_uuid: c.component_uuid,
                project_uuid: v.project_uuid
            })
        })
    })

    return Array.from(groups.values())
})

const updateFormFromGroup = (force = true) => {
    // If not forced and user has touched the form, don't overwrite
    if (!force && formTouched.value) {
        if (window.localStorage?.getItem?.('dtvp_debug_persistence') === 'true') {
            console.log('[Persistence Debug] updateFormFromGroup blocked by formTouched');
        }
        return
    }

    isInternalUpdate.value = true
    try {
        pendingScore.value = props.group.rescored_cvss ?? props.group.cvss_score ?? props.group.cvss ?? null
        pendingVector.value = props.group.rescored_vector || props.group.cvss_vector || ''
        
        const teamBlocks = mergedAssessmentData.value.blocks
        
        if (selectedTeam.value) { // Team view
            const teamName = selectedTeam.value
            const myBlock = teamBlocks.find(b => b.team === teamName)
            
            state.value = myBlock?.state || 'NOT_SET'
            // Strip the status tag from the details shown in the textarea
            details.value = (myBlock?.details || '').replace(/\n\n\[Status: Pending Review\]/g, '').replace(/\[Status: Pending Review\]/g, '')
            justification.value = myBlock?.justification || 'NOT_SET'
        } else {
             // No team selected - if Reviewer, show General block
             if (isReviewer.value) {
                const generalBlock = teamBlocks.find(b => b.team === 'General')
                if (generalBlock && generalBlock.state !== 'NOT_SET') {
                    state.value = generalBlock.state || 'NOT_SET'
                    details.value = (generalBlock.details || '').replace(/\n\n\[Status: Pending Review\]/g, '').replace(/\[Status: Pending Review\]/g, '')
                    justification.value = generalBlock.justification || 'NOT_SET'
                } else {
                    const dtCandidates = allInstances.value
                        .map(i => {
                            const rawState = i.analysis_state || i.analysisState || 'NOT_SET'
                            const rawDetails = (i as any).analysis_details || (i as any).analysisDetails || ''
                            const rawJust = (i as any).justification || (i as any).analysisJustification
                            const parsedJust = parseJustificationFromText(rawDetails)
                            return {
                                state: rawState,
                                justification: rawJust || parsedJust || 'NOT_SET',
                                details: rawDetails
                            }
                        })
                        .filter(i => i.state && i.state !== 'NOT_SET')

                    const dtWorstCandidate = dtCandidates
                        .sort((a, b) => (STATE_PRIORITY[a.state] ?? 10) - (STATE_PRIORITY[b.state] ?? 10))[0]

                    if (dtWorstCandidate) {
                        state.value = dtWorstCandidate.state
                        details.value = dtWorstCandidate.details.replace(/\n\n\[Status: Pending Review\]/g, '').replace(/\[Status: Pending Review\]/g, '')

                        let resolvedJustification = dtWorstCandidate.justification && dtWorstCandidate.justification !== 'NOT_SET'
                            ? dtWorstCandidate.justification
                            : undefined

                        if (!resolvedJustification) {
                            resolvedJustification = dtCandidates.find(c => c.state === dtWorstCandidate.state && c.justification && c.justification !== 'NOT_SET')?.justification
                        }

                        if (!resolvedJustification) {
                            resolvedJustification = parseJustificationFromText(dtWorstCandidate.details)
                        }

                        justification.value = resolvedJustification || 'NOT_SET'
                    } else if (generalBlock) {
                        state.value = generalBlock.state || 'NOT_SET'
                        details.value = (generalBlock.details || '').replace(/\n\n\[Status: Pending Review\]/g, '').replace(/\[Status: Pending Review\]/g, '')
                        justification.value = generalBlock.justification || 'NOT_SET'
                    } else {
                        state.value = 'NOT_SET'
                        details.value = ''
                        justification.value = 'NOT_SET'
                    }
                }
             } else {
                state.value = 'NOT_SET'
                details.value = ''
                justification.value = 'NOT_SET'
             }
        }
        
        comment.value = ''
        
        const firstSuppressed = allInstances.value.find(i => i.is_suppressed)
        suppressed.value = firstSuppressed ? true : false

        // Set initial values for "touched" check
        initialVector.value = pendingVector.value
        initialScore.value = pendingScore.value

        if (force) formTouched.value = false
    } finally {
        isInternalUpdate.value = false
    }
}

const applyConsensusAssessment = () => {
    const allBlocks = mergedAssessmentData.value.blocks
    
    if (allBlocks.length === 0) {
        showAlert('No Analysis Data', 'No assessments found to pull from.')
        return
    }

    // Derive the authoritative Dependency Track state (worst state across instances)
    const dtCandidates = allInstances.value
        .map(i => {
            const rawState = i.analysis_state || i.analysisState || 'NOT_SET'
            const rawDetails = (i as any).analysis_details || (i as any).analysisDetails || ''
            const rawJustification = (i as any).justification || (i as any).analysisJustification
            const parsedJustification = parseJustificationFromText(rawDetails)

            return {
                state: rawState,
                justification: rawJustification || parsedJustification || 'NOT_SET',
                details: rawDetails
            }
        })
        .filter(i => i.state && i.state !== 'NOT_SET')

    const dtWorstCandidate = dtCandidates
        .sort((a, b) => (STATE_PRIORITY[a.state] ?? 10) - (STATE_PRIORITY[b.state] ?? 10))[0]

    const dtStates = dtCandidates.map(i => i.state)
    let dtJustification = dtWorstCandidate ? dtWorstCandidate.justification : undefined

    // If DT provides a state but no explicit justification, try to extract it from the structured details
    // or from another same-state DT candidate, then fallback to parsing from the block.
    if (dtWorstCandidate && (!dtJustification || dtJustification === 'NOT_SET')) {
        const sameStateCandidateJustification = dtCandidates.find(
            c => c.state === dtWorstCandidate.state && c.justification && c.justification !== 'NOT_SET'
        )?.justification

        if (sameStateCandidateJustification) {
            dtJustification = sameStateCandidateJustification
        } else {
            const blocks = parseAssessmentBlocks(dtWorstCandidate.details)
            const matching = blocks.find(
                b => b.state === dtWorstCandidate.state && b.justification && b.justification !== 'NOT_SET'
            )
            if (matching) {
                dtJustification = matching.justification
            } else {
                const parsed = parseJustificationFromText(dtWorstCandidate.details)
                if (parsed) dtJustification = parsed
            }

            if ((!dtJustification || dtJustification === 'NOT_SET') && dtCandidates) {
                const fallbackCandidate = dtCandidates.find(
                    c => c.state === dtWorstCandidate.state && c.justification && c.justification !== 'NOT_SET'
                )
                if (fallbackCandidate) {
                    dtJustification = fallbackCandidate.justification
                }
            }
        }
    }

    const consensus = getConsensusAssessment(allBlocks, displayState.value as string, dtStates, dtJustification)
    state.value = consensus.state
    justification.value = consensus.justification
    details.value = consensus.details

    // Always trigger a rescore for the resolved state, even if state.value
    // didn't change (the watcher's newState !== oldState guard would skip it).
    if (isReviewer.value) {
        applyStateRescore(consensus.state)
    }
}

watch(selectedTeam, () => {
    updateFormFromGroup()
})

watch(() => props.group, () => updateFormFromGroup(true), { immediate: true })


watch(expanded, (isOpen) => {
    emit('toggle-expand', props.group.id, isOpen)
    if (isOpen) {
        refreshDetails()
    }
})
/**
 * Applies the configured rescore rules for a given state.
 * Extracted so it can be triggered explicitly (e.g. from applyConsensusAssessment)
 * without relying solely on the watch(state) guard.
 */
const applyStateRescore = (targetState: string) => {
    const rules = rescoreRules?.value?.transitions || []
    const triggerMatch = rules.find((r: any) => r.trigger.state === targetState)

    if (!triggerMatch) return

    const actions = triggerMatch.actions?.[activeVersion.value] || {}

    // Create a fresh CVSS instance from the pending vector
    let v = pendingVector.value?.trim() || ''
    try {
        if (v.startsWith('CVSS:4.0')) {
            cvssInstance.value = new Cvss4P0(v)
        } else if (v.startsWith('CVSS:3.')) {
            if (v.startsWith('CVSS:3.0')) v = v.replace('CVSS:3.0', 'CVSS:3.1')
            cvssInstance.value = new Cvss3P1(v)
        } else if (v.startsWith('CVSS:2.0') || (v.includes('/') && !v.startsWith('CVSS:'))) {
            cvssInstance.value = new Cvss2(v)
        } else {
            if (activeVersion.value === '4.0') {
                cvssInstance.value = new Cvss4P0('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N')
            } else if (activeVersion.value === '2.0') {
                cvssInstance.value = new Cvss2('AV:N/AC:L/Au:N/C:N/I:N/A:N')
            } else {
                cvssInstance.value = new Cvss3P1('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N')
                activeVersion.value = '3.1'
            }
        }
    } catch {}

    // Apply each configured modifier
    for (const [key, val] of Object.entries(actions)) {
        try {
            const vectorParts = (pendingVector.value || '').split('/')
            const isV4 = pendingVector.value && pendingVector.value.startsWith('CVSS:4.0');

            const isModifiedMetric = key.startsWith('M') && key.length > 1;
            const isRequirementMetric = key === 'CR' || key === 'IR' || key === 'AR';

            let baseKey = key;
            if (isModifiedMetric) {
                baseKey = key.slice(1);
            } else if (isRequirementMetric) {
                baseKey = isV4 ? 'V' + key.charAt(0) : key.charAt(0);
            }

            const basePart = vectorParts.find(part => part.startsWith(`${baseKey}:`));
            const baseValue = basePart ? basePart.split(':')[1] : null;
            const isDefined = baseValue && baseValue !== 'X';

            if (isModifiedMetric) {
                const isSameAsBase = baseValue === val;
                if (isDefined && !isSameAsBase) {
                    cvssInstance.value.applyComponentString(key, val as string)
                }
            } else if (isRequirementMetric) {
                const modKey = 'M' + baseKey;
                const modValFromActions = (actions as Record<string, unknown>)[modKey] as string | undefined;

                let currentModVal = null;
                if (modValFromActions !== undefined) {
                    currentModVal = modValFromActions;
                } else {
                    const currentModPart = vectorParts.find(part => part.startsWith(`${modKey}:`));
                    currentModVal = currentModPart ? currentModPart.split(':')[1] : null;
                }

                const finalModVal = (currentModVal && currentModVal !== 'X') ? currentModVal : baseValue;
                const isSameAsBase = baseValue === finalModVal;

                if (isDefined && !isSameAsBase) {
                    cvssInstance.value.applyComponentString(key, val as string)
                }
            } else {
                cvssInstance.value.applyComponentString(key, val as string)
            }
        } catch (e) {
            console.error("Failed to apply component string:", key, val, e)
        }
    }
    updateVectorString()
}

watch(state, (newState, oldState) => {
    // Only auto-rescore if we're changing states via user interaction.
    // We check `loadingDetails` to avoid rescoring during the initial data load.
    // Note: applyConsensusAssessment calls applyStateRescore() directly to
    // bypass the newState !== oldState guard when syncing.
    if (!loadingDetails.value && !updating.value && newState !== oldState && isReviewer.value) {
        applyStateRescore(newState)
    }
})

const refreshDetails = async () => {
    loadingDetails.value = true
    try {
        const instances = allInstances.value
        // Only fetch if we have instances
        if (instances.length === 0) return

        const detailsList = await getAssessmentDetails(instances)
        
        if (!detailsList) {
            console.error('Failed to fetch assessment details: getAssessmentDetails returned undefined')
            return
        }
        
        // Update local state and originalAnalysis map
        const newOriginals: Record<string, any> = {}
        
        for (const item of detailsList) {
             if (item.error) {
                 console.error(`Error fetching details for ${item.finding_uuid}:`, item.error)
                 await showAlert('Update Failed', `Failed to refresh details for a component: ${item.error}`)
                 continue
             }
             
             if (item.analysis) {
                 // Store original for conflict checking
                 if (item.finding_uuid) {
                     newOriginals[item.finding_uuid] = item.analysis
                 }
                 
                 // Update the reactive object in the group
                 const targetProj = item.project_uuid
                 const targetComp = item.component_uuid
                 const targetVuln = item.vulnerability_uuid

                 props.group.affected_versions.forEach(v => {
                     if (v.project_uuid !== targetProj) return
                     
                     v.components.forEach(c => {
                         if (c.component_uuid === targetComp && c.vulnerability_uuid === targetVuln) {
                             c.analysis_state = item.analysis.analysisState || item.analysis.analysis_state
                             c.analysis_details = item.analysis.analysisDetails || item.analysis.analysis_details
                             c.is_suppressed = item.analysis.isSuppressed || item.analysis.is_suppressed
                             c.justification = item.analysis.analysisJustification || item.analysis.justification || parseJustificationFromText(item.analysis.analysisDetails || item.analysis.analysis_details || '') || 'NOT_SET'
                             const comments = item.analysis.analysisComments || item.analysis.analysis_comments
                             if (comments) {
                                  c.analysis_comments = comments
                             }
                         }
                     })
                 })
             }
        }
        
        originalAnalysis.value = { ...originalAnalysis.value, ...newOriginals }
        
        // Refresh local form state from the first instance's new data
        updateFormFromGroup(false)
        
        // Mark these as initial for "touched" check
        initialVector.value = pendingVector.value
        initialScore.value = pendingScore.value
        
    } catch (e) {
        console.error("Failed to refresh details", e)
    } finally {
        loadingDetails.value = false
        refreshCounter.value++
        updateFormFromGroup(false)
    }
}


const handleUpdate = async (force: boolean = false, isApprove: boolean = false) => {
    let instances = allInstances.value
    
    // When a team is selected, automatically filter to only that team's instances
    if (selectedTeam.value) {
        const team = selectedTeam.value
        instances = instances.filter(inst => inst.tags && inst.tags.includes(team))
    }

    if (window.localStorage?.getItem?.('dtvp_debug_persistence') === 'true') {
        console.log('[Persistence Debug] handleUpdate started', {
            force,
            isApprove,
            selectedTeam: selectedTeam.value,
            currentState: state.value,
            currentDetails: details.value,
            formTouched: formTouched.value
        });
    }

    if (!force && !await promptConfirm('Apply Assessment', `Apply this assessment?`)) {
        if (window.localStorage?.getItem?.('dtvp_debug_persistence') === 'true') {
            console.log('[Persistence Debug] handleUpdate cancelled by user');
        }
        return
    }
    
    updating.value = true
    try {
        const allBlocks: AssessmentBlock[] = []
        const teamToIndex = new Map<string, number>()
        const allTags = new Set<string>()
        let isPending = false
        
        for (const inst of instances) {
            let detailsToParse = inst.analysis_details || inst.analysisDetails || ''
            if (inst.finding_uuid && originalAnalysis.value[inst.finding_uuid]) {
                const orig = originalAnalysis.value[inst.finding_uuid]
                detailsToParse = orig.analysisDetails || orig.analysis_details || ''
            }
            if (!detailsToParse) continue
            
            if (detailsToParse.includes('[Status: Pending Review]')) isPending = true
            
            const blocks = parseAssessmentBlocks(detailsToParse)
            for (const block of blocks) {
                const teamName = block.team
                const existingIndex = teamToIndex.get(teamName)
                
                if (existingIndex === undefined) {
                    teamToIndex.set(teamName, allBlocks.length)
                    allBlocks.push(block)
                } else {
                    const existingBlock = allBlocks[existingIndex]
                    if (existingBlock) {
                        const currentTimestamp = existingBlock.timestamp || 0
                        const newTimestamp = block.timestamp || 0
                        
                        if (newTimestamp > currentTimestamp) {
                            allBlocks[existingIndex] = block
                        } else if (newTimestamp === currentTimestamp) {
                            if ((block.details?.length || 0) > (existingBlock.details?.length || 0)) {
                                allBlocks[existingIndex] = block
                            }
                        }
                    }
                }
            }
            const rescoredMatch = detailsToParse.match(/\[Rescored:\s*[\d\.]+\]/);
            if (rescoredMatch) allTags.add(rescoredMatch[0]);

            const vectorMatch = detailsToParse.match(/\[Rescored Vector:\s*[^\]]+\]/);
            if (vectorMatch) allTags.add(vectorMatch[0]);
        }
        
        const currentFullDetails = allBlocks.length > 0 ? constructAssessmentDetails(allBlocks, Array.from(allTags), isPending).text : ''

        // 2. Perform Client-Side Merge
        const targetTeam = selectedTeam.value || 'General'
        
        if (window.localStorage?.getItem?.('dtvp_debug_persistence') === 'true') {
            console.log('[Persistence Debug] handleUpdate merging details', {
                targetTeam,
                state: state.value,
                details: details.value,
                allBlocksInitialCount: allBlocks.length
            });
        }

        if (!targetTeam && !isReviewer.value) {
             await showAlert('Input Required', "Please select a team to assess.")
             return
        }

        const currentUser = user.value?.username || 'unknown'
        
        // Prepare rescored tags if any (only for Reviewers)
        let rescoredTags: string[] | undefined = undefined
        const canRescore = isReviewer.value;
        
        if (canRescore) {
            // Check if touched in this session
            const touched = pendingVector.value !== initialVector.value || pendingScore.value !== initialScore.value;

            if (touched) {
                // If it now matches the ORIGINAL (DT) vector, we explicitly clear it
                const matchesOriginal = pendingVector.value === props.group.cvss_vector && 
                                       (pendingScore.value === (props.group.cvss_score ?? props.group.cvss));
                
                if (matchesOriginal) {
                    rescoredTags = [] // Forces removal of existing tags
                } else {
                    rescoredTags = []
                    if (pendingScore.value !== null && pendingScore.value !== undefined) {
                        rescoredTags.push(`[Rescored: ${pendingScore.value}]`)
                    }
                    if (pendingVector.value) {
                        rescoredTags.push(`[Rescored Vector: ${pendingVector.value}]`)
                    }
                }
            } else {
                // Not touched - leave as undefined so helper preserves existing tags from details
                rescoredTags = undefined
            }
        }

        let mergedResult: { text: string, aggregatedState: string }
        
         // Case: Merge with existing blocks and potentially clear/set pending flag
         // Decoupled logic: only clear pending flag if isApprove is explicitly true.
         // Otherwise, always keep it pending.
         mergedResult = mergeTeamAssessment(
            currentFullDetails,
            targetTeam,
            state.value,
            details.value,
            currentUser,
            justification.value,
            rescoredTags,
            !isApprove // isPending = true unless approving
         )
        
        let finalText = mergedResult.text

        const payload: AssessmentPayload = {
            instances: instances,
            state: mergedResult.aggregatedState, // calculated by helper
            details: finalText, // The FULL merged history
            comment: comment.value, // Audit comment usually separate from details
            justification: justification.value && justification.value !== 'NOT_SET' ? justification.value : undefined,
            suppressed: suppressed.value,
            team: selectedTeam.value || undefined, 
            comparison_mode: 'REPLACE' as const,
            original_analysis: originalAnalysis.value,
            force: force
        }

        const results = await updateAssessment(payload)

        const errors = results.filter((r: any) => r.status === 'error')
        if (errors.length > 0) {
             console.error('Update completed with errors:', errors)
             await showAlert('Update Partial', `Assessment updated with ${errors.length} errors. Check console for details.`)
        } else {
             const success = results.find((r: any) => r.status === 'success')
             if (success) {
                 const canRescore = isReviewer.value;
                 const hasVectorChange = canRescore ? (pendingVector.value !== props.group.cvss_vector) : !!props.group.rescored_vector;
                 
                 const data = {
                     rescored_cvss: hasVectorChange ? (canRescore ? pendingScore.value : props.group.rescored_cvss) : null,
                     rescored_vector: hasVectorChange ? (canRescore ? pendingVector.value : props.group.rescored_vector) : null,
                     analysis_state: success.new_state,
                     analysis_details: success.new_details,
                     is_suppressed: suppressed.value
                 }
                 emit('update:assessment', data)
                 
                 // Reset local state so UI reflects the new server state
                 pendingScore.value = null
                 pendingVector.value = data.rescored_vector || props.group.cvss_vector || ''
                 initialVector.value = pendingVector.value
                 initialScore.value = data.rescored_cvss ?? null
                 isManualBaseMode.value = false
                 lastRescoredScore.value = data.rescored_cvss ?? null
             }
             showConflictModal.value = false
        }
        
        
        // expanded.value = false // Removed as it's confusing to close the card while the user is looking at it
    } catch (err: any) {
        if (err.response && err.response.status === 409) {
            conflictData.value = err.response.data.conflicts
            showConflictModal.value = true
        } else {
            await showAlert('Error', 'Failed to update assessment')
            console.error(err)
        }
    } finally {
        updating.value = false
    }
}

const handleUseServerState = () => {
    // Refresh details to get latest server state (which we technically have in conflictData but refresh is safer/simpler)
    refreshDetails()
    showConflictModal.value = false
}

const severityColor = computed(() => {
    switch (props.group.severity) {
        case 'CRITICAL': return 'bg-red-600 text-white shadow-sm ring-1 ring-red-400'
        case 'HIGH': return 'bg-orange-600 text-white shadow-sm ring-1 ring-orange-400'
        case 'MEDIUM': return 'bg-yellow-600 text-white shadow-sm ring-1 ring-yellow-400'
        case 'LOW': return 'bg-green-600 text-white shadow-sm ring-1 ring-green-400'
        case 'INFO': return 'bg-blue-600 text-white shadow-sm ring-1 ring-blue-400'
        default: return 'bg-gray-600 text-white shadow-sm ring-1 ring-gray-400'
    }
})


const stateColor = computed(() => {
    switch (technicalState.value) {
        case 'NOT_AFFECTED': return 'text-green-400'
        case 'EXPLOITABLE': return 'text-red-400'
        case 'NOT_SET': return 'text-red-500/80'
        case 'IN_TRIAGE': return 'text-amber-400'
        case 'FALSE_POSITIVE': return 'text-teal-400'
        case 'RESOLVED': return 'text-purple-400'
        case 'INCOMPLETE': return 'text-amber-500'
        case 'INCONSISTENT': return 'text-indigo-400'
        default: return 'text-gray-300'
    }
})


const cardStyle = computed(() => {
    switch (displayState.value) {
        case 'INCOMPLETE':
            return 'bg-amber-500/5 border-amber-500/20 hover:bg-amber-500/10'
        case 'INCONSISTENT':
            return 'bg-indigo-500/5 border-indigo-500/30 hover:bg-indigo-500/10 stripe-bg'
        case 'NOT_SET':
        case 'OPEN':
            return 'bg-red-500/5 border-red-500/20 hover:bg-red-500/10'
        case 'EXPLOITABLE':
            return 'bg-red-900/10 border-red-600/40'
        case 'NOT_AFFECTED':
            return 'bg-green-900/5 border-green-600/30'
        default:
            return 'bg-gray-800 border-gray-700 hover:bg-gray-750'
    }
})



const affectedComponentNames = computed(() => {
    const names = new Set(allInstances.value.map(c => `${c.component_name} ${c.component_version}`))
    return Array.from(names).join(', ')
})

const rescoredVectorSegments = computed(() => {
    const rescored = props.group.rescored_vector
    const original = props.group.cvss_vector
    
    if (!rescored || !original || !rescored.startsWith(original)) {
        return { bold: '', normal: rescored || '' }
    }
    
    return {
        bold: original,
        normal: rescored.slice(original.length)
    }
})

const normalizedTags = computed(() => {
    if (!props.group.tags) return []

    const rawTags = props.group.tags.map(tagToString).filter(Boolean)
    if (!teamMapping?.value) return rawTags

    const result = new Set<string>()
    rawTags.forEach(tag => {
        let foundPrimary = tag
        for (const componentName in teamMapping.value) {
            const mappingVal = teamMapping.value[componentName]
            if (Array.isArray(mappingVal) && mappingVal.length > 1) {
                const primary = mappingVal[0]
                const aliases = mappingVal.slice(1)
                if (aliases.includes(tag)) {
                    foundPrimary = primary
                    break
                }
            }
        }
        result.add(foundPrimary)
    })
    return Array.from(result)
})

const assessedTeams = computed(() => {
    const assessed = getAssessedTeams(props.group)
    const matchedTeams = new Set<string>()

    normalizedTags.value.forEach(tag => {
        // A primary tag is assessed if it OR any of its aliases are assessed
        if (assessed.has(tag)) {
            matchedTeams.add(tag)
            return
        }

        if (teamMapping?.value) {
            for (const componentName in teamMapping.value) {
                const mappingVal = teamMapping.value[componentName]
                if (Array.isArray(mappingVal) && mappingVal.length > 1) {
                    const primary = mappingVal[0]
                    if (primary === tag) {
                        const aliases = mappingVal.slice(1)
                        if (aliases.some(alias => assessed.has(alias))) {
                            matchedTeams.add(tag)
                            break
                        }
                    }
                }
            }
        }
    })

    return matchedTeams
})

const getStateDescription = (stateValue: string | undefined) => {
    if (!stateValue) return ''
    return ANALYSIS_STATES.find(s => s.value === stateValue)?.description || ''
}

const getJustificationDescription = (justValue: string | undefined) => {
    if (!justValue) return ''
    return JUSTIFICATION_OPTIONS.find(j => j.value === justValue)?.description || ''
}
</script>

<template>
  <div :class="['vuln-card relative border rounded-lg overflow-hidden transition-colors', cardStyle]">
    <!-- Assessed Corner Fold -->
    <div v-if="isAssessed" class="absolute top-0 right-0 pointer-events-none z-20">
        <div 
            class="w-8 h-8 flex justify-end items-start p-1 uppercase"
            :class="displayState === 'INCOMPLETE' ? 'bg-green-600/30' : 'bg-green-600'"
            style="clip-path: polygon(100% 0, 0 0, 100% 100%)"
        >
            <CheckCircle :size="12" :class="displayState === 'INCOMPLETE' ? 'text-white/40' : 'text-white'" />
        </div>
    </div>
    <!-- Header -->
    <div 
        @click="expanded = !expanded" 
        class="p-5 flex flex-col md:flex-row md:items-center justify-between gap-8 cursor-pointer hover:bg-white/2 transition-all relative overflow-hidden group/header"
    >
        <div class="flex-1 min-w-0">
            <div class="flex items-center gap-8 mb-3">
                <!-- ID & Aliases -->
                <div class="flex flex-col w-56 shrink-0">
                    <span class="text-xl font-black text-yellow-400 tracking-tight leading-none group-hover/header:text-yellow-300 transition-colors">
                        {{ group.id }}
                    </span>
                    <div v-if="group.aliases?.length" class="text-[10px] text-gray-500 font-bold uppercase tracking-widest mt-1.5 flex gap-2 overflow-hidden">
                        <span v-for="alias in group.aliases" :key="alias" class="whitespace-nowrap opacity-60 hover:opacity-100 transition-opacity">
                            {{ alias }}
                        </span>
                    </div>
                </div>
                
                <!-- Criticality -->
                <div class="flex flex-col items-center gap-1.5 w-28 shrink-0">
                    <span class="text-[9px] font-black text-gray-600 uppercase tracking-[0.2em] leading-none">Criticality</span>
                    <span :class="['px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-tight border text-center w-full', severityColor]">
                        {{ group.severity || 'UNKNOWN' }}
                    </span>
                </div>

                <!-- CVSS Base Score -->
                <div class="flex flex-col items-center gap-1.5 w-24 shrink-0">
                    <span class="text-[9px] font-black text-gray-600 uppercase tracking-[0.2em] leading-none">CVSS Base</span>
                    <div class="flex items-center gap-2">
                        <span 
                            v-if="isRescoredOrModified" 
                            :class="['px-2.5 py-1 rounded-lg text-xs font-black transition-all duration-300 border', 
                                (pendingScore !== null) 
                                    ? 'bg-purple-500/10 text-purple-400 border-purple-500/30' 
                                    : 'bg-purple-500/5 text-purple-500 border-purple-500/20'
                            ]" 
                            data-testid="rescored-value-badge"
                        >
                            {{ currentDisplayScore }}
                        </span>
                        <span v-else class="text-lg font-black text-gray-100">
                            {{ currentDisplayScore }}
                        </span>
                        <span v-if="isRescoredOrModified" class="text-[10px] text-gray-600 line-through font-bold opacity-40">
                            {{ group.cvss || group.cvss_score }}
                        </span>
                    </div>
                </div>

                <!-- Team Consensus Badges -->
                <div v-if="normalizedTags.length > 0" class="flex items-center gap-3 flex-1 ml-4 pl-6 border-l border-white/5">
                    <div class="flex gap-2 flex-wrap">
                        <span 
                            v-for="tag in normalizedTags" 
                            :key="tag" 
                            class="px-2 py-1 rounded-lg text-[10px] font-black uppercase tracking-tight flex items-center gap-2 transition-all"
                            :class="assessedTeams.has(tag) 
                                ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' 
                                : 'bg-white/2 text-gray-600 border border-white/5'"
                        >
                            <CheckCircle v-if="assessedTeams.has(tag)" :size="10" class="text-blue-400" />
                            {{ tag }}
                        </span>
                    </div>
                </div>
            </div>
            
            <div class="text-sm text-gray-400 line-clamp-1 font-mono pl-0.5">
                {{ affectedComponentNames }}
            </div>
            
            <!-- Vector Display in Header if expanded or explicitly shown -->
            <div v-if="expanded && (group.rescored_vector || group.cvss_vector)" class="mt-2 flex flex-col gap-1.5">
                <div v-if="group.rescored_vector && group.rescored_vector !== group.cvss_vector" class="font-mono text-[10px] text-purple-300 break-all bg-purple-900/20 p-1.5 rounded border border-purple-500/30 flex items-center gap-2">
                    <span class="text-purple-400/70 uppercase font-bold shrink-0">Rescored Vector:</span>
                    <span class="tracing-tight">
                        <span class="font-bold rescored-bold-segment">{{ rescoredVectorSegments.bold }}</span>{{ rescoredVectorSegments.normal }}
                    </span>
                </div>
                <div class="font-mono text-[10px] text-gray-500 break-all bg-gray-900/50 p-1.5 rounded border border-gray-700/50 flex items-center gap-2">
                    <span class="text-gray-600 uppercase font-bold shrink-0">{{ group.rescored_vector ? 'Original Vector:' : 'Vector:' }}</span>
                    <span :class="{ 'line-through opacity-50': group.rescored_vector }">{{ group.cvss_vector || 'N/A' }}</span>
                </div>
            </div>
        </div>
        
        <div class="flex items-start gap-8 shrink-0">
            <div class="w-28 text-right">
                <div class="text-[10px] text-gray-500 font-bold uppercase tracking-wider mb-0.5">Analysis</div>
                <div 
                    :id="`state-${group.id}`"
                    :class="['font-bold text-sm truncate analysis-state-value cursor-help', stateColor]"
                    :title="getStateDescription(technicalState)"
                >
                    {{ technicalState }}
                </div>
                <div class="text-[9px] font-black uppercase tracking-tighter mt-1 opacity-40 px-1 border border-white/5 rounded inline-block analysis-lifecycle-value" :title="getStateDescription(displayState)">
                    {{ displayState }}
                </div>
            </div>

            
            <div class="w-24 text-right">
                    <div class="text-[10px] text-gray-500 font-bold uppercase tracking-wider mb-0.5">Affected</div>
                    <div class="font-bold text-sm text-gray-300">{{ group.affected_versions?.length || 0 }} Versions</div>
                    
                    <div class="mt-1 flex flex-col items-end gap-1">
                        <div v-if="isPendingReview">
                            <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold bg-yellow-900/50 text-yellow-300 border border-yellow-700/50 uppercase tracking-wide">
                                Pending Review
                            </span>
                        </div>
                    </div>
                
                    <button 
                        v-if="canApprove"
                        @click="approveAssessment"
                        class="mt-1 px-2 py-0.5 text-xs bg-green-700 hover:bg-green-600 text-white rounded font-bold transition-colors w-full z-10 relative"
                    >
                        Approve
                    </button>
            </div>

            <div class="pt-1 flex items-center gap-2">
                 <button 
                    @click.stop="refreshDetails" 
                    class="p-1 hover:bg-gray-700 rounded text-gray-400 hover:text-white transition-colors"
                    title="Refresh Analysis Details"
                >
                    <RefreshCw :size="16" :class="{ 'animate-spin': loadingDetails }" />
                </button>
                <component :is="expanded ? ChevronUp : ChevronDown" class="text-gray-500" :size="20" />
            </div>
        </div>
    </div>

            <!-- Expanded Details -->
    <div v-if="expanded" class="p-4 border-t border-gray-700 bg-gray-850">
        <div class="grid md:grid-cols-2 gap-8">
            <div>
                    <h4 class="font-semibold mb-2 text-gray-300">Description</h4>
                    <p class="text-sm text-gray-400 mb-4">{{ group.description || 'No description available.' }}</p>
                    
                    <div class="mt-4">
                         <h4 class="font-semibold text-gray-300 mb-4">Analysis Details & Comments</h4>
                         
                         <div v-for="(assessment, idx) in groupedAssessments" :key="idx" 
                              class="mb-8 last:mb-0 border-l-2 border-gray-700 pl-4 py-2 bg-gray-900/10 rounded-r-lg"
                              data-testid="grouped-assessment">
                             
                             <!-- Affected Instances List -->
                             <div class="mb-3 flex flex-wrap gap-1.5">
                                 <span v-for="inst in assessment.instances" :key="inst.component_uuid" 
                                       class="px-2 py-0.5 bg-gray-800 text-[9px] text-gray-400 rounded border border-gray-700 font-mono"
                                       data-testid="assessment-instance-badge"
                                       :title="`${inst.project_name} ${inst.project_version}`">
                                     v{{ inst.project_version }} {{ inst.component_name }} ({{ inst.component_version }})
                                 </span>
                             </div>

                             <!-- Assessment Data -->
                             <div v-if="assessment.state !== 'NOT_SET' || assessment.details || assessment.comments.length > 0" class="space-y-3">
                                 <div v-if="assessment.state !== 'NOT_SET' || assessment.details" class="space-y-3">
                                     <div v-for="block in parseAssessmentBlocks(assessment.details)" :key="block.team" 
                                          class="bg-gray-800/60 rounded border border-gray-700/50 p-3">
                                         <div class="flex justify-between items-start mb-2">
                                             <div class="flex flex-wrap items-center gap-2">
                                                 <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-blue-900/40 text-blue-300 border border-blue-800/50">
                                                     {{ block.team === 'General' ? 'Global Policy' : block.team }}
                                                 </span>
                                                 <span v-if="block.state && block.state !== 'NOT_SET'" 
                                                       class="px-2 py-0.5 rounded text-[10px] font-bold flex items-center gap-1 bg-gray-700/50 text-gray-300 border border-gray-600/50 cursor-help"
                                                       :title="getStateDescription(block.state)">
                                                     State: <span :class="block.state === 'NOT_AFFECTED' ? 'text-green-400' : (block.state === 'EXPLOITABLE' ? 'text-red-400' : 'text-gray-200')">{{ block.state }}</span>
                                                 </span>
                                                 <span v-if="block.justification && block.justification !== 'NOT_SET'" 
                                                       class="px-2 py-0.5 rounded text-[10px] font-bold text-gray-400 border border-gray-700 bg-gray-900/30 cursor-help"
                                                       :title="getJustificationDescription(block.justification)">
                                                     {{ block.justification.replace(/_/g, ' ') }}
                                                 </span>
                                             </div>
                                             <div class="text-[10px] text-gray-500 font-mono text-right shrink-0">
                                                 <div v-if="block.user" class="text-gray-400">{{ block.user }}</div>
                                                 <div v-if="block.timestamp">{{ new Date(typeof block.timestamp === 'number' ? block.timestamp : parseInt(block.timestamp)).toLocaleString() }}</div>
                                             </div>
                                         </div>
                                         <div v-if="block.details && block.details.trim()" class="text-sm text-gray-300 pl-2 border-l-2 border-gray-600 whitespace-pre-wrap break-words mt-2">
                                             {{ block.details }}
                                         </div>
                                     </div>
                                 </div>
                                 <div v-else-if="assessment.comments.length > 0" class="text-xs text-gray-500 italic opacity-50 pl-1 mb-2">
                                     No assessment state recorded, but comments available.
                                 </div>

                                 <!-- Comments / Audit Log Section -->
                                 <div v-if="assessment.comments.length > 0" class="mt-4">
                                     <div class="flex items-center justify-between mb-2">
                                         <h5 class="text-[10px] font-black uppercase tracking-[0.2em] text-gray-600">Audit Trail ({{ assessment.comments.length }})</h5>
                                         <button 
                                            @click="showAuditLog = !showAuditLog"
                                            class="text-[9px] font-black uppercase tracking-widest text-blue-500/70 hover:text-blue-400 transition-all flex items-center gap-1.5"
                                         >
                                            <History :size="10" />
                                            {{ showAuditLog ? 'Collapse Trail' : 'Expand Trail' }}
                                         </button>
                                     </div>

                                     <div v-if="showAuditLog" class="space-y-2 mt-2 max-h-[300px] overflow-y-auto pr-2 custom-scrollbar bg-black/20 p-3 rounded-lg border border-white/5">
                                         <div v-for="(c, ci) in assessment.comments" :key="ci" class="text-xs text-gray-400 italic pl-3 border-l border-gray-700 py-0.5">
                                             {{ c.comment }} <span class="text-[10px] text-gray-600 not-italic block mt-0.5 font-bold">Assessed on {{ new Date(c.timestamp).toLocaleDateString() }}</span>
                                         </div>
                                     </div>
                                 </div>
                             </div>
                             <div v-else class="text-xs text-gray-500 italic opacity-50 pl-1">
                                 No assessment recorded for these versions.
                             </div>

                             <!-- Usage Chains Section (Collapsible) -->
                             <div class="mt-4 pt-2 border-t border-gray-800/50">
                                 <details class="group/usage">
                                     <summary class="text-[10px] font-bold text-gray-600 cursor-pointer hover:text-gray-400 select-none flex items-center gap-1.5 uppercase tracking-widest">
                                         <ChevronDown :size="10" class="group-open/usage:rotate-180 transition-transform" />
                                         Usage Paths ({{ assessment.instances.length }})
                                     </summary>
                                     <div class="mt-3 space-y-6">
                                         <div v-for="inst in assessment.instances" :key="'graph-' + inst.component_uuid" class="relative">
                                             <div class="text-[9px] text-gray-500 mb-2 font-mono uppercase tracking-tight flex items-center gap-2">
                                                 <span class="w-1.5 h-1.5 rounded-full bg-gray-700"></span>
                                                 {{ inst.project_name }} › {{ inst.component_name }}
                                             </div>
                                             <DependencyChainViewer 
                                                :project-uuid="inst.project_uuid"
                                                :component-uuid="inst.component_uuid"
                                                :project-name="inst.project_name"
                                            />
                                         </div>
                                     </div>
                                 </details>
                             </div>
                         </div>
                    </div>
            </div>
            
            <div class="bg-gray-900 p-4 rounded border border-gray-700 h-fit">
                <h4 class="font-bold flex items-center gap-2 mb-4">
                    <Shield :size="16" class="text-blue-400"/>
                    {{ selectedTeam ? `Team Assessment: ${selectedTeam}` : 'Global Assessment' }}
                </h4>
                
                <div class="space-y-4">
                    <!-- CVSS Calculator Section (For Reviewers) -->
                    <div v-if="isReviewer" class="p-3 border border-gray-700 rounded bg-gray-800">
                        <h5 class="text-xs font-bold text-gray-300 mb-2 flex items-center gap-2">
                            <Calculator :size="12" />
                            CVSS Calculator
                        </h5>
                        
                        <div class="mb-2">
                            <label class="block text-xs font-semibold text-gray-500 mb-1 flex justify-between">
                                <span>Vector String</span>
                                <div class="flex items-center gap-2">
                                    <button 
                                        @click="resetVector" 
                                        class="text-gray-400 hover:text-white flex items-center gap-1 cursor-pointer"
                                        title="Reset to Original"
                                    >
                                        <RotateCcw :size="10" />
                                    </button>
                                    <button @click="showCalculatorModal = true" class="text-blue-400 hover:text-blue-300 flex items-center gap-1 cursor-pointer">
                                        <ExternalLink :size="10" /> Visual Calculator
                                    </button>
                                </div>
                            </label>
                            <input 
                                v-model="pendingVector"
                                type="text" 
                                :readonly="!canEditBase"
                                placeholder="CVSS:4.0/AV:N/..."
                                class="w-full p-1.5 rounded bg-gray-900 border border-gray-600 focus:border-blue-500 text-xs font-mono disabled:opacity-50"
                                :class="{ 'cursor-not-allowed text-gray-400': !canEditBase }"
                            />
                            <div v-if="group.cvss_vector && group.cvss_vector !== pendingVector" class="mt-1 text-[9px] text-gray-500/60 flex gap-1.5 truncate">
                                <span class="uppercase font-bold shrink-0">Original:</span>
                                <span class="truncate italic">{{ group.cvss_vector }}</span>
                            </div>
                        </div>
                        
                        <div class="flex items-center justify-between">
                            <label class="block text-xs font-semibold text-gray-500">Score</label>
                            <div class="flex gap-2">
                                <input 
                                    v-model="pendingScore"
                                    type="number" 
                                    :readonly="!canEditBase"
                                    step="0.1" 
                                    min="0" 
                                    max="10" 
                                    class="w-16 p-1.5 text-right rounded bg-gray-900 border border-gray-600 focus:border-blue-500 text-sm font-bold text-yellow-400 disabled:opacity-50"
                                    :class="{ 'cursor-not-allowed text-gray-500': !canEditBase }"
                                />
                            </div>
                        </div>
                    </div>

                    <!-- Team Selection -->
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs font-semibold text-gray-400 mb-1">Team assessment (Marker)</label>
                            <select 
                                v-model="selectedTeam" 
                                class="w-full p-2 rounded bg-gray-800 border border-gray-600 focus:border-blue-500"
                            >
                                <option value="">{{ isReviewer ? 'Global assessment' : 'No team marker' }}</option>
                                <option v-for="t in normalizedTags" :key="t" :value="t">{{ t }}</option>
                            </select>
                        </div>
                    </div>

                    <!-- Assessment Section (Reviewer Global or Team Selected) -->
                    <div v-if="selectedTeam || isReviewer" :class="['border rounded p-3', selectedTeam ? 'border-blue-700/50 bg-blue-950/20' : 'border-purple-700/50 bg-purple-950/20']">
                        <h5 class="text-xs font-bold mb-3 uppercase tracking-wide flex items-center gap-2" :class="selectedTeam ? 'text-blue-300' : 'text-purple-300'">
                            {{ selectedTeam ? 'Team Opinion' : 'Global Baseline' }}
                        </h5>
                        
                        <div class="space-y-3">
                            <div>
                                <label class="block text-xs font-semibold text-gray-400 mb-1">{{ selectedTeam ? 'Team' : 'Global' }} Analysis State</label>
                                <select 
                                    v-model="state" 
                                    @change="formTouched = true"
                                    class="w-full p-2 rounded bg-gray-800 border border-gray-600 focus:border-blue-500"
                                >
                                    <option v-for="s in ANALYSIS_STATES" :key="s.value" :value="s.value" :title="s.description">{{ s.label }}</option>
                                </select>
                            </div>

                            <div v-if="state === 'NOT_AFFECTED'">
                                <label class="block text-xs font-semibold text-gray-400 mb-1">{{ selectedTeam ? 'Team' : 'Global' }} Justification</label>
                                <select 
                                    v-model="justification" 
                                    class="w-full p-2 rounded bg-gray-800 border border-gray-600 focus:border-blue-500"
                                >
                                    <option v-for="o in JUSTIFICATION_OPTIONS" :key="o.value" :value="o.value" :title="o.description">{{ o.label }}</option>
                                </select>
                            </div>

                            <div>
                                <label class="block text-xs font-semibold text-gray-400 mb-1">{{ selectedTeam ? 'Team' : 'Global' }} Analysis Details</label>
                                <textarea 
                                    v-model="details" 
                                    @input="formTouched = true"
                                    placeholder="Technical details..."
                                    class="w-full p-2 rounded bg-gray-800 border border-gray-600 focus:border-blue-500 h-24"
                                />
                            </div>
                        </div>
                    </div>

                    <!-- No-Team Section (Prompt for non-reviewers) -->
                    <div v-if="!selectedTeam && !isReviewer" class="p-4 rounded border border-gray-700 bg-gray-800/50 flex flex-col items-center justify-center text-center space-y-2">
                        <Shield :size="32" class="text-blue-500/50" />
                        <h4 class="text-sm font-bold text-gray-300">Select a Team to Assess</h4>
                        <p class="text-xs text-gray-400 max-w-xs">
                          Global assessments are restricted to reviewers. Please select a specific team marker above to provide an assessment.
                        </p>
                    </div>

                    <div v-if="isReviewer">
                        <label class="block text-xs font-semibold text-gray-400 mb-1">Comment</label>
                        <textarea 
                            v-model="comment"
                            placeholder="Add a comment for audit trail..."
                            class="w-full p-2 rounded bg-gray-800 border border-gray-600 focus:border-blue-500 h-24"
                        />
                    </div>
                    
                    <div v-if="isReviewer" class="flex items-center gap-2">
                        <input 
                            type="checkbox" 
                            :id="`suppress-${group.id}`"
                            v-model="suppressed"
                            class="w-4 h-4 rounded"
                        />
                        <label :for="`suppress-${group.id}`" class="text-sm">Suppress this vulnerability</label>
                    </div>
                    
                    <div v-if="isReviewer && !selectedTeam && mergedAssessmentData.blocks.length > 0" class="pt-2 border-t border-gray-700 mt-2">
                        <button 
                            @click="applyConsensusAssessment"
                            class="w-full mb-2 bg-yellow-600/20 hover:bg-yellow-600/30 text-yellow-500 border border-yellow-600/50 font-bold py-1.5 rounded text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer"
                        >
                            <AlertTriangle :size="14" />
                            {{ consensusButtonLabel }}
                        </button>
                    </div>

                    <button 
                        @click="() => handleUpdate(false)"
                        :disabled="updating || loadingDetails || totalTargeted === 0"
                        class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded transition-colors disabled:opacity-50 cursor-pointer"
                    >
                        {{ updating ? 'Updating...' : 'Apply' }}
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Grouped Calculator Modal -->
    <div v-if="showCalculatorModal && isReviewer" class="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
        <div class="bg-gray-800 w-full max-w-3xl max-h-[90vh] flex flex-col rounded-lg border border-gray-700 shadow-2xl">
            <!-- Modal Header -->
            <div class="p-4 border-b border-gray-700 flex justify-between items-center bg-gray-800">
                <h3 class="font-bold text-lg text-gray-300">CVSS v{{ activeVersion }} Calculator</h3>
                <div class="flex items-center gap-3">
                    <button 
                        @click="clearVector"
                        class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-xs font-bold text-gray-300 transition-colors"
                        title="Clear vector to unlock all versions"
                    >
                        Clear
                    </button>
                    <button 
                        @click="resetVector"
                        class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-xs font-bold text-gray-300 transition-colors"
                        title="Reset to original CVE vector"
                    >
                        Reset
                    </button>
                    <button @click="showCalculatorModal = false" class="text-gray-400 hover:text-white text-xl font-bold cursor-pointer">✕</button>
                </div>
            </div>
            
            <!-- Version Tabs -->
            <div class="flex border-b border-gray-700 bg-gray-850">
                <button 
                    v-for="v in visibleVersions" 
                    :key="v"
                    @click="switchVersion(v as any)"
                    :class="[
                        'px-4 py-2 text-sm font-bold border-r border-gray-700 transition-colors',
                        activeVersion === v ? 'bg-gray-700 text-white' : 'bg-gray-850 text-gray-400 hover:bg-gray-800'
                    ]"
                >
                    CVSS v{{ v }}
                </button>
            </div>

            <!-- Content -->
            <div class="flex-1 overflow-y-auto p-4 bg-gray-800">
                <div v-if="activeVersion === '2.0'">
                    <CvssCalculatorV2 
                        :instance="cvssInstance" 
                        :can-edit-base="canEditBase"
                        @update="updateCalcVector" 
                        @reset="resetVector"
                    />
                </div>
                <div v-else-if="activeVersion === '3.1' || activeVersion === '3.0'">
                    <CvssCalculatorV3 
                        :instance="cvssInstance" 
                        :can-edit-base="canEditBase" 
                        @update="updateCalcVector" 
                        @reset="resetVector"
                    />
                </div>
                <div v-else-if="activeVersion === '4.0'">
                    <CvssCalculatorV4 
                        :instance="cvssInstance" 
                        :can-edit-base="canEditBase" 
                        @update="updateCalcVector" 
                        @reset="resetVector"
                    />
                </div>
            </div>

            <!-- Footer -->
            <div class="p-4 border-t border-gray-700 bg-gray-850">
                <div class="flex justify-between items-center">
                    <div>
                        <div class="text-xs text-gray-500 font-mono mb-1">Current Vector</div>
                        <div class="text-sm font-mono font-bold text-white break-all mb-2">{{ pendingVector }}</div>
                    </div>
                    <div class="text-right ml-4">
                         <div class="text-xs text-gray-500 uppercase">Score</div>
                         <div class="text-2xl font-bold text-yellow-400">{{ pendingScore }}</div>
                    </div>
                </div>
                <button 
                    @click="showCalculatorModal = false"
                    class="w-full mt-4 bg-green-600 hover:bg-green-700 text-white font-bold py-2 rounded transition-colors"
                >
                    Done
                </button>
            </div>
        </div>
    </div>

    <!-- Conflict Resolution Modal -->
    <div v-if="showConflictModal" class="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
        <div class="bg-gray-800 w-full max-w-4xl max-h-[90vh] flex flex-col rounded-lg border border-red-500 shadow-2xl">
            <div class="p-4 border-b border-gray-700 flex justify-between items-center bg-gray-800">
                <h3 class="font-bold text-lg text-red-400 flex items-center gap-2">
                    <AlertTriangle :size="20" />
                    Conflict Detected
                </h3>
                <button @click="showConflictModal = false" class="text-gray-400 hover:text-white text-xl font-bold">✕</button>
            </div>
            
            <div class="p-4 bg-red-900/20 border-b border-red-900/50 text-red-200 text-sm">
                The analysis data on the server has changed since you started editing. 
                Please review the differences below and choose how to proceed.
            </div>

            <div class="flex-1 overflow-y-auto p-4 bg-gray-800 space-y-4">
                <div v-for="conflict in conflictData" :key="conflict.finding_uuid" class="bg-gray-900 border border-gray-700 rounded p-4">
                    <div class="font-bold text-gray-300 mb-2 border-b border-gray-700 pb-1">
                        {{ conflict.project_name }} {{ conflict.project_version }} - {{ conflict.component_name }}
                    </div>
                    
                    <div class="grid grid-cols-2 gap-4">
                        <!-- Server State -->
                        <div class="space-y-2">
                             <h4 class="text-xs font-bold uppercase text-gray-500">Server State (New)</h4>
                             <div class="text-sm">
                                <span class="text-gray-400">State:</span> <span class="font-mono text-blue-300">{{ conflict.current.analysisState }}</span>
                             </div>
                             <div class="text-sm">
                                <span class="text-gray-400">Suppressed:</span> <span class="font-mono text-blue-300">{{ conflict.current.isSuppressed }}</span>
                             </div>
                             <div class="text-sm bg-gray-800 p-2 rounded border border-gray-700 max-h-40 overflow-auto whitespace-pre-wrap font-mono text-xs">
                                {{ conflict.current.analysisDetails || '(No details)' }}
                             </div>
                        </div>
                        
                         <!-- Your State -->
                        <div class="space-y-2">
                             <h4 class="text-xs font-bold uppercase text-gray-500">Your Changes</h4>
                             <div class="text-sm">
                                <span class="text-gray-400">State:</span> <span class="font-mono text-green-300">{{ conflict.your_change.analysisState }}</span>
                             </div>
                             <div class="text-sm">
                                <span class="text-gray-400">Suppressed:</span> <span class="font-mono text-green-300">{{ conflict.your_change.isSuppressed }}</span>
                             </div>
                             <div class="text-sm bg-gray-800 p-2 rounded border border-gray-700 max-h-40 overflow-auto whitespace-pre-wrap font-mono text-xs">
                                {{ conflict.your_change.analysisDetails || '(No details)' }}
                             </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="p-4 border-t border-gray-700 bg-gray-850 flex justify-end gap-4">
                <button 
                    @click="handleUseServerState"
                    class="px-4 py-2 rounded bg-gray-700 hover:bg-gray-600 text-white font-bold transition-colors"
                >
                    Discard My Changes (Use Server)
                </button>
                <button 
                    @click="() => handleUpdate(true)"
                    :disabled="updating"
                    class="px-4 py-2 rounded bg-red-600 hover:bg-red-700 text-white font-bold transition-colors disabled:opacity-50"
                >
                    Force Overwrite
                </button>
            </div>
        </div>
    </div>
    <!-- Generic Modal (Alert/Confirm) -->
    <div v-if="genericModal.show" class="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-[100]">
        <div class="bg-gray-800 w-full max-w-md rounded-lg border border-gray-700 shadow-2xl overflow-hidden scale-in-center">
            <div class="p-4 border-b border-gray-700 bg-gray-800 flex justify-between items-center">
                <h3 class="font-bold text-lg text-gray-200">{{ genericModal.title }}</h3>
                <button @click="handleModalResponse(false)" class="text-gray-400 hover:text-white transition-colors">✕</button>
            </div>
            <div class="p-6 bg-gray-850 text-gray-300">
                <p class="text-sm leading-relaxed">{{ genericModal.message }}</p>
            </div>
            <div class="p-4 bg-gray-900 border-t border-gray-700 flex justify-end gap-3">
                <button 
                    v-if="!genericModal.confirmOnly"
                    @click="handleModalResponse(false)"
                    class="px-4 py-2 rounded bg-gray-700 hover:bg-gray-600 text-white text-sm font-bold transition-colors"
                >
                    Cancel
                </button>
                <button 
                    @click="handleModalResponse(true)"
                    class="px-6 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white text-sm font-bold shadow-lg shadow-blue-900/20 transition-all active:scale-95"
                >
                    {{ genericModal.confirmOnly ? 'Close' : 'Confirm' }}
                </button>
            </div>
        </div>
    </div>
  </div>
</template>

<style scoped>
.scale-in-center {
	animation: scale-in-center 0.15s cubic-bezier(0.250, 0.460, 0.450, 0.940) both;
}
@keyframes scale-in-center {
  0% { transform: scale(0.95); opacity: 0; }
  100% { transform: scale(1); opacity: 1; }
}

.stripe-bg {
    background-image: repeating-linear-gradient(
        45deg,
        transparent,
        transparent 10px,
        rgba(99, 102, 241, 0.03) 10px,
        rgba(99, 102, 241, 0.03) 20px
    );
}
</style>

