<script setup lang="ts">
import { ref, computed, watch, inject } from 'vue'
import { updateAssessment, getAssessmentDetails } from '../lib/api'

import type { GroupedVuln, AssessmentPayload } from '../types'
import { ChevronDown, ChevronUp, Shield, RefreshCw, AlertTriangle, Calculator, ExternalLink } from 'lucide-vue-next'

import { parseAssessmentBlocks, mergeTeamAssessment } from '../lib/assessment-helpers'
import { calculateScoreFromVector } from '../lib/cvss'
import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'
import CvssCalculatorV2 from './CvssCalculatorV2.vue'
import CvssCalculatorV3 from './CvssCalculatorV3.vue'
import CvssCalculatorV4 from './CvssCalculatorV4.vue'
import DependencyChainViewer from './DependencyChainViewer.vue'


const props = defineProps<{
  group: GroupedVuln
}>()

const user = inject<any>('user')

const emit = defineEmits(['update', 'update:assessment', 'toggle-expand'])

const ANALYSIS_STATES = [
    { value: 'NOT_SET', label: 'Not Set' },
    { value: 'NOT_AFFECTED', label: 'Not Affected' },
    { value: 'EXPLOITABLE', label: 'Exploitable' },
    { value: 'IN_TRIAGE', label: 'In Triage' },
    { value: 'FALSE_POSITIVE', label: 'False Positive' },
    { value: 'RESOLVED', label: 'Resolved' },
]

const JUSTIFICATION_OPTIONS = [
    { value: 'NOT_SET', label: 'Not Set' },
    { value: 'CODE_NOT_PRESENT', label: 'Code Not Present' },
    { value: 'CODE_NOT_REACHABLE', label: 'Code Not Reachable' },
    { value: 'REQUIRES_CONFIGURATION', label: 'Requires Configuration' },
    { value: 'REQUIRES_DEPENDENCY', label: 'Requires Dependency' },
    { value: 'REQUIRES_ENVIRONMENT', label: 'Requires Environment' },
    { value: 'PROTECTED_BY_COMPILER', label: 'Protected by Compiler' },
    { value: 'PROTECTED_AT_RUNTIME', label: 'Protected at Runtime' },
    { value: 'PROTECTED_AT_PERIMETER', label: 'Protected at Perimeter' },
    { value: 'PROTECTED_BY_MITIGATING_CONTROL', label: 'Protected by Mitigating Control' },
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
    const states = new Set(allInstances.value.map(i => i.analysis_state || 'NOT_SET'))
    if (states.size === 0) return 'NOT_SET'
    if (states.size > 1) return 'MIXED'
    const state = Array.from(states)[0]
    return state === 'NOT_SET' ? 'NOT_SET' : state
})

const isPendingReview = computed(() => {
    return allInstances.value.some(i => (i.analysis_details || '').includes('[Status: Pending Review]'))
})

const canApprove = computed(() => {
    return user?.value?.role === 'REVIEWER' && isPendingReview.value
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
    const original = props.group.rescored_vector || props.group.cvss_vector
    if (!original) return true
    return isManualBaseMode.value
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

const updateFormFromGroup = () => {
    pendingScore.value = props.group.rescored_cvss ?? props.group.cvss_score ?? props.group.cvss ?? null
    pendingVector.value = props.group.rescored_vector || props.group.cvss_vector || ''
    
    const firstVersion = props.group.affected_versions?.[0]
    if (firstVersion && firstVersion.components?.length > 0) {
        const first = firstVersion.components[0]
        if (first) {
            const rawDetails = first.analysis_details || ''
            const teamBlocks = parseAssessmentBlocks(rawDetails)
            
            if (selectedTeam.value) { // Team view
                const teamName = selectedTeam.value
                const myBlock = teamBlocks[teamName]
                state.value = myBlock?.state || 'NOT_SET'
                // Strip the status tag from the details shown in the textarea
                details.value = (myBlock?.details || '').replace(/\n\n\[Status: Pending Review\]/g, '').replace(/\[Status: Pending Review\]/g, '')
                justification.value = myBlock?.justification || 'NOT_SET'
            } else {
                 // No team selected - if Reviewer, show General block
                 if (isReviewer.value) {
                    const generalBlock = teamBlocks['General']
                    state.value = generalBlock?.state || 'NOT_SET'
                    details.value = (generalBlock?.details || '').replace(/\n\n\[Status: Pending Review\]/g, '').replace(/\[Status: Pending Review\]/g, '')
                    justification.value = generalBlock?.justification || 'NOT_SET'
                 } else {
                    state.value = 'NOT_SET'
                    details.value = ''
                    justification.value = 'NOT_SET'
                 }
            }
            comment.value = first.analysis_comments?.[0]?.comment || ''
            suppressed.value = first.is_suppressed || false
        }
    }

    // Set initial values for "touched" check
    initialVector.value = pendingVector.value
    initialScore.value = pendingScore.value
}

watch(selectedTeam, updateFormFromGroup)

watch(() => props.group, updateFormFromGroup, { immediate: true })


watch(expanded, (isOpen) => {
    emit('toggle-expand', props.group.id, isOpen)
    if (isOpen) {
        refreshDetails()
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
                             c.analysis_state = item.analysis.analysisState
                             c.analysis_details = item.analysis.analysisDetails
                             c.is_suppressed = item.analysis.isSuppressed
                             if (item.analysis.analysisComments) {
                                  c.analysis_comments = item.analysis.analysisComments
                             }
                         }
                     })
                 })
             }
        }
        
        originalAnalysis.value = { ...originalAnalysis.value, ...newOriginals }
        
        // Refresh local form state from the first instance's new data
        updateFormFromGroup()
        
        // Mark these as initial for "touched" check
        initialVector.value = pendingVector.value
        initialScore.value = pendingScore.value
        
    } catch (e) {
        console.error("Failed to refresh details", e)
    } finally {
        loadingDetails.value = false
    }
}


const handleUpdate = async (force: boolean = false, isApprove: boolean = false) => {
    let instances = allInstances.value
    
    // When a team is selected, automatically filter to only that team's instances
    if (selectedTeam.value) {
        const team = selectedTeam.value
        instances = instances.filter(inst => inst.tags && inst.tags.includes(team))
    }

    if (instances.length === 0) {
        await showAlert('Selection Error', 'No components found for the selected team.')
        return
    }

    if (!force && !await promptConfirm('Apply Assessment', `Apply this assessment to ${instances.length} instances?`)) return
    
    updating.value = true
    try {
        // 1. Get current full details from the first instance (or use refreshed data)
        // We need the BASE string to merge into. Use originalAnalysis.value as source of truth for "current" state
        const refInstance = instances[0]
        const findingUuid = refInstance?.finding_uuid
        const currentAnalysis = findingUuid ? originalAnalysis.value[findingUuid] : null
        // Fallback to refInstance.analysis_details if originalAnalysis is not yet populated
        const currentFullDetails = currentAnalysis?.analysisDetails || refInstance?.analysis_details || ''

        // 2. Perform Client-Side Merge
        const targetTeam = selectedTeam.value || 'General'
        if (!targetTeam && !isReviewer.value) {
             await showAlert('Input Required', "Please select a team to assess.")
             return
        }

        const currentUser = user.value?.username || 'unknown'
        
        // Prepare rescored tags if any (only for Reviewers)
        let rescoredTags: string[] | undefined = undefined
        if (isReviewer.value) {
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
            justification: (state.value === 'NOT_AFFECTED') ? justification.value : undefined,
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
             if (!force) await showAlert('Success', 'Assessment updated successfully')
             const success = results.find((r: any) => r.status === 'success')
             
             if (success) {
                 const data = {
                     rescored_cvss: isReviewer.value ? pendingScore.value : props.group.rescored_cvss,
                     rescored_vector: isReviewer.value ? pendingVector.value : props.group.rescored_vector,
                     analysis_state: success.new_state,
                     analysis_details: success.new_details,
                     is_suppressed: suppressed.value
                 }
                 emit('update:assessment', data)
             }
             showConflictModal.value = false
        }
        
        expanded.value = false
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

// ... (keep existing computed properties: displayState, severityColor, stateColor)
// ... (keep existing computed properties: severityColor, stateColor)

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
    switch (displayState.value) {
        case 'NOT_AFFECTED': return 'text-green-400'
        case 'EXPLOITABLE': return 'text-red-400'
        default: return 'text-gray-300'
    }
})


const cardStyle = computed(() => {
    switch (displayState.value) {
        case 'NOT_SET': 
            return 'bg-red-500/10 border-red-500/40 hover:bg-red-500/15'
        case 'MIXED':
            return 'bg-yellow-500/10 border-yellow-500/40 hover:bg-yellow-500/15'
        default:
            return 'bg-gray-800 border-gray-700 hover:bg-gray-750'
    }
})


const getGroupedInstances = (components: any[]) => {
    if (!components) return []
    const map = new Map<string, any>()
    
    components.forEach(comp => {
        const key = comp.component_uuid || `${comp.component_name}:${comp.component_version}`
        if (!map.has(key)) {
            map.set(key, { ...comp, usage_paths: new Set(comp.usage_paths || []) })
        } else {
            const entry = map.get(key)
            if (comp.usage_paths) {
                comp.usage_paths.forEach((p: string) => entry.usage_paths.add(p))
            }
        }
    })
    
    return Array.from(map.values()).map(c => ({
        ...c,
        usage_paths: Array.from(c.usage_paths)
    }))
}
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
</script>

<template>
  <div :class="['border rounded-lg overflow-hidden transition-colors', cardStyle]">
    <!-- Header -->
    <div 
        class="p-4 flex items-start justify-between cursor-pointer transition-colors gap-8"
        @click="expanded = !expanded"
    >
        <div>
            <div class="flex items-center gap-4 mb-2">
                <!-- ID Column -->
                <div class="w-40 shrink-0 font-mono text-lg font-bold text-yellow-400">
                    {{ group.id }}
                    <div v-if="group.aliases && group.aliases.length > 0" class="text-[11px] text-gray-400 font-medium mt-1 break-words leading-tight">
                        {{ group.aliases.join(', ') }}
                    </div>
                </div>
                
                <div class="h-5 w-0.5 bg-gray-600 shrink-0 rounded-full"></div>

                <!-- Severity Column -->
                <div class="w-24 shrink-0 flex justify-center">
                    <span :class="['px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider', severityColor]">
                        {{ group.severity || 'UNKNOWN' }}
                    </span>
                </div>

                <div class="h-5 w-0.5 bg-gray-600 shrink-0 rounded-full"></div>

                <!-- Score Column -->
                <div class="w-28 shrink-0 text-sm text-gray-300 flex items-center gap-2">
                    <span v-if="group.rescored_cvss" class="px-2 py-0.5 rounded text-xs font-bold bg-purple-900/50 text-purple-300 border border-purple-500 shadow-[0_0_10px_rgba(168,85,247,0.2)]" title="Rescored Value">
                        {{ group.rescored_cvss }}
                    </span>
                    <span v-else class="font-bold">
                        {{ group.cvss || group.cvss_score || 'N/A' }}
                    </span>
                    <span v-if="group.rescored_cvss" class="text-gray-600 line-through text-[10px]" title="Original Score">
                        {{ group.cvss || group.cvss_score }}
                    </span>
                    <span class="text-[10px] text-gray-500 font-medium uppercase">CVSS</span>
                </div>

                <div v-if="group.tags && group.tags.length > 0" class="flex items-center gap-4 flex-1 min-w-0">
                     <div class="h-5 w-0.5 bg-gray-600 shrink-0 rounded-full"></div>
                     <div class="flex gap-1.5 overflow-hidden">
                        <span 
                            v-for="tag in group.tags" 
                            :key="tag" 
                            class="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-900/40 text-blue-300 border border-blue-800/50 whitespace-nowrap"
                        >
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
                <div v-if="group.rescored_vector" class="font-mono text-[10px] text-purple-300 break-all bg-purple-900/20 p-1.5 rounded border border-purple-500/30 flex items-center gap-2">
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
            <div class="w-32 text-right">
                <div class="text-[10px] text-gray-500 font-bold uppercase tracking-wider mb-0.5">Analysis</div>
                <div 
                    :id="`state-${group.id}`"
                    :class="['font-bold text-sm truncate analysis-state-value', stateColor]"
                >
                    {{ displayState }}
                </div>
            </div>

            
            <div class="w-24 text-right">
                    <div class="text-[10px] text-gray-500 font-bold uppercase tracking-wider mb-0.5">Affected</div>
                    <div class="font-bold text-sm text-gray-300">{{ group.affected_versions?.length || 0 }} Versions</div>
                    
                    <div v-if="isPendingReview" class="mt-1 flex justify-end">
                        <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold bg-yellow-900/50 text-yellow-300 border border-yellow-700/50 uppercase tracking-wide">
                            Pending Review
                        </span>
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
                         <h4 class="font-semibold mb-2 text-gray-300">Analysis Details & Comments</h4>
                         <div v-for="v in group.affected_versions" :key="v.project_uuid" class="mb-4">
                            <h5 class="text-sm font-bold text-gray-400 mb-2">{{ v.project_name }} {{ v.project_version }}</h5>
                         
                            <div v-for="(inst, i) in getGroupedInstances(v.components)" :key="i" class="mb-2 bg-gray-900 p-3 rounded border border-gray-700 ml-2">
                                <div class="flex justify-between text-xs text-gray-500 mb-1">
                                    <span>{{ inst.component_name }} {{ inst.component_version }}</span>
                                    <span>{{ inst.analysis_state }}</span>
                                </div>
                                <div v-if="inst.analysis_details" class="text-sm text-gray-300 mb-1 p-2 bg-gray-800 rounded whitespace-pre-wrap break-all">
                                    {{ inst.analysis_details }}
                                </div>
                                <div v-if="inst.analysis_comments && inst.analysis_comments.length > 0" class="space-y-1 max-h-32 overflow-y-auto custom-scrollbar">
                                    <div v-for="(c, ci) in inst.analysis_comments" :key="ci" class="text-xs text-gray-400 italic pl-2 border-l-2 border-gray-600">
                                        {{ c.comment }} <span class="text-gray-600">- {{ new Date(c.timestamp).toLocaleDateString() }}</span>
                                    </div>
                                </div>
                                
                                <!-- Usage Graph Section (grouped) -->
                                <div class="mt-3 border-t border-gray-800 pt-2">
                                     <DependencyChainViewer 
                                        :project-uuid="v.project_uuid"
                                        :component-uuid="inst.component_uuid"
                                        :project-name="v.project_name"
                                    />
                                </div>
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
                                <button @click="showCalculatorModal = true" class="text-blue-400 hover:text-blue-300 flex items-center gap-1 cursor-pointer">
                                    <ExternalLink :size="10" /> Visual Calculator
                                </button>
                            </label>
                            <input 
                                v-model="pendingVector"
                                type="text" 
                                placeholder="CVSS:4.0/AV:N/..."
                                class="w-full p-1.5 rounded bg-gray-900 border border-gray-600 focus:border-blue-500 text-xs font-mono"
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
                                    step="0.1" 
                                    min="0" 
                                    max="10" 
                                    class="w-16 p-1.5 text-right rounded bg-gray-900 border border-gray-600 focus:border-blue-500 text-sm font-bold text-yellow-400"
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
                                <option v-for="t in group.tags" :key="t" :value="t">{{ t }}</option>
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
                                    class="w-full p-2 rounded bg-gray-800 border border-gray-600 focus:border-blue-500"
                                >
                                    <option v-for="s in ANALYSIS_STATES" :key="s.value" :value="s.value">{{ s.label }}</option>
                                </select>
                            </div>

                            <div v-if="state === 'NOT_AFFECTED'">
                                <label class="block text-xs font-semibold text-gray-400 mb-1">{{ selectedTeam ? 'Team' : 'Global' }} Justification</label>
                                <select 
                                    v-model="justification" 
                                    class="w-full p-2 rounded bg-gray-800 border border-gray-600 focus:border-blue-500"
                                >
                                    <option v-for="o in JUSTIFICATION_OPTIONS" :key="o.value" :value="o.value">{{ o.label }}</option>
                                </select>
                            </div>

                            <div>
                                <label class="block text-xs font-semibold text-gray-400 mb-1">{{ selectedTeam ? 'Team' : 'Global' }} Analysis Details</label>
                                <textarea 
                                    v-model="details" 
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

                    <!-- Comment Section (visible to all) -->
                    <div>
                        <label class="block text-xs font-semibold text-gray-400 mb-1">Comment</label>
                        <textarea 
                            v-model="comment"
                            placeholder="Add a comment for audit trail..."
                            class="w-full p-2 rounded bg-gray-800 border border-gray-600 focus:border-blue-500 h-24"
                        />
                    </div>
                    
                    <div class="flex items-center gap-2">
                        <input 
                            type="checkbox" 
                            :id="`suppress-${group.id}`"
                            v-model="suppressed"
                            class="w-4 h-4 rounded"
                        />
                        <label :for="`suppress-${group.id}`" class="text-sm">Suppress this vulnerability</label>
                    </div>
                    
                    <button 
                        @click="() => handleUpdate(false)"
                        :disabled="updating || loadingDetails || totalTargeted === 0"
                        class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded transition-colors disabled:opacity-50 cursor-pointer"
                    >
                        {{ updating ? 'Updating...' : `Apply to ${totalTargeted} ${totalTargeted === 1 ? 'instance' : 'instances'}` }}
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Grouped Calculator Modal -->
    <div v-if="showCalculatorModal" class="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
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
</style>

