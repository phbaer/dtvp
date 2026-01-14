```
<script setup lang="ts">
import { ref, computed, watch, shallowRef } from 'vue'
import { updateAssessment } from '../lib/api'
import type { GroupedVuln, AssessmentPayload } from '../types'
import { ChevronDown, ChevronUp, Shield, Calculator, ExternalLink } from 'lucide-vue-next'
import { Cvss2, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'
import DependencyChainViewer from './DependencyChainViewer.vue'

const props = defineProps<{
  group: GroupedVuln
}>()

const emit = defineEmits(['update', 'update:assessment'])

const ANALYSIS_STATES = [
    { value: 'NOT_SET', label: 'Not Set' },
    { value: 'NOT_AFFECTED', label: 'Not Affected' },
    { value: 'EXPLOITABLE', label: 'Exploitable' },
    { value: 'IN_TRIAGE', label: 'In Triage' },
    { value: 'FALSE_POSITIVE', label: 'False Positive' },
    { value: 'RESOLVED', label: 'Resolved' },
]

const expanded = ref(false)
const state = ref('NOT_SET')
const details = ref('')
const comment = ref('')
const suppressed = ref(false)
const updating = ref(false)
const pendingScore = ref<number | null>(null)
const pendingVector = ref<string>('')
const showCalculatorModal = ref(false)

// Multi-version Calculator State
// We use shallowRef for the instance to avoid deep reactivity overhead on complex objects
const activeVersion = ref<'4.0' | '3.1' | '3.0' | '2.0'>('3.1')
const activeInstance = shallowRef<any>(new Cvss3P1())

// Initialize calculator state from pendingVector
watch([showCalculatorModal, pendingVector], () => {
    if (showCalculatorModal.value) {
        let v = pendingVector.value?.trim() || ''
        try {
            if (v.startsWith('CVSS:4.0')) {
                activeVersion.value = '4.0'
                activeInstance.value = new Cvss4P0(v)
            } else if (v.startsWith('CVSS:3.')) {
                // User requested to treat all CVSS 3.x as 3.1
                activeVersion.value = '3.1'
                // Replace prefix if it's 3.0 to avoid library validation errors if needed,
                // or just pass to v3.1 calculator
                if (v.startsWith('CVSS:3.0')) {
                   v = v.replace('CVSS:3.0', 'CVSS:3.1')
                }
                activeInstance.value = new Cvss3P1(v)
            } else if (v.startsWith('CVSS:2.0') || (v.includes('/') && !v.startsWith('CVSS:'))) { // Naive v2 check
                activeVersion.value = '2.0'
                activeInstance.value = new Cvss2(v)
            } else {
                // Default to 3.1 if empty or unknown
                activeVersion.value = '3.1'
                activeInstance.value = new Cvss3P1()
            }
        } catch {
             // Fallback if parsing fails
             activeVersion.value = '3.1'
             activeInstance.value = new Cvss3P1()
        }
    }
})

// Switch version handler
const switchVersion = (ver: '4.0' | '3.1' | '3.0' | '2.0') => {
    activeVersion.value = ver
    // Reset instance to clean vector for that version
    switch(ver) {
        case '4.0': activeInstance.value = new Cvss4P0(); break;
        case '3.1': activeInstance.value = new Cvss3P1(); break;
        case '2.0': activeInstance.value = new Cvss2('AV:N/AC:L/Au:N/C:N/I:N/A:N'); break;
    }
    // Update vector immediately
    pendingVector.value = activeInstance.value.toString()
}

// Update vector when selections change
const updateCalcVector = (componentShortName: string, value: string) => {
    try {
        activeInstance.value.applyComponentString(componentShortName, value)
        // Force update of string - we need to trigger reactivity manually for the string update
        pendingVector.value = activeInstance.value.toString()
        // Force shallowRef update to trigger UI re-renders if needed (though we bind to properties)
        activeInstance.value = activeInstance.value 
    } catch (e) {
        console.error(e)
    }
}



// Grouped components for UI
const calculatorGroups = computed(() => {
    const instance = activeInstance.value
    if (!instance) return []

    // Map<ComponentCategory, VectorComponent[]>
    // We convert this to a simple array of objects for v-for
    const groups: { category: string, components: any[] }[] = []
    
    try {
        const map = instance.getRegisteredComponents()
        for (const [cat, list] of map.entries()) {
            groups.push({
                category: cat.name,
                components: list
            })
        }
    } catch (e) {
        console.error("Error getting components", e)
    }
    
    return groups
})

// Helper to get all instances
const allInstances = computed(() => {
    return props.group.affected_versions?.flatMap(v => v.components) || []
})

const displayState = computed(() => {
    const states = new Set(allInstances.value.map(i => i.analysis_state || 'NOT_SET'))
    if (states.size === 0) return 'NOT_SET'
    if (states.size > 1) return 'MIXED'
    const state = Array.from(states)[0]
    return state === 'NOT_SET' ? 'NOT_SET' : state
})

// Pre-fill form from first instance when expanded or group changes
watch(() => props.group, (newGroup) => {
    // Reset pending values
    // Use rescored value if present, otherwise fallback to original score, or null
    pendingScore.value = newGroup.rescored_cvss ?? newGroup.cvss_score ?? newGroup.cvss ?? null
    pendingVector.value = newGroup.rescored_vector || newGroup.cvss_vector || ''
    
    const firstVersion = newGroup.affected_versions?.[0]
    if (firstVersion && firstVersion.components?.length > 0) {
        const first = firstVersion.components[0]
        if (first) {
            state.value = first.analysis_state || 'NOT_SET'
            details.value = first.analysis_details || ''
            suppressed.value = first.is_suppressed || false
        }
    }
}, { immediate: true })

// Auto-calculate score when vector changes
watch(pendingVector, (newVector) => {
    if (newVector && newVector.trim().length > 5) {
        try {
            let v = newVector.trim()
            let score: number | null = null
            
            if (v.startsWith('CVSS:4.0')) {
                const cvss = new Cvss4P0(v)
                const s = cvss.calculateScores()
                score = s.overall ?? null
            } else if (v.startsWith('CVSS:3.')) {
                if (v.startsWith('CVSS:3.0')) v = v.replace('CVSS:3.0', 'CVSS:3.1')
                const cvss = new Cvss3P1(v)
                const s = cvss.calculateScores(false)
                score = s.overall ?? s.base ?? null
            } else {
                // Try CVSS v2
                const cvss = new Cvss2(v)
                const s = cvss.calculateScores()
                score = s.overall ?? s.base ?? null
            }

            if (score !== null && !isNaN(score)) {
                pendingScore.value = parseFloat(score.toFixed(1))
            }
        } catch (e) {
            // Invalid vector, ignore
        }
    }
})

// Reset to original vector from CVE
const resetVector = () => {
    if (props.group.cvss_vector) {
        pendingVector.value = props.group.cvss_vector
    } else {
        alert('No original vector available for this vulnerability.')
    }
}

const handleUpdate = async () => {
    const instances = allInstances.value
    if (!confirm(`Apply this assessment to all ${instances.length} instances?`)) return
    
    updating.value = true
    try {
        // Start with current details, but remove any existing system tags to avoid duplication
        let cleanDetails = (details.value || '')
            .replace(/\[Rescored:\s*[\d\.]+\]/g, '')
            .replace(/\[Rescored Vector:\s*[^\]]+\]/g, '')
            .trim()
        
        let finalDetails = cleanDetails
        
        // Add vector tag first if it exists
        if (pendingVector.value) {
            finalDetails = `[Rescored Vector: ${pendingVector.value}]\n${finalDetails}`.trim()
        }

        // Add score tag at the very top (primary indicator)
        if (pendingScore.value !== null && pendingScore.value !== undefined) {
             finalDetails = `[Rescored: ${pendingScore.value}]\n${finalDetails}`.trim()
        }
        
        // Ensure some spacing between tags and User details if any
        if (cleanDetails && (pendingScore.value || pendingVector.value)) {
             // If we have tags and original details, make sure there is a double newline
             const tags = []
             if (pendingScore.value) tags.push(`[Rescored: ${pendingScore.value}]`)
             if (pendingVector.value) tags.push(`[Rescored Vector: ${pendingVector.value}]`)
             finalDetails = tags.join('\n') + '\n\n' + cleanDetails
        }

        const payload: AssessmentPayload = {
            instances: instances,
            state: state.value,
            details: finalDetails,
            comment: comment.value,
            suppressed: suppressed.value
        }

        const results = await updateAssessment(payload)
        
        const errors = results.filter((r: any) => r.status === 'error')
        if (errors.length > 0) {
            console.error('Update completed with errors:', errors)
            alert(`Assessment updated with ${errors.length} errors. Check console for details.`)
        } else {
            alert('Assessment updated successfully')
            // Emit the updated assessment so the parent can update the state in memory
            emit('update:assessment', {
                rescored_cvss: pendingScore.value,
                rescored_vector: pendingVector.value,
                analysis_state: state.value,
                analysis_details: finalDetails,
                is_suppressed: suppressed.value
            })
        }
        
        expanded.value = false
    } catch (err) {
        alert('Failed to update assessment')
        console.error(err)
    } finally {
        updating.value = false
    }
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
  <div class="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
    <!-- Header -->
    <div 
        class="p-4 flex items-start justify-between cursor-pointer hover:bg-gray-750 transition-colors gap-8"
        @click="expanded = !expanded"
    >
        <div>
            <div class="flex items-center gap-4 mb-2">
                <!-- ID Column -->
                <div class="w-40 shrink-0 font-mono text-lg font-bold text-yellow-400">
                    {{ group.id }}
                </div>
                
                <div class="h-5 w-0.5 bg-gray-600 shrink-0 rounded-full"></div>

                <!-- Severity Column -->
                <div class="w-24 shrink-0 flex justify-center">
                    <span :class="['px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider', severityColor]">
                        {{ group.severity || 'UNKNOWN' }}
                    </span>
                </div>

                <div class="h-5 w-0.5 bg-gray-600 shrink-0 rounded-full"></div>

                <!-- Status Column -->
                <div class="w-24 shrink-0 flex justify-center">
                    <span v-if="displayState === 'NOT_SET'" class="px-2 py-0.5 text-[10px] font-bold rounded bg-red-900 text-red-100 border border-red-700 animate-pulse uppercase tracking-wider">
                        Unassessed
                    </span>
                    <span v-else-if="displayState === 'MIXED'" class="px-2 py-0.5 text-[10px] font-bold rounded bg-yellow-900 text-yellow-100 border border-yellow-700 uppercase tracking-wider">
                        Mixed
                    </span>
                    <span v-else class="px-2 py-0.5 text-[10px] font-bold rounded bg-blue-900/50 text-blue-200 border border-blue-800 uppercase tracking-wider">
                        {{ ANALYSIS_STATES.find(s => s.value === displayState)?.label || displayState }}
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
                <div :class="['font-bold text-sm truncate analysis-state-value', stateColor]">
                    {{ displayState }}
                </div>
            </div>
            
            <div class="w-24 text-right">
                    <div class="text-[10px] text-gray-500 font-bold uppercase tracking-wider mb-0.5">Affected</div>
                    <div class="font-bold text-sm text-gray-300">{{ group.affected_versions?.length || 0 }} Versions</div>
            </div>

            <div class="pt-1">
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
                            <h5 class="text-sm font-bold text-gray-400 mb-2">{{ v.project_version }}</h5>
                         
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
                    Bulk Assessment
                </h4>
                
                <div class="space-y-4">
                    <div>
                        <label class="block text-xs font-semibold text-gray-400 mb-1">Analysis State</label>
                        <select 
                            v-model="state" 
                            class="w-full p-2 rounded bg-gray-800 border border-gray-600 focus:border-blue-500"
                        >
                            <option v-for="s in ANALYSIS_STATES" :key="s.value" :value="s.value">{{ s.label }}</option>
                        </select>
                    </div>

                    <!-- Calculator Section -->
                    <div class="p-3 border border-gray-700 rounded bg-gray-800">
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
                        <div class="text-[10px] text-gray-600 mt-1 italic">
                            Modifying vector auto-calculates score.
                        </div>
                    </div>

                    <div>
                        <label class="block text-xs font-semibold text-gray-400 mb-1">Analysis Details</label>
                        <textarea 
                            v-model="details"
                            placeholder="Technical details..."
                            class="w-full p-2 rounded bg-gray-800 border border-gray-600 focus:border-blue-500 h-24"
                        />
                    </div>
                    
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
                        @click="handleUpdate"
                        :disabled="updating"
                        class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded transition-colors disabled:opacity-50 cursor-pointer"
                    >
                        {{ updating ? 'Updating...' : 'Apply to All' }}
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
                        @click="resetVector"
                        class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-xs font-bold text-gray-300 transition-colors"
                        title="Reset to original CVE vector"
                    >
                        Reset to Original
                    </button>
                    <button @click="showCalculatorModal = false" class="text-gray-400 hover:text-white text-xl font-bold cursor-pointer">✕</button>
                </div>
            </div>
            
            <!-- Version Tabs -->
            <div class="flex border-b border-gray-700 bg-gray-850">
                <button 
                    v-for="v in ['4.0', '3.1', '2.0']" 
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
                <div v-if="calculatorGroups.length > 0" class="space-y-6">
                    <div v-for="group in calculatorGroups" :key="group.category" class="bg-gray-850 rounded p-4 border border-gray-700">
                        <h4 class="font-bold text-blue-400 border-b border-gray-700 pb-2 mb-3 tracking-wide uppercase text-xs">
                            {{ group.category }} Metrics
                        </h4>
                        
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div v-for="comp in group.components" :key="comp.shortName" class="border-b border-gray-700 pb-2 border-opacity-50 last:border-0">
                                <label :for="`metric-${comp.shortName}`" class="block text-sm font-bold text-gray-300 mb-1" :title="comp.description">
                                    {{ comp.name }} ({{ comp.shortName }})
                                </label>
                                <select 
                                    :id="`metric-${comp.shortName}`"
                                    :value="activeInstance.getComponent(comp).shortName" 
                                    @change="updateCalcVector(comp.shortName, ($event.target as HTMLSelectElement).value)"
                                    class="w-full p-2 rounded bg-gray-900 border border-gray-600 text-sm text-gray-200 focus:border-blue-500"
                                >
                                    <option v-for="val in comp.values" :key="val.shortName" :value="val.shortName" :title="val.description">
                                        {{ val.name }} ({{ val.shortName }})
                                    </option>
                                </select>
                                <div class="text-[10px] text-gray-500 mt-1 line-clamp-1">
                                    {{ comp.description }}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div v-else class="text-center text-gray-500 p-8">
                    Loading components...
                </div>
            </div>

            <!-- Footer -->
            <div class="p-4 border-t border-gray-700 bg-gray-850">
                <div class="flex justify-between items-center">
                    <div>
                        <div class="text-xs text-gray-500 font-mono mb-1">Current Vector</div>
                        <div class="text-sm font-mono font-bold text-white break-all mb-2">{{ pendingVector }}</div>
                        <div v-if="group.cvss_vector && group.cvss_vector !== pendingVector" class="text-[10px] text-gray-500/60 font-mono flex gap-2">
                             <span class="uppercase font-bold shrink-0">Original Vector:</span>
                             <span class="break-all italic">{{ group.cvss_vector }}</span>
                        </div>
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
  </div>
</template>
