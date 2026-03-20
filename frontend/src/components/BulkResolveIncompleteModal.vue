<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { CheckCircle, X, Info, AlertTriangle, Loader2 } from 'lucide-vue-next'
import type { GroupedVuln } from '../types'
import { parseAssessmentBlocks, getConsensusAssessment, buildBulkSyncDetails, STATE_PRIORITY } from '../lib/assessment-helpers'
import { updateAssessment } from '../lib/api'

const props = defineProps<{
    show: boolean
    incompleteGroups: GroupedVuln[]
}>()

const emit = defineEmits(['close', 'updated'])

const selectedIds = ref<Set<string>>(new Set())
const processing = ref(false)
const progress = ref(0)
const currentAction = ref('')
const errors = ref<Array<{ id: string, message: string }>>([])  // Track per-item errors

// Initialize selection
const initializeSelection = () => {
    selectedIds.value = new Set(props.incompleteGroups.map(g => g.id))
}

const previewChanges = computed(() => {
    return props.incompleteGroups.map(group => {
        const allInstances = group.affected_versions?.flatMap(v => v.components) || []
        const allBlocks: any[] = []
        const seenTeams = new Set()

        // Collect unique team blocks across all instances.
        // If multiple instances have the same team, prefer the one with a non-NOT_SET state.
        for (const inst of allInstances) {
            if (!inst.analysis_details) continue
            const blocks = parseAssessmentBlocks(inst.analysis_details)
            for (const b of blocks) {
                if (!seenTeams.has(b.team)) {
                    allBlocks.push(b)
                    seenTeams.add(b.team)
                } else {
                    // Replace if the new block has a more informative state
                    const existingIdx = allBlocks.findIndex(eb => eb.team === b.team)
                    if (
                        existingIdx >= 0 &&
                        allBlocks[existingIdx].state === 'NOT_SET' &&
                        b.state !== 'NOT_SET'
                    ) {
                        allBlocks[existingIdx] = b
                    }
                }
            }
        }

        // Derive the authoritative Dependency Track state from the raw instances.
        const dtCandidates = allInstances
            .map(i => ({
                state: i.analysis_state || i.analysisState || 'NOT_SET',
                justification: (i as any).justification || (i as any).analysisJustification || 'NOT_SET'
            }))
            .filter(i => i.state && i.state !== 'NOT_SET')

        const dtWorstCandidate = dtCandidates
            .sort((a, b) => (STATE_PRIORITY[a.state] ?? 10) - (STATE_PRIORITY[b.state] ?? 10))[0]

        const dtStates = dtCandidates.map(i => i.state)
        const dtWorstState = dtWorstCandidate ? dtWorstCandidate.state : 'NOT_SET'
        const dtJustification = dtWorstCandidate ? dtWorstCandidate.justification : undefined

        // Find an instance that has a General block so we can extract its user comment.
        const existingGeneralText = allInstances.find(inst => {
            if (!inst.analysis_details) return false
            const blocks = parseAssessmentBlocks(inst.analysis_details)
            return blocks.some(b => b.team === 'General')
        })?.analysis_details || ''

        // Build the full text including the General/global-policy block. Ensure DT state wins.
        const { text: builtText, aggregatedState } = buildBulkSyncDetails(allBlocks, existingGeneralText, dtWorstState)

        // Also derive consensus for UI preview (state, justification) and include DT state/justification.
        const consensus = getConsensusAssessment(allBlocks, 'INCOMPLETE', dtStates, dtJustification)

        return {
            id: group.id,
            title: group.title,
            severity: group.severity,
            targetState: aggregatedState || consensus.state,
            targetDetails: builtText,
            targetJustification: consensus.justification,
            blockCount: allBlocks.length,
            allInstances,
            rescored_cvss: group.rescored_cvss,
            rescored_vector: group.rescored_vector
        }
    })
})

const handleApply = async () => {
    const toUpdate = previewChanges.value.filter(p => selectedIds.value.has(p.id))
    console.log(`[BulkSync] Starting. toUpdate count: ${toUpdate.length}, selectedIds: ${[...selectedIds.value].join(', ')}`)
    if (toUpdate.length === 0) {
        console.warn('[BulkSync] Nothing to update — selectedIds may be empty or previewChanges returned no matching items.')
        return
    }

    processing.value = true
    progress.value = 0
    errors.value = []
    
    let completed = 0
    const successfulUpdates: Array<{ id: string; data: any }> = []

    for (const change of toUpdate) {
        currentAction.value = `Updating ${change.id}...`
        console.log(`[BulkSync] Updating ${change.id}: state=${change.targetState}, instances=${change.allInstances.length}, detailsPreview=${change.targetDetails.slice(0, 120)}`)
        
        try {
            const result = await updateAssessment({
                instances: change.allInstances,
                state: change.targetState,
                // The details string already contains the full structured text
                // (all team blocks + General/global-policy block). Tell the backend
                // to accept it as-is rather than re-wrapping it into a team block.
                details: change.targetDetails,
                suppressed: false,
                justification: change.targetJustification,
                comment: 'Bulk sync of incomplete analysis states',
                comparison_mode: 'REPLACE'
            })
            console.log(`[BulkSync] ${change.id} result:`, result)

            successfulUpdates.push({
                id: change.id,
                data: {
                    analysis_state: change.targetState,
                    analysis_details: change.targetDetails,
                    justification: change.targetJustification,
                    is_suppressed: false,
                    rescored_cvss: change.rescored_cvss,
                    rescored_vector: change.rescored_vector,
                },
            })

            completed++
            progress.value = Math.round((completed / toUpdate.length) * 100)
        } catch (err: any) {
            const msg = err?.response?.data?.detail || err?.message || String(err)
            console.error(`[BulkSync] Failed to update ${change.id}:`, err)
            errors.value.push({ id: change.id, message: msg })
        }
    }
    
    processing.value = false
    emit('updated', successfulUpdates)
}

const toggleSelectAll = () => {
    if (selectedIds.value.size === props.incompleteGroups.length) {
        selectedIds.value.clear()
    } else {
        selectedIds.value = new Set(props.incompleteGroups.map(g => g.id))
    }
}

const toggleId = (id: string) => {
    if (selectedIds.value.has(id)) {
        selectedIds.value.delete(id)
    } else {
        selectedIds.value.add(id)
    }
}

watch(() => props.show, (newVal) => {
    if (newVal) initializeSelection()
})

const getSeverityClass = (sev?: string) => {
    switch (sev) {
        case 'CRITICAL': return 'bg-red-500/10 text-red-500 border-red-500/20'
        case 'HIGH': return 'bg-orange-500/10 text-orange-500 border-orange-500/20'
        case 'MEDIUM': return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'
        default: return 'bg-blue-500/10 text-blue-500 border-blue-500/20'
    }
}

const getStateClass = (state: string) => {
    switch (state) {
        case 'EXPLOITABLE': return 'text-red-400 bg-red-400/10 border-red-400/20'
        case 'NOT_AFFECTED': return 'text-green-400 bg-green-400/10 border-green-400/20'
        case 'FALSE_POSITIVE': return 'text-blue-400 bg-blue-400/10 border-blue-400/20'
        default: return 'text-gray-400 bg-gray-400/10 border-gray-400/20'
    }
}
</script>

<template>
    <div v-if="show" class="fixed inset-0 bg-[#0a0a12]/80 flex items-center justify-center p-4 z-[100] backdrop-blur-md">
        <div class="bg-[#12121e] w-full max-w-5xl max-h-[90vh] flex flex-col rounded-2xl border border-white/10 shadow-[0_32px_64px_-16px_rgba(0,0,0,0.6)] overflow-hidden animate-modal">
            
            <!-- Header: Premium & Spacious -->
            <div class="px-8 py-6 border-b border-white/5 flex justify-between items-center bg-gradient-to-r from-blue-500/10 to-transparent">
                <div class="flex items-center gap-5">
                    <div class="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center border border-blue-500/30">
                        <CheckCircle class="text-blue-400" :size="28" />
                    </div>
                    <div>
                        <h3 class="font-extrabold text-2xl text-white tracking-tight">Bulk Resolve Incomplete</h3>
                        <p class="text-xs text-gray-400 font-medium">Synchronize analysis consensus for vulnerable findings with partial assessments</p>
                    </div>
                </div>
                <button 
                    @click="!processing && $emit('close')" 
                    class="w-10 h-10 flex items-center justify-center hover:bg-white/5 rounded-full transition-all group"
                    :disabled="processing"
                >
                    <X :size="20" class="text-gray-500 group-hover:text-white transition-colors" />
                </button>
            </div>

            <!-- Main Content Area -->
            <div class="flex-1 overflow-hidden flex flex-col p-8 gap-6">
                
                <!-- Zero State -->
                <div v-if="incompleteGroups.length === 0" class="flex-1 flex flex-col items-center justify-center text-center py-20">
                    <div class="w-20 h-20 bg-gray-800/50 rounded-full flex items-center justify-center mb-6">
                        <Info :size="40" class="text-gray-600" />
                    </div>
                    <h4 class="text-xl font-bold text-gray-300 mb-2">Everything is balanced</h4>
                    <p class="text-sm text-gray-500 max-w-[320px] mb-8">No vulnerabilities currently require synchronization. All assessments are either consistent or fully categorized.</p>
                    <button @click="$emit('close')" class="px-8 py-2.5 bg-white/5 hover:bg-white/10 rounded-xl text-sm font-bold border border-white/10 transition-all">
                        Return to Project
                    </button>
                </div>

                <template v-else>
                    <!-- Quick Stats Cards: Premium Alignment -->
                    <div class="grid grid-cols-4 gap-4">
                        <div class="bg-white/2 p-4 rounded-xl border border-white/5 flex flex-col gap-1">
                            <span class="text-[10px] uppercase font-black tracking-[0.1em] text-gray-500">Available Items</span>
                            <span class="text-2xl font-black text-white">{{ incompleteGroups.length }}</span>
                        </div>
                        <div class="bg-blue-500/5 p-4 rounded-xl border border-blue-500/10 flex flex-col gap-1">
                            <span class="text-[10px] uppercase font-black tracking-[0.1em] text-blue-500/70">Selected Items</span>
                            <span class="text-2xl font-black text-blue-400">{{ selectedIds.size }}</span>
                        </div>
                        <div class="bg-white/2 p-4 rounded-xl border border-white/5 flex flex-col gap-1">
                            <span class="text-[10px] uppercase font-black tracking-[0.1em] text-gray-500">Total Instances</span>
                            <span class="text-2xl font-black text-gray-300">
                                {{ previewChanges.filter(p => selectedIds.has(p.id)).reduce((acc, p) => acc + p.allInstances.length, 0) }}
                            </span>
                        </div>
                        <div class="flex items-center justify-end">
                            <button 
                                @click="toggleSelectAll" 
                                class="px-4 py-2 rounded-xl text-xs font-black uppercase tracking-widest border transition-all"
                                :class="selectedIds.size === incompleteGroups.length 
                                    ? 'bg-red-500/5 border-red-500/20 text-red-400 hover:bg-red-500/10' 
                                    : 'bg-blue-500/5 border-blue-500/20 text-blue-400 hover:bg-blue-500/10'"
                                :disabled="processing"
                            >
                                {{ selectedIds.size === incompleteGroups.length ? 'Deselect All' : 'Select All' }}
                            </button>
                        </div>
                    </div>

                    <!-- Enhanced Table Component -->
                    <div class="flex-1 flex flex-col overflow-hidden bg-black/20 rounded-xl border border-white/5">
                        
                        <!-- Table Header: Perfectly Aligned Boxes -->
                        <div class="grid grid-cols-[60px_1fr_120px_140px_100px] gap-4 px-6 py-4 bg-white/2 border-b border-white/5 items-center">
                            <div class="flex justify-center uppercase text-[10px] font-black text-gray-600 tracking-widest leading-none">SEL</div>
                            <div class="uppercase text-[10px] font-black text-gray-600 tracking-widest leading-none">Vulnerability Details</div>
                            <div class="uppercase text-[10px] font-black text-gray-600 tracking-widest leading-none text-center">Severity</div>
                            <div class="uppercase text-[10px] font-black text-gray-600 tracking-widest leading-none text-center">Consensus Target</div>
                            <div class="uppercase text-[10px] font-black text-gray-600 tracking-widest leading-none text-right">Blocks</div>
                        </div>

                        <!-- Scrollable Row Area -->
                        <div class="flex-1 overflow-y-auto custom-scrollbar">
                            <div 
                                v-for="change in previewChanges" 
                                :key="change.id"
                                :class="[
                                    'grid grid-cols-[60px_1fr_120px_140px_100px] gap-4 px-6 py-4 border-b border-white/5 items-center transition-all cursor-pointer group',
                                    selectedIds.has(change.id) ? 'bg-blue-500/5' : 'hover:bg-white/2 bg-transparent'
                                ]"
                                @click="toggleId(change.id)"
                            >
                                <div class="flex justify-center">
                                    <div 
                                        class="w-5 h-5 rounded-md border-2 flex items-center justify-center transition-all"
                                        :class="selectedIds.has(change.id) 
                                            ? 'bg-blue-600 border-blue-400 shadow-[0_0_12px_rgba(59,130,246,0.4)]' 
                                            : 'border-white/10 group-hover:border-white/20'"
                                    >
                                        <CheckCircle v-if="selectedIds.has(change.id)" :size="12" class="text-white" />
                                    </div>
                                </div>
                                
                                <div class="min-w-0 pr-4">
                                    <div class="flex flex-col gap-0.5">
                                        <span class="font-bold text-sm text-white tracking-tight leading-tight">{{ change.id }}</span>
                                        <span class="text-[11px] font-medium text-gray-500 truncate italic" v-if="change.title">
                                            {{ change.title }}
                                        </span>
                                    </div>
                                </div>

                                <div class="flex justify-center">
                                    <span :class="['text-[10px] font-black px-2.5 py-1 rounded-lg border uppercase tracking-tight', getSeverityClass(change.severity)]">
                                        {{ change.severity }}
                                    </span>
                                </div>

                                <div class="flex justify-center">
                                    <span :class="['text-[10px] font-black px-2.5 py-1 rounded-lg border uppercase tracking-tight', getStateClass(change.targetState)]">
                                        {{ change.targetState }}
                                    </span>
                                </div>

                                <div class="text-right">
                                    <div class="flex flex-col items-end">
                                        <span class="text-xs font-bold text-gray-300">{{ change.blockCount }}</span>
                                        <span class="text-[9px] font-black text-gray-600 uppercase tracking-tighter">Sources</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Bottom Notification: Distinct Box -->
                    <div class="p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-center gap-4">
                        <div class="w-10 h-10 bg-amber-500/20 rounded-lg flex items-center justify-center shrink-0">
                            <AlertTriangle class="text-amber-500" :size="20" />
                        </div>
                        <p class="text-[11px] font-medium text-amber-500/90 leading-relaxed uppercase tracking-[0.02em]">
                            Warning: This operation will rewrite the analysis state for <span class="font-black text-amber-400 underline">{{ previewChanges.filter(p => selectedIds.has(p.id)).reduce((acc, p) => acc + p.allInstances.length, 0) }} vulnerable instances</span> using merged details from all available assessors.
                        </p>
                    </div>
                </template>
            </div>

            <!-- Modal Footer: Fixed Height, Premium -->
            <div class="px-8 py-6 border-t border-white/5 bg-black/40 flex flex-col gap-4">
                <div v-if="processing" class="space-y-2">
                    <div class="flex justify-between items-center text-[10px] font-black uppercase tracking-widest">
                        <span class="text-blue-400 animate-pulse flex items-center gap-2">
                            <Loader2 class="animate-spin" :size="12" />
                            {{ currentAction }}
                        </span>
                        <span class="text-blue-400 font-mono">{{ progress }}%</span>
                    </div>
                    <div class="w-full bg-white/5 rounded-full h-2 overflow-hidden border border-white/5">
                        <div class="bg-gradient-to-r from-blue-600 to-blue-400 h-full transition-all duration-300 shadow-[0_0_8px_rgba(59,130,246,0.5)]" :style="{ width: progress + '%' }"></div>
                    </div>
                </div>

                <!-- Error display: shows per-item failures -->
                <div v-if="errors.length > 0" class="space-y-1 max-h-24 overflow-y-auto">
                    <div class="text-[9px] font-black uppercase tracking-widest text-red-400 mb-1">
                        {{ errors.length }} item(s) failed — check browser console for details
                    </div>
                    <div 
                        v-for="e in errors" 
                        :key="e.id" 
                        class="text-[10px] text-red-400/80 bg-red-500/5 border border-red-500/10 rounded-lg px-3 py-1.5"
                    >
                        <span class="font-bold">{{ e.id }}</span>: {{ e.message }}
                    </div>
                </div>

                <div class="flex justify-end gap-4">
                    <button 
                        @click="$emit('close')" 
                        class="px-8 py-3 rounded-xl text-[11px] font-black uppercase tracking-widest text-gray-500 hover:text-white transition-all border border-transparent hover:border-white/10"
                        :disabled="processing"
                    >
                        Cancel
                    </button>
                    <button 
                        @click="handleApply"
                        class="px-10 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-[11px] font-black uppercase tracking-widest shadow-[0_8px_20px_-6px_rgba(59,130,246,0.6)] transition-all active:scale-95 disabled:opacity-30 flex items-center gap-3"
                        :disabled="processing || selectedIds.size === 0"
                    >
                        <Loader2 v-if="processing" class="animate-spin" :size="14" />
                        {{ processing ? 'Processing Synchronization...' : `Confirm Bulk Sync (${selectedIds.size})` }}
                    </button>
                </div>
            </div>
        </div>
    </div>
</template>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 6px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: transparent;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.1);
  border-radius: 10px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.2);
}

@keyframes modal-in {
    from { opacity: 0; transform: scale(0.9) translateY(20px); }
    to { opacity: 1; transform: scale(1) translateY(0); }
}
.animate-modal {
    animation: modal-in 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}
</style>
