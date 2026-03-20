<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { ShieldCheck, X, Info, Loader2 } from 'lucide-vue-next'
import type { GroupedVuln } from '../types'
import { parseAssessmentBlocks, constructAssessmentDetails } from '../lib/assessment-helpers'
import { updateAssessment } from '../lib/api'

const props = defineProps<{
    show: boolean
    needsApprovalGroups: GroupedVuln[]
}>()

const emit = defineEmits(['close', 'updated'])

const selectedIds = ref<Set<string>>(new Set())
const processing = ref(false)
const progress = ref(0)
const currentAction = ref('')
const errors = ref<Array<{ id: string, message: string }>>([])

// Initialize selection
const initializeSelection = () => {
    selectedIds.value = new Set(props.needsApprovalGroups.map(g => g.id))
}

const previewChanges = computed(() => {
    return props.needsApprovalGroups.map(group => {
        const allInstances = group.affected_versions?.flatMap(v => v.components) || []
        const allBlocks: any[] = []
        const teamToIndex = new Map<string, number>()
        const allTags = new Set<string>()
        
        for (const inst of allInstances) {
            if (!inst.analysis_details) continue
            const blocks = parseAssessmentBlocks(inst.analysis_details)
            for (const b of blocks) {
                const teamName = b.team
                const existingIndex = teamToIndex.get(teamName)
                
                if (existingIndex === undefined) {
                    teamToIndex.set(teamName, allBlocks.length)
                    allBlocks.push(b)
                } else {
                    const existingBlock = allBlocks[existingIndex]
                    const currentTimestamp = existingBlock.timestamp || 0
                    const newTimestamp = b.timestamp || 0
                    
                    if (newTimestamp > currentTimestamp) {
                        allBlocks[existingIndex] = b
                    } else if (newTimestamp === currentTimestamp) {
                        if ((b.details?.length || 0) > (existingBlock.details?.length || 0)) {
                            allBlocks[existingIndex] = b
                        }
                    }
                }
            }

            const rescoredMatch = inst.analysis_details.match(/\[Rescored:\s*[\d\.]+\]/);
            if (rescoredMatch) allTags.add(rescoredMatch[0]);

            const vectorMatch = inst.analysis_details.match(/\[Rescored Vector:\s*[^\]]+\]/);
            if (vectorMatch) allTags.add(vectorMatch[0]);
        }
        
        // Construct final text with isPending = false
        const { text: builtText, aggregatedState } = constructAssessmentDetails(allBlocks, Array.from(allTags), false)

        return {
            id: group.id,
            title: group.title,
            severity: group.severity,
            targetState: aggregatedState,
            targetDetails: builtText,
            isSuppressed: allInstances.some(inst => inst.is_suppressed),
            allInstances
        }
    })
})

const handleApply = async () => {
    const toUpdate = previewChanges.value.filter(p => selectedIds.value.has(p.id))
    if (toUpdate.length === 0) return

    processing.value = true
    progress.value = 0
    errors.value = []
    
    let completed = 0
    const successfulUpdates: Array<{ id: string; data: any }> = []

    for (const change of toUpdate) {
        currentAction.value = `Approving ${change.id}...`
        
        try {
            await updateAssessment({
                instances: change.allInstances,
                state: change.targetState,
                details: change.targetDetails,
                suppressed: change.isSuppressed,
                comment: 'Bulk approval of assessments',
                comparison_mode: 'REPLACE'
            })

            successfulUpdates.push({
                id: change.id,
                data: {
                    analysis_state: change.targetState,
                    analysis_details: change.targetDetails,
                    is_suppressed: change.isSuppressed,
                }
            })

            completed++
            progress.value = Math.round((completed / toUpdate.length) * 100)
        } catch (err: any) {
            const msg = err?.response?.data?.detail || err?.message || String(err)
            errors.value.push({ id: change.id, message: msg })
        }
    }
    
    processing.value = false
    emit('updated', successfulUpdates)
}

const toggleSelectAll = () => {
    if (selectedIds.value.size === props.needsApprovalGroups.length) {
        selectedIds.value.clear()
    } else {
        selectedIds.value = new Set(props.needsApprovalGroups.map(g => g.id))
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
            
            <!-- Header -->
            <div class="px-8 py-6 border-b border-white/5 flex justify-between items-center bg-gradient-to-r from-purple-500/10 to-transparent">
                <div class="flex items-center gap-5">
                    <div class="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center border border-purple-500/30">
                        <ShieldCheck class="text-purple-400" :size="28" />
                    </div>
                    <div>
                        <h3 class="font-extrabold text-2xl text-white tracking-tight">Bulk Approve Assessments</h3>
                        <p class="text-xs text-gray-400 font-medium">Finalize and remove pending status from multiple findings</p>
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
                <div v-if="needsApprovalGroups.length === 0" class="flex-1 flex flex-col items-center justify-center text-center py-20">
                    <div class="w-20 h-20 bg-gray-800/50 rounded-full flex items-center justify-center mb-6">
                        <Info :size="40" class="text-gray-600" />
                    </div>
                    <h4 class="text-xl font-bold text-gray-300 mb-2">Queue is Empty</h4>
                    <p class="text-sm text-gray-500 max-w-[320px] mb-8">No findings currently require approval. All assessments are either reviewed or not yet performed.</p>
                    <button @click="$emit('close')" class="px-8 py-2.5 bg-white/5 hover:bg-white/10 rounded-xl text-sm font-bold border border-white/10 transition-all">
                        Return to Project
                    </button>
                </div>

                <template v-else>
                    <!-- Quick Stats Cards -->
                    <div class="grid grid-cols-4 gap-4">
                        <div class="bg-white/2 p-4 rounded-xl border border-white/5 flex flex-col gap-1">
                            <span class="text-[10px] uppercase font-black tracking-[0.1em] text-gray-500">Awaiting Approval</span>
                            <span class="text-2xl font-black text-white">{{ needsApprovalGroups.length }}</span>
                        </div>
                        <div class="bg-purple-500/5 p-4 rounded-xl border border-purple-500/10 flex flex-col gap-1">
                            <span class="text-[10px] uppercase font-black tracking-[0.1em] text-purple-500/70">Selected for Approval</span>
                            <span class="text-2xl font-black text-purple-400">{{ selectedIds.size }}</span>
                        </div>
                        <div class="bg-white/2 p-4 rounded-xl border border-white/5 flex flex-col gap-1">
                            <span class="text-[10px] uppercase font-black tracking-[0.1em] text-gray-500">Affected Instances</span>
                            <span class="text-2xl font-black text-gray-300">
                                {{ previewChanges.filter(p => selectedIds.has(p.id)).reduce((acc, p) => acc + p.allInstances.length, 0) }}
                            </span>
                        </div>
                        <div class="flex items-center justify-end">
                            <button 
                                @click="toggleSelectAll" 
                                class="px-4 py-2 rounded-xl text-xs font-black uppercase tracking-widest border transition-all"
                                :class="selectedIds.size === needsApprovalGroups.length 
                                    ? 'bg-red-500/5 border-red-500/20 text-red-400 hover:bg-red-500/10' 
                                    : 'bg-purple-500/5 border-purple-500/20 text-purple-400 hover:bg-purple-500/10'"
                                :disabled="processing"
                            >
                                {{ selectedIds.size === needsApprovalGroups.length ? 'Deselect All' : 'Select All' }}
                            </button>
                        </div>
                    </div>

                    <!-- Enhanced Table Component -->
                    <div class="flex-1 flex flex-col overflow-hidden bg-black/20 rounded-xl border border-white/5">
                        <div class="grid grid-cols-[60px_1fr_120px_140px] gap-4 px-6 py-4 bg-white/2 border-b border-white/5 items-center">
                            <div class="flex justify-center uppercase text-[10px] font-black text-gray-600 tracking-widest">SEL</div>
                            <div class="uppercase text-[10px] font-black text-gray-600 tracking-widest">Vulnerability Details</div>
                            <div class="uppercase text-[10px] font-black text-gray-600 tracking-widest text-center">Severity</div>
                            <div class="uppercase text-[10px] font-black text-gray-600 tracking-widest text-center">Analysis State</div>
                        </div>

                        <div class="flex-1 overflow-y-auto custom-scrollbar">
                            <div 
                                v-for="change in previewChanges" 
                                :key="change.id"
                                :class="[
                                    'grid grid-cols-[60px_1fr_120px_140px] gap-4 px-6 py-4 border-b border-white/5 items-center transition-all cursor-pointer group',
                                    selectedIds.has(change.id) ? 'bg-purple-500/5' : 'hover:bg-white/2 bg-transparent'
                                ]"
                                @click="toggleId(change.id)"
                            >
                                <div class="flex justify-center">
                                    <div 
                                        class="w-5 h-5 rounded-md border-2 flex items-center justify-center transition-all"
                                        :class="selectedIds.has(change.id) 
                                            ? 'bg-purple-600 border-purple-400 shadow-[0_0_12px_rgba(147,51,234,0.4)]' 
                                            : 'border-white/10 group-hover:border-white/20'"
                                    >
                                        <ShieldCheck v-if="selectedIds.has(change.id)" :size="12" class="text-white" />
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
                            </div>
                        </div>
                    </div>

                    <!-- Bottom Warning -->
                    <div class="p-4 bg-purple-500/10 border border-purple-500/20 rounded-xl flex items-center gap-4">
                        <div class="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center shrink-0">
                            <ShieldCheck class="text-purple-500" :size="20" />
                        </div>
                        <p class="text-[11px] font-medium text-purple-500/90 leading-relaxed uppercase tracking-[0.02em]">
                            Note: Bulk approval will remove the <span class="font-black text-purple-400 underline">Pending Review</span> status for <span class="font-black text-purple-400 underline">{{ previewChanges.filter(p => selectedIds.has(p.id)).reduce((acc, p) => acc + p.allInstances.length, 0) }} vulnerable instances</span>.
                        </p>
                    </div>
                </template>
            </div>

            <!-- Modal Footer -->
            <div class="px-8 py-6 border-t border-white/5 bg-black/40 flex flex-col gap-4">
                <div v-if="processing" class="space-y-2">
                    <div class="flex justify-between items-center text-[10px] font-black uppercase tracking-widest">
                        <span class="text-purple-400 animate-pulse flex items-center gap-2">
                            <Loader2 class="animate-spin" :size="12" />
                            {{ currentAction }}
                        </span>
                        <span class="text-purple-400 font-mono">{{ progress }}%</span>
                    </div>
                    <div class="w-full bg-white/5 rounded-full h-2 overflow-hidden border border-white/5">
                        <div class="bg-gradient-to-r from-purple-600 to-purple-400 h-full transition-all duration-300 shadow-[0_0_8px_rgba(147,51,234,0.5)]" :style="{ width: progress + '%' }"></div>
                    </div>
                </div>

                <!-- Error display -->
                <div v-if="errors.length > 0" class="space-y-1 max-h-24 overflow-y-auto">
                    <div class="text-[9px] font-black uppercase tracking-widest text-red-400 mb-1">
                        {{ errors.length }} item(s) failed
                    </div>
                    <div v-for="e in errors" :key="e.id" class="text-[10px] text-red-400/80 bg-red-500/5 border border-red-500/10 rounded-lg px-3 py-1.5">
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
                        class="px-10 py-3 bg-purple-600 hover:bg-purple-500 text-white rounded-xl text-[11px] font-black uppercase tracking-widest shadow-[0_8px_20px_-6px_rgba(147,51,234,0.6)] transition-all active:scale-95 disabled:opacity-30 flex items-center gap-3"
                        :disabled="processing || selectedIds.size === 0"
                    >
                        <Loader2 v-if="processing" class="animate-spin" :size="14" />
                        {{ processing ? 'Processing Approval...' : `Confirm Bulk Approve (${selectedIds.size})` }}
                    </button>
                </div>
            </div>
        </div>
    </div>
</template>

<style scoped>
.custom-scrollbar::-webkit-scrollbar { width: 6px; }
.custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
.custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.1); border-radius: 10px; }
.custom-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.2); }

@keyframes modal-in {
    from { opacity: 0; transform: scale(0.9) translateY(20px); }
    to { opacity: 1; transform: scale(1) translateY(0); }
}
.animate-modal { animation: modal-in 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
</style>
