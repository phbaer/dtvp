<script setup lang="ts">
import { BarChart3, Layers, ChevronLeft, LayoutList } from 'lucide-vue-next'

defineProps<{
    projectName: string
    viewMode: 'analysis' | 'statistics'
    isAllProjects: boolean
    userRole: string
    incompleteCount: number
}>()

const emit = defineEmits<{
    'toggle-view-mode': []
    'show-bulk-modal': []
}>()
</script>

<template>
    <div class="flex flex-col gap-2 py-4">
        <router-link to="/" class="text-blue-400 hover:text-blue-300 text-sm flex items-center gap-1.5 font-medium transition-colors">
            <ChevronLeft :size="16" />
            Back to Dashboard
        </router-link>
        <div class="flex items-center justify-between gap-6 flex-wrap">
            <h2 class="text-3xl font-extrabold tracking-tight text-white leading-none">
                {{ isAllProjects ? 'All Projects' : projectName }}
            </h2>
            <div class="flex items-center gap-3">
                <button 
                    v-if="!isAllProjects"
                    @click="emit('toggle-view-mode')"
                    class="bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 border border-blue-500/20 px-4 py-1.5 rounded-xl text-[11px] font-black uppercase tracking-widest transition-all flex items-center gap-2 group shadow-lg active:scale-95"
                >
                    <BarChart3 v-if="viewMode === 'analysis'" :size="14" class="group-hover:rotate-12 transition-transform" />
                    <LayoutList v-else :size="14" class="group-hover:-rotate-12 transition-transform" />
                    {{ viewMode === 'analysis' ? 'Project Statistics' : 'Analysis' }}
                </button>
                <button 
                    v-if="userRole === 'REVIEWER' && incompleteCount > 0"
                    @click="emit('show-bulk-modal')"
                    class="bg-amber-500/10 hover:bg-amber-500/20 text-amber-500 border border-amber-500/20 px-4 py-1.5 rounded-xl text-[11px] font-black uppercase tracking-widest transition-all flex items-center gap-2 shadow-xl shadow-amber-900/5 active:scale-95"
                >
                    <Layers :size="14" />
                    Bulk Sync ({{ incompleteCount }})
                </button>
            </div>
        </div>
    </div>
</template>
