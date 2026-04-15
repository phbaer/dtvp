<script setup lang="ts">
import { useRouter } from 'vue-router'
import { BarChart3, Layers, LayoutList, ChevronRight } from 'lucide-vue-next'

const { projectName, viewMode, isAllProjects, userRole, incompleteCount } = defineProps<{
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

const router = useRouter()

const goToAllProjects = () => {
    router.push('/')
}

const goToProject = () => {
    if (!isAllProjects) {
        router.push(`/project/${projectName}`)
    }
}

const goToThreatModel = () => {
    if (!isAllProjects) {
        router.push(`/project/${projectName}/tmrescore`)
    }
}
</script>

<template>
    <div class="flex flex-col gap-4">
        <div class="flex flex-wrap items-center gap-2">
            <button
                type="button"
                @click="goToAllProjects"
                class="inline-flex h-9 min-h-9 items-center justify-center leading-none px-4 rounded-full text-[11px] font-semibold uppercase tracking-widest transition-all border border-white/10"
                :class="isAllProjects
                    ? 'bg-white/10 text-white shadow-sm shadow-slate-900/20'
                    : 'bg-slate-950/20 text-slate-300 hover:bg-slate-950/30 hover:text-white'"
            >
                All Projects
            </button>

            <div v-if="!isAllProjects" class="flex items-center gap-2">
                <ChevronRight class="w-4 h-4 text-slate-500" />
                <button
                    type="button"
                    @click="goToProject"
                    class="inline-flex h-9 min-h-9 items-center justify-center leading-none px-4 rounded-full text-[11px] font-semibold uppercase tracking-widest transition-all border border-white/10 bg-white/10 text-white shadow-sm shadow-slate-900/20 whitespace-nowrap"
                >
                    {{ projectName }}
                </button>
            </div>

            <button
                v-if="!isAllProjects"
                type="button"
                @click="goToThreatModel"
                class="inline-flex h-9 min-h-9 items-center justify-center leading-none px-4 rounded-full text-[11px] font-semibold uppercase tracking-widest transition-all border border-white/10 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20"
            >
                Threat Model
            </button>

            <span v-if="!isAllProjects" class="h-5 w-px bg-white/10 mx-2"></span>

            <button
                v-if="!isAllProjects"
                type="button"
                @click="emit('toggle-view-mode')"
                class="inline-flex h-9 min-h-9 items-center justify-center leading-none gap-2 px-4 rounded-full text-[11px] font-semibold uppercase tracking-widest transition-all border border-white/10 bg-slate-950/20 text-slate-300 hover:bg-slate-950/30 hover:text-white"
            >
                <BarChart3 v-if="viewMode === 'analysis'" :size="14" />
                <LayoutList v-else :size="14" />
                {{ viewMode === 'analysis' ? 'Project Statistics' : 'Analysis' }}
            </button>

            <button
                v-if="!isAllProjects && userRole === 'REVIEWER' && incompleteCount > 0"
                type="button"
                @click="emit('show-bulk-modal')"
                class="inline-flex h-9 min-h-9 items-center justify-center leading-none gap-2 px-4 rounded-full text-[11px] font-semibold uppercase tracking-widest transition-all border border-white/10 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20"
            >
                <Layers :size="14" />
                Bulk Sync ({{ incompleteCount }})
            </button>
        </div>
    </div>
</template>
