<script setup lang="ts">
import { ref, computed } from 'vue'
import { LayoutList, Copy } from 'lucide-vue-next'

export interface TeamEntry {
    team: string
    open: number
    assessed: number
}

export interface DependencyCounts {
    direct: number
    transitive: number
    unknown: number
}

const props = defineProps<{
    filteredCount: number
    dependencyCounts: DependencyCounts
    teamTagList: TeamEntry[]
    cacheStatusState: 'cached' | 'partial' | 'unknown' | 'loading'
    cacheStatusLabel: string
    cacheStatusAge: string
    cacheStatusTooltip: string
}>()

const copiedStats = ref(false)

const statsText = computed(() => {
    const lines = [
        `Findings: ${props.filteredCount}`,
        `Direct: ${props.dependencyCounts.direct}`,
        `Transitive: ${props.dependencyCounts.transitive}`,
        `Unknown: ${props.dependencyCounts.unknown}`
    ]

    if (props.teamTagList.length) {
        lines.push('Per Team:')
        props.teamTagList.forEach(entry => {
            lines.push(`  ${entry.team}: Open ${entry.open}, Assessed ${entry.assessed}`)
        })
    }

    return lines.join('\n')
})

const copyStatistics = async () => {
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(statsText.value)
        } else {
            const textarea = document.createElement('textarea')
            document.body.appendChild(textarea)
            textarea.value = statsText.value
            textarea.select()
            document.execCommand('copy')
            document.body.removeChild(textarea)
        }

        copiedStats.value = true
        setTimeout(() => {
            copiedStats.value = false
        }, 2000)
    } catch (e) {
        console.error('Failed to copy statistics', e)
    }
}
</script>

<template>
    <div class="sticky top-4 self-start w-full max-w-[280px] flex-shrink-0 space-y-3">
        <div class="relative shadow-xl bg-white/2 border border-white/5 rounded-2xl p-5 backdrop-blur-sm">
            <button
                @click="copyStatistics"
                class="absolute top-3 right-3 text-gray-200 hover:text-white p-1 rounded-full border border-white/10 bg-white/5 hover:bg-white/15 transition-colors"
                title="Copy statistics to clipboard"
            >
                <Copy :size="14" />
            </button>
            <span v-if="copiedStats" class="absolute top-3 right-12 text-[10px] text-green-300">Copied!</span>
            <div class="text-[10px] font-black uppercase tracking-widest text-gray-500">Statistics</div>
            <div class="flex items-center gap-2 px-3 py-1.5 my-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                <LayoutList :size="12" class="text-blue-400" />
                <span class="text-[10px] font-black text-blue-400 uppercase tracking-widest">{{ filteredCount }} Findings</span>
            </div>
            <div class="flex flex-col gap-1">
                <div class="flex justify-between items-center px-2 py-0.5 rounded bg-green-500/10">
                    <span class="text-[10px] text-green-300">Direct</span>
                    <span class="text-[10px] font-bold text-green-200">{{ dependencyCounts.direct }}</span>
                </div>
                <div class="flex justify-between items-center px-2 py-0.5 rounded bg-purple-500/10">
                    <span class="text-[10px] text-purple-300">Transitive</span>
                    <span class="text-[10px] font-bold text-purple-200">{{ dependencyCounts.transitive }}</span>
                </div>
                <div class="flex justify-between items-center px-2 py-0.5 rounded bg-gray-500/10">
                    <span class="text-[10px] text-gray-400">Unknown</span>
                    <span class="text-[10px] font-bold text-gray-300">{{ dependencyCounts.unknown }}</span>
                </div>
            </div>
            <div v-if="teamTagList.length > 0" class="flex flex-col gap-1 mt-3">
                <div class="text-[10px] uppercase tracking-widest text-gray-500">Per Team</div>
                <div class="overflow-y-auto max-h-[20rem]">
                    <table class="min-w-full table-auto text-left text-[10px] text-gray-300 border-separate border-spacing-0">
                        <thead class="border-b border-white/10 sticky top-0 bg-white/5">
                            <tr class="text-gray-400 uppercase text-[9px] tracking-widest">
                                <th class="px-2 py-1">Team</th>
                                <th class="px-2 py-1 text-right">Open</th>
                                <th class="px-2 py-1 text-right">Assessed</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr
                                v-for="entry in teamTagList"
                                :key="entry.team"
                                class="border-t border-white/5"
                            >
                                <td class="px-2 py-0.5 text-[10px] text-gray-200">{{ entry.team }}</td>
                                <td class="px-2 py-0.5 text-right text-[10px] text-orange-200">{{ entry.open }}</td>
                                <td class="px-2 py-0.5 text-right text-[10px] text-cyan-200">{{ entry.assessed }}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div
            class="shadow-xl bg-white/2 border border-white/5 rounded-2xl p-5 backdrop-blur-sm"
            :title="cacheStatusTooltip"
        >
            <div class="text-[10px] font-black uppercase tracking-widest text-gray-500 mb-3">Cache Status</div>
            <div
                class="flex items-center gap-3 px-3 py-1.5 rounded-lg border"
                :class="[
                    cacheStatusState === 'cached' ? 'bg-emerald-500/10 border-emerald-300/20 text-emerald-200' :
                    cacheStatusState === 'partial' ? 'bg-amber-500/10 border-amber-300/20 text-amber-200' :
                    cacheStatusState === 'loading' ? 'bg-sky-500/10 border-sky-300/20 text-sky-200' :
                    'bg-gray-500/10 border-white/10 text-gray-300'
                ]"
            >
                <span :class="[
                    'inline-flex h-2.5 w-2.5 rounded-full',
                    cacheStatusState === 'cached' ? 'bg-emerald-400' :
                    cacheStatusState === 'partial' ? 'bg-amber-400' :
                    cacheStatusState === 'loading' ? 'bg-sky-400' :
                    'bg-slate-400'
                ]"></span>
                <div class="flex flex-col gap-0.5 truncate">
                    <span class="text-[10px] font-black uppercase tracking-widest truncate">{{ cacheStatusLabel }}</span>
                    <span class="text-[10px] text-gray-400 truncate">{{ cacheStatusAge }}</span>
                </div>
            </div>
        </div>
    </div>
</template>
