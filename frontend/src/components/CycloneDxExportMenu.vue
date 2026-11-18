<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { Download, Loader2 } from '@lucide/vue'
import { getCycloneDxDownloadUrl, getProjects } from '../lib/api'

// CycloneDX documents of each version of a project: the inventory (BOM) and
// the VDR, which adds every finding with its assessment in standard fields.
const props = defineProps<{ projectName: string }>()

interface Version { uuid: string; version: string }

const open = ref(false)
const loading = ref(false)
const error = ref('')
const versions = ref<Version[]>([])
const root = ref<HTMLElement | null>(null)

const byVersionDescending = (left: Version, right: Version) =>
    right.version.localeCompare(left.version, undefined, { numeric: true, sensitivity: 'base' })

const load = async () => {
    loading.value = true
    error.value = ''
    try {
        const projects = await getProjects(props.projectName)
        versions.value = projects
            .filter(project => project.name === props.projectName && project.uuid)
            .map(project => ({ uuid: project.uuid, version: String(project.version || '') }))
            .sort(byVersionDescending)
    } catch {
        versions.value = []
        error.value = 'The versions could not be loaded.'
    } finally {
        loading.value = false
    }
}

const toggle = () => {
    open.value = !open.value
    if (open.value) void load()
}

const closeOnOutsideClick = (event: MouseEvent) => {
    if (open.value && root.value && !root.value.contains(event.target as Node)) open.value = false
}
const closeOnEscape = (event: KeyboardEvent) => {
    if (event.key === 'Escape') open.value = false
}

onMounted(() => {
    document.addEventListener('mousedown', closeOnOutsideClick)
    document.addEventListener('keydown', closeOnEscape)
})
onBeforeUnmount(() => {
    document.removeEventListener('mousedown', closeOnOutsideClick)
    document.removeEventListener('keydown', closeOnEscape)
})
</script>

<template>
    <div ref="root" class="relative shrink-0">
        <button
            type="button"
            data-testid="cyclonedx-export-button"
            title="Download CycloneDX inventory or VDR of a project version"
            aria-haspopup="true"
            :aria-expanded="open"
            class="inline-flex h-10 items-center gap-2 rounded-xl border border-white/10 bg-slate-950/35 px-3 text-xs font-semibold uppercase tracking-wider text-slate-200 transition-colors hover:bg-slate-900/55 hover:text-white"
            @click="toggle"
        >
            <Download :size="14" />
            <span class="hidden sm:inline">CycloneDX</span>
        </button>
        <div
            v-if="open"
            data-testid="cyclonedx-export-menu"
            class="absolute right-0 z-40 mt-2 w-80 rounded-xl border border-white/10 bg-slate-950 p-3 text-left shadow-2xl"
        >
            <div class="text-xs font-semibold text-white">CycloneDX per version</div>
            <p class="mt-1 text-[11px] leading-snug text-gray-400">
                <span class="font-semibold text-gray-300">Inventory</span> is the BOM.
                <span class="font-semibold text-gray-300">VDR</span> adds every finding with DTVP's
                assessment: state, rescoring, and each team's text.
            </p>
            <div v-if="loading" class="mt-3 flex items-center gap-2 text-xs text-gray-400" role="status">
                <Loader2 :size="12" class="animate-spin" /> Loading versions…
            </div>
            <div v-else-if="error" class="mt-3 text-xs text-red-300" role="alert">{{ error }}</div>
            <div v-else-if="versions.length === 0" class="mt-3 text-xs text-gray-400">
                No versions found for this project.
            </div>
            <ul v-else class="mt-3 max-h-72 space-y-1 overflow-y-auto">
                <li
                    v-for="version in versions"
                    :key="version.uuid"
                    data-testid="cyclonedx-export-version"
                    class="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-white/5"
                >
                    <span class="min-w-0 flex-1 truncate font-mono text-xs text-gray-200">
                        {{ version.version || '(no version)' }}
                    </span>
                    <a
                        :href="getCycloneDxDownloadUrl(version.uuid, 'inventory')"
                        :aria-label="`Download inventory of version ${version.version}`"
                        class="rounded border border-white/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-300 hover:bg-white/10 hover:text-white"
                    >Inventory</a>
                    <a
                        :href="getCycloneDxDownloadUrl(version.uuid, 'vdr')"
                        :aria-label="`Download VDR of version ${version.version}`"
                        class="rounded border border-blue-500/30 bg-blue-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-blue-200 hover:bg-blue-500/20"
                    >VDR</a>
                </li>
            </ul>
        </div>
    </div>
</template>
