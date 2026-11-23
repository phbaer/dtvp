<script setup lang="ts">
// For a finding without an assessment: what DTVP still holds for gone
// findings of the same vulnerability (or an alias) in the same project
// version. "Use this" fills the form; nothing is saved here.
import { computed, ref, watch } from 'vue'
import { getEarlierAssessments, type EarlierAssessment } from '../lib/api'

const props = defineProps<{
    /** The findings to look up: project version and vulnerability. */
    findings: { project_uuid: string; vulnerability_uuid: string; project_version?: string }[]
}>()

const emit = defineEmits<{ (e: 'use', entry: EarlierAssessment): void }>()

interface Entry extends EarlierAssessment { project_version: string }

const entries = ref<Entry[]>([])
const loading = ref(false)

const keys = computed(() => {
    const seen = new Map<string, { project_uuid: string; vulnerability_uuid: string; project_version: string }>()
    for (const finding of props.findings) {
        if (!finding.project_uuid || !finding.vulnerability_uuid) continue
        const key = `${finding.project_uuid}/${finding.vulnerability_uuid}`
        if (!seen.has(key)) seen.set(key, { ...finding, project_version: finding.project_version || '' })
    }
    return [...seen.values()]
})

const load = async () => {
    loading.value = true
    try {
        const lists = await Promise.all(keys.value.map(async key => {
            try {
                return (await getEarlierAssessments(key.project_uuid, key.vulnerability_uuid))
                    .map(entry => ({ ...entry, project_version: key.project_version }))
            } catch {
                return []
            }
        }))
        entries.value = lists.flat()
    } finally {
        loading.value = false
    }
}

watch(() => keys.value.map(key => `${key.project_uuid}/${key.vulnerability_uuid}`).join(','), load, { immediate: true })

const componentLabel = (entry: EarlierAssessment) => {
    if (!entry.component_name && !entry.component_purl) return 'unknown component'
    return [entry.component_name || entry.component_purl, entry.component_version].filter(Boolean).join(' ')
}
const day = (value: string | null) => (value ? new Date(value).toLocaleDateString() : '')
const label = (value: string) => value.replaceAll('_', ' ')
</script>

<template>
    <div
        v-if="entries.length"
        data-testid="earlier-assessments"
        class="mt-3 rounded border border-sky-700/40 bg-sky-950/20 p-3 text-xs"
    >
        <div class="font-semibold text-sky-100">Earlier assessments</div>
        <p class="mt-1 text-sky-200/75">
            DTVP still holds these for findings of this vulnerability that are gone from the same version.
            Use one as a draft; nothing is saved until you submit, and the usual review applies.
        </p>
        <div
            v-for="entry in entries"
            :key="`${entry.component_uuid}/${entry.vulnerability_uuid}`"
            data-testid="earlier-assessment"
            class="mt-2 flex items-start justify-between gap-3 border-t border-sky-700/30 pt-2"
        >
            <div class="min-w-0 text-sky-100">
                <strong>{{ componentLabel(entry) }}</strong>
                <span v-if="entry.project_version" class="text-sky-200/60"> · {{ entry.project_version }}</span>
                <span v-if="entry.alias" class="text-sky-200/60"> · as {{ entry.vuln_id }}</span>
                · {{ label(entry.state) }}
                <span v-if="entry.justification !== 'NOT_SET'"> · {{ label(entry.justification) }}</span>
                <span v-if="entry.date" class="text-sky-200/60"> · {{ day(entry.date) }}</span>
                <p class="mt-0.5 line-clamp-2 text-sky-200/70">{{ entry.preview }}</p>
            </div>
            <button
                type="button"
                data-testid="use-earlier-assessment"
                class="shrink-0 rounded border border-sky-500/40 px-2 py-1 font-semibold text-sky-100 hover:bg-sky-500/15"
                @click="emit('use', entry)"
            >Use this</button>
        </div>
    </div>
</template>
