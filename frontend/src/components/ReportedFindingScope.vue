<script setup lang="ts">
import { computed } from 'vue'
import type { Instance } from '../types'
import { stateLabel } from '../lib/teamOverview'
import { parseAssessmentBlocks } from '../lib/assessment-helpers'

const props = defineProps<{
    instances: Partial<Pick<Instance,
        'project_version' | 'component_name' | 'component_group' | 'component_version' | 'analysis_state' | 'analysis_details' | 'analysisDetails'
    >>[]
    team?: string
    teamAliases?: string[]
}>()

// Preserve the release/component/version/state association. Different saved
// states stay separate rather than presenting a combined state as a fact.
const rows = computed(() => {
    const unique = new Map<string, { key: string; product: string; component: string; version: string; state: string }>()
    const names = new Set([props.team || '', ...(props.teamAliases || [])].map(name => name.trim().toLowerCase()))
    for (const instance of props.instances) {
        const product = instance.project_version || 'Unknown product version'
        const component = [instance.component_group, instance.component_name].filter(Boolean).join('/') || 'Unknown component'
        const version = instance.component_version || 'Unknown component version'
        const ownStates = props.team
            ? parseAssessmentBlocks(instance.analysis_details || instance.analysisDetails || '')
                .filter(block => !block.historical && names.has(block.team.trim().toLowerCase()))
                .map(block => block.state || 'NOT_SET')
            : [instance.analysis_state || 'NOT_SET']
        // A team's missing block is not an explicit decision by that team,
        // even when a Global assessment or another team decides the finding.
        for (const state of new Set(ownStates.length ? ownStates : ['NOT_SET'])) {
            const key = JSON.stringify([product, component, version, state])
            unique.set(key, { key, product, component, version, state })
        }
    }
    return [...unique.values()].sort((left, right) =>
        left.product.localeCompare(right.product, undefined, { numeric: true })
        || left.component.localeCompare(right.component)
        || left.version.localeCompare(right.version, undefined, { numeric: true })
        || left.state.localeCompare(right.state),
    )
})
</script>

<template>
    <section data-testid="reported-finding-scope" class="min-w-0 max-w-full rounded-lg border border-gray-700/70 bg-gray-900/45 p-3 text-xs">
        <h4 class="font-semibold text-gray-200">{{ team ? `Reported components for ${team}` : 'Reported components — all teams' }}</h4>
        <p class="mt-1 text-gray-400">{{ team ? `Only findings owned by ${team}, including components inherited through its dependencies. The last column shows this team's own saved assessment.` : 'All findings of this vulnerability, across teams. The last column shows each saved finding assessment.' }}</p>
        <div v-if="rows.length" class="mt-2 max-h-64 overflow-auto">
            <table class="w-full text-left">
                <caption class="sr-only">{{ team ? `Component versions reported for ${team} in each product version and its own saved assessments` : 'Reported component versions in each product version and their saved finding assessments' }}</caption>
                <thead class="text-gray-400">
                    <tr>
                        <th scope="col" class="px-2 py-1">Product version</th>
                        <th scope="col" class="px-2 py-1">Component</th>
                        <th scope="col" class="px-2 py-1">Component version</th>
                        <th scope="col" class="px-2 py-1">{{ team ? `${team} assessment` : 'Saved finding assessment' }}</th>
                    </tr>
                </thead>
                <tbody class="text-gray-200">
                    <tr v-for="row in rows" :key="row.key" class="border-t border-gray-700/60">
                        <td class="px-2 py-1 font-mono">{{ row.product }}</td>
                        <td class="break-all px-2 py-1 font-mono">{{ row.component }}</td>
                        <td class="px-2 py-1 font-mono">{{ row.version }}</td>
                        <td class="px-2 py-1">{{ row.state === 'NOT_SET' ? (team ? 'Not assessed by this team' : 'Not assessed') : stateLabel(row.state) }}</td>
                    </tr>
                </tbody>
            </table>
        </div>
        <p v-else class="mt-2 text-amber-200">{{ team ? `No reported components have confirmed ownership by ${team}.` : 'No reported findings in this scope.' }}</p>
        <p class="mt-2 text-gray-400">Reported presence does not establish affectedness. Missing findings do not prove a product version is unaffected.</p>
    </section>
</template>
