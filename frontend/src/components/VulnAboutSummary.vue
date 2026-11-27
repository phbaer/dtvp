<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, useId, watch } from 'vue'
import { ChevronDown, ChevronRight, ExternalLink } from '@lucide/vue'
import { markdownToPlainText } from '../lib/safeMarkdown'

/**
 * A short summary of the advisory at the top of the assessment form, so the
 * decision is taken with the vulnerability in view: the start of the
 * description, expandable in place, and the key facts on one line. Plain
 * text only; the Context tab has the full rendering. In the assessment
 * workspace, where the Context pane shows the description, it starts folded.
 */
const props = defineProps<{
    vulnId: string
    title?: string | null
    description?: string | null
    cwes?: Array<{ id: number, name?: string | null }> | null
    recommendation?: string | null
    cvssVector?: string | null
    /** Reported components in the selected assessment scope, with their versions. */
    components: Array<{ name: string, versions: string[] }>
    /** Project versions the components in scope are found in. */
    projectVersions: string[]
    links: Array<{ label: string, url: string }>
    /** Start folded to one line: the assessment workspace shows the full
     * description beside the form. */
    collapsed?: boolean
}>()

const MAX_COMPONENTS = 3
// Longer text, or more blocks than fit, is clamped with "Show more".
const CLAMP_CHARACTERS = 260
const CLAMP_LINES = 3

const id = useId()
const open = ref(!props.collapsed)
watch(() => props.collapsed, collapsed => { open.value = !collapsed })
const showAll = ref(false)

const shownTitle = computed(() => {
    const title = (props.title || '').trim()
    return title && title !== props.vulnId ? title : ''
})
const text = computed(() => markdownToPlainText(props.description || ''))
// Whether the clamped text is cut off, measured where there is layout;
// estimated from its length where there is none.
const descriptionEl = ref<HTMLElement | null>(null)
const overflowing = ref<boolean | null>(null)
const measure = () => {
    const element = descriptionEl.value
    if (!element || showAll.value) return
    overflowing.value = element.clientHeight > 0 ? element.scrollHeight > element.clientHeight + 1 : null
}
const canExpand = computed(() => showAll.value || (overflowing.value ?? (
    text.value.length > CLAMP_CHARACTERS || text.value.split('\n').length > CLAMP_LINES
)))
// The form may be hidden when this mounts (another tab is open): measure
// again whenever the description changes size, including when it appears.
let observer: ResizeObserver | null = null
watch(descriptionEl, (element, previous) => {
    if (previous) observer?.unobserve(previous)
    if (element) observer?.observe(element)
})
watch([text, open], () => { overflowing.value = null; void nextTick(measure) })
onMounted(() => {
    if (typeof ResizeObserver !== 'undefined') {
        observer = new ResizeObserver(() => measure())
        if (descriptionEl.value) observer.observe(descriptionEl.value)
    }
    void nextTick(measure)
})
onUnmounted(() => observer?.disconnect())
const recommendation = computed(() => markdownToPlainText(props.recommendation || '').replace(/\n/g, ' '))

const componentSummary = computed(() => props.components
    .slice(0, MAX_COMPONENTS)
    .map(component => component.versions.length
        ? `${component.name} ${component.versions.join(', ')}`
        : component.name))
const hiddenComponents = computed(() => Math.max(0, props.components.length - MAX_COMPONENTS))

const METRICS: Record<string, Record<string, string>> = {
    AV: { N: 'network', A: 'adjacent network', L: 'local', P: 'physical access' },
    AC: { L: 'low complexity', M: 'medium complexity', H: 'high complexity' },
    AT: { P: 'attack requirements present' },
    PR: { N: 'no privileges', L: 'low privileges', H: 'high privileges' },
    Au: { N: 'no authentication', S: 'single authentication', M: 'multiple authentication' },
}
const USER_INTERACTION: Record<string, Record<string, string>> = {
    '3': { N: 'no user interaction', R: 'user interaction' },
    '4': { N: 'no user interaction', P: 'passive user interaction', A: 'active user interaction' },
}

/** What an attacker needs, in words, from the advisory's CVSS base vector. */
const attackConditions = computed(() => {
    const vector = (props.cvssVector || '').trim()
    if (!vector) return ''
    const major = vector.match(/^CVSS:(\d)/)?.[1] || '2'
    const values = new Map<string, string>()
    for (const part of vector.split('/')) {
        const [key, value] = part.split(':')
        if (key && value && !values.has(key)) values.set(key, value)
    }
    const words: string[] = []
    for (const key of major === '2' ? ['AV', 'AC', 'Au'] : ['AV', 'AC', 'AT', 'PR']) {
        const word = METRICS[key]?.[values.get(key) || '']
        if (word) words.push(word)
    }
    const interaction = USER_INTERACTION[major]?.[values.get('UI') || '']
    if (interaction) words.push(interaction)
    return words.join(', ')
})

/** One CWE with its name; several by number, the names in the tooltip. */
const cweSummary = computed(() => {
    const cwes = props.cwes || []
    if (cwes.length === 1) return [`CWE-${cwes[0].id}`, cwes[0].name].filter(Boolean).join(' ')
    return cwes.map(cwe => `CWE-${cwe.id}`).join(', ')
})
const cweNames = computed(() => (props.cwes || [])
    .filter(cwe => cwe.name)
    .map(cwe => `CWE-${cwe.id}: ${cwe.name}`)
    .join('\n'))
</script>

<template>
    <section
        data-testid="vuln-about"
        class="rounded-lg border border-gray-700/70 bg-gray-900/45 px-4 py-2.5"
        :aria-labelledby="`${id}-heading`"
    >
        <h4 :id="`${id}-heading`" class="flex min-w-0 items-center gap-2 text-xs">
            <button
                type="button"
                class="inline-flex shrink-0 items-center gap-1 font-bold text-gray-200 hover:text-white"
                :aria-expanded="open ? 'true' : 'false'"
                :aria-controls="`${id}-body`"
                data-testid="vuln-about-toggle"
                @click="open = !open"
            >
                <ChevronDown v-if="open" :size="13" aria-hidden="true" />
                <ChevronRight v-else :size="13" aria-hidden="true" />
                About this vulnerability
            </button>
            <span v-if="!open && (shownTitle || text)" class="min-w-0 truncate font-normal text-gray-500">
                {{ shownTitle || text }}
            </span>
        </h4>
        <div v-if="open" :id="`${id}-body`" class="mt-1.5 space-y-1.5 pl-[18px]">
            <p v-if="shownTitle" class="text-sm font-semibold text-gray-100" data-testid="vuln-about-title">{{ shownTitle }}</p>
            <p
                ref="descriptionEl"
                data-testid="vuln-about-description"
                class="whitespace-pre-line text-xs leading-relaxed"
                :class="[text ? 'text-gray-300' : 'italic text-gray-500', showAll ? '' : 'line-clamp-3']"
            >{{ text || 'No description available.' }}</p>
            <button
                v-if="canExpand"
                type="button"
                data-testid="vuln-about-more"
                class="text-[11px] font-semibold text-cyan-300 hover:text-cyan-200"
                :aria-expanded="showAll ? 'true' : 'false'"
                @click="showAll = !showAll"
            >
                {{ showAll ? 'Show less' : 'Show more' }}
            </button>
            <dl data-testid="vuln-about-facts" class="flex flex-wrap gap-x-4 gap-y-1 text-[11px] leading-snug">
                <div v-if="components.length" class="flex min-w-0 gap-1" data-testid="vuln-about-affects">
                    <dt class="shrink-0 text-gray-500">Reported</dt>
                    <dd class="min-w-0 text-gray-300">
                        <span class="font-mono">{{ componentSummary.join(' · ') }}</span>
                        <template v-if="hiddenComponents"> +{{ hiddenComponents }} more</template>
                        <span v-if="projectVersions.length" class="text-gray-500">
                            in {{ projectVersions.length === 1 ? `version ${projectVersions[0]}` : `${projectVersions.length} versions` }}
                        </span>
                    </dd>
                </div>
                <div v-if="attackConditions" class="flex min-w-0 gap-1" data-testid="vuln-about-attack" :title="cvssVector || undefined">
                    <dt class="shrink-0 text-gray-500">Attack</dt>
                    <dd class="min-w-0 text-gray-300">{{ attackConditions }}</dd>
                </div>
                <div v-if="cweSummary" class="flex min-w-0 gap-1" data-testid="vuln-about-cwe" :title="cweNames || undefined">
                    <dt class="sr-only">Weakness</dt>
                    <dd class="min-w-0 text-gray-300">{{ cweSummary }}</dd>
                </div>
                <div v-if="recommendation" class="flex min-w-0 basis-full gap-1" data-testid="vuln-about-fix">
                    <dt class="shrink-0 text-gray-500">Fix</dt>
                    <dd class="min-w-0 text-gray-300">{{ recommendation }}</dd>
                </div>
                <div v-if="links.length" class="flex min-w-0 items-center gap-1.5">
                    <dt class="sr-only">References</dt>
                    <dd v-for="link in links" :key="link.url">
                        <a
                            :href="link.url"
                            target="_blank"
                            rel="noopener noreferrer"
                            class="inline-flex items-center gap-0.5 text-blue-300 hover:text-blue-200"
                        >
                            <ExternalLink :size="9" aria-hidden="true" />
                            {{ link.label }}
                        </a>
                    </dd>
                </div>
            </dl>
        </div>
    </section>
</template>
