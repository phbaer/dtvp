<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import {
    GROUP_ORDER,
    PULL_REQUEST_URL,
    entryCount,
    mergeGroups,
    topEntries,
    type Release,
    type ReleaseGroup,
} from '../lib/whatsNew'

// major: an upgrade to a new major version, shown prominently.
// compact: a minor or patch upgrade, a short list with "Show all".
// browse: opened by the user; every release, one at a time.
type Mode = 'major' | 'compact' | 'browse'

const props = defineProps<{
    mode: Mode
    currentVersion: string
    // The releases since the user's last visit (major, compact), newest first.
    shown: Release[]
    // Every release of this build, newest first (browse).
    releases: Release[]
    // The version the user had before, for the heading.
    previousVersion?: string | null
}>()

const emit = defineEmits<{ (e: 'close'): void }>()

const COMPACT_LIMIT = 5
const expanded = ref(false)
const root = ref<HTMLElement | null>(null)
let restoreFocus: HTMLElement | null = null

const GROUP_LABEL: Record<ReleaseGroup, string> = {
    breaking: 'Action needed',
    new: 'New',
    faster: 'Faster',
    fixed: 'Fixed',
}
const GROUP_CLASS: Record<ReleaseGroup, string> = {
    breaking: 'text-amber-300',
    new: 'text-emerald-300',
    faster: 'text-cyan-300',
    fixed: 'text-blue-300',
}

const browsable = computed(() =>
    props.releases.filter(release => entryCount(release) > 0),
)
const releaseLabel = (release: Release) =>
    release.unreleased ? 'Not yet released' : `v${release.version}`
const releaseKey = (release: Release) => release.version ?? 'unreleased'

const initialBrowseKey = () => {
    const current = browsable.value.find(release => release.version === props.currentVersion)
    return releaseKey(current ?? browsable.value.find(release => !release.unreleased) ?? browsable.value[0] ?? {
        version: null,
    } as Release)
}
const selectedKey = ref(initialBrowseKey())
const selectedRelease = computed(() =>
    browsable.value.find(release => releaseKey(release) === selectedKey.value) ?? null,
)

const visibleReleases = computed<Release[]>(() =>
    props.mode === 'browse'
        ? (selectedRelease.value ? [selectedRelease.value] : [])
        : props.shown,
)
const groups = computed(() => mergeGroups(visibleReleases.value))
const severalVersions = computed(() => visibleReleases.value.length > 1)
const total = computed(() => visibleReleases.value.reduce((sum, release) => sum + entryCount(release), 0))
const compactEntries = computed(() => topEntries(props.shown, COMPACT_LIMIT))
const showFullList = computed(() => props.mode !== 'compact' || expanded.value)

const title = computed(() => {
    if (props.mode === 'browse') return "What's new"
    return props.mode === 'major'
        ? `DTVP ${props.currentVersion}`
        : `What's new in DTVP ${props.currentVersion}`
})
const subtitle = computed(() => {
    if (props.mode === 'browse') return `You are running DTVP ${props.currentVersion}.`
    if (props.previousVersion) return `Changes since ${props.previousVersion}.`
    return ''
})

const dialogWidth = computed(() => {
    if (props.mode === 'major') return 'max-w-3xl'
    if (props.mode === 'browse') return 'max-w-4xl'
    return expanded.value ? 'max-w-2xl' : 'max-w-md'
})

const focusables = () =>
    Array.from(
        root.value?.querySelectorAll<HTMLElement>(
            'a[href], button:not([disabled]), summary, [tabindex]:not([tabindex="-1"])',
        ) ?? [],
    ).filter(element => element.offsetParent !== null || element === document.activeElement)

const onKeydown = (event: KeyboardEvent) => {
    if (event.key === 'Escape') {
        event.preventDefault()
        emit('close')
        return
    }
    if (event.key !== 'Tab') return
    const items = focusables()
    if (items.length === 0) return
    const first = items[0]
    const last = items[items.length - 1]
    const active = document.activeElement as HTMLElement | null
    if (event.shiftKey && (active === first || !root.value?.contains(active))) {
        event.preventDefault()
        last.focus()
    } else if (!event.shiftKey && (active === last || !root.value?.contains(active))) {
        event.preventDefault()
        first.focus()
    }
}

const showAll = async () => {
    expanded.value = true
    await nextTick()
    root.value?.querySelector<HTMLElement>('[data-testid="whats-new-full"]')?.focus()
}

onMounted(async () => {
    restoreFocus = document.activeElement as HTMLElement | null
    document.addEventListener('keydown', onKeydown)
    await nextTick()
    root.value?.querySelector<HTMLElement>('[data-autofocus]')?.focus()
})

onBeforeUnmount(() => {
    document.removeEventListener('keydown', onKeydown)
    restoreFocus?.focus?.()
})
</script>

<template>
    <div
        class="fixed inset-0 bg-black/80 flex items-center justify-center p-4"
        style="z-index: 10000"
        data-testid="whats-new-backdrop"
        @click.self="emit('close')"
    >
        <div
            ref="root"
            role="dialog"
            aria-modal="true"
            aria-labelledby="whats-new-title"
            :data-testid="`whats-new-${mode}`"
            :class="['bg-gray-800 border border-gray-700 rounded-lg shadow-2xl w-full max-h-[85vh] flex flex-col', dialogWidth]"
        >
            <!-- Header -->
            <div
                :class="[
                    'border-b border-gray-700 flex justify-between items-start gap-4',
                    mode === 'major' ? 'p-6 bg-gradient-to-r from-blue-900/60 to-gray-800 rounded-t-lg' : 'p-4',
                ]"
            >
                <div>
                    <p v-if="mode === 'major'" class="text-xs font-semibold uppercase tracking-wider text-blue-300">
                        New major version
                    </p>
                    <h2
                        id="whats-new-title"
                        :class="mode === 'major' ? 'text-3xl font-bold text-white mt-1' : 'font-bold text-lg text-blue-300'"
                    >
                        {{ title }}
                    </h2>
                    <p v-if="subtitle" class="text-sm text-gray-400 mt-1">{{ subtitle }}</p>
                </div>
                <button
                    type="button"
                    class="text-gray-400 hover:text-white transition-colors"
                    aria-label="Close what's new"
                    @click="emit('close')"
                >
                    ✕
                </button>
            </div>

            <div class="flex min-h-0 flex-1">
                <!-- Version list (browse) -->
                <nav
                    v-if="mode === 'browse'"
                    aria-label="Versions"
                    class="w-44 shrink-0 overflow-y-auto border-r border-gray-700 p-2"
                    data-testid="whats-new-versions"
                >
                    <p v-if="browsable.length === 0" class="p-2 text-xs text-gray-500">No release notes in this build.</p>
                    <button
                        v-for="release in browsable"
                        :key="releaseKey(release)"
                        type="button"
                        :aria-current="releaseKey(release) === selectedKey ? 'true' : undefined"
                        :class="[
                            'w-full rounded px-2 py-1.5 text-left text-sm transition-colors',
                            releaseKey(release) === selectedKey ? 'bg-blue-600/30 text-white' : 'text-gray-300 hover:bg-gray-700',
                        ]"
                        @click="selectedKey = releaseKey(release)"
                    >
                        <span class="font-medium">{{ releaseLabel(release) }}</span>
                        <span v-if="release.prerelease" class="ml-1 text-[10px] uppercase text-amber-300">pre</span>
                        <span v-if="release.date" class="block text-[11px] text-gray-500">{{ release.date }}</span>
                    </button>
                </nav>

                <!-- Content -->
                <div class="min-w-0 flex-1 overflow-y-auto p-6" tabindex="-1" data-testid="whats-new-full">
                    <template v-if="!showFullList">
                        <ul class="space-y-2" data-testid="whats-new-compact-list">
                            <li v-for="(entry, index) in compactEntries" :key="index" class="text-sm text-gray-200">
                                <span
                                    v-if="entry.breaking"
                                    class="mr-1 rounded bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-bold uppercase text-amber-300"
                                >Action needed</span>
                                <span v-if="entry.scope" class="mr-1 rounded bg-gray-700 px-1.5 py-0.5 text-[10px] text-gray-300">{{ entry.scope }}</span>
                                {{ entry.text }}
                                <a
                                    v-if="entry.pr"
                                    :href="`${PULL_REQUEST_URL}${entry.pr}`"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    class="ml-1 text-xs text-blue-300 hover:text-blue-200"
                                >#{{ entry.pr }}</a>
                                <p v-if="entry.note" class="mt-0.5 text-xs text-amber-200/80">{{ entry.note }}</p>
                            </li>
                        </ul>
                        <p v-if="total > compactEntries.length" class="mt-3 text-xs text-gray-400">
                            and {{ total - compactEntries.length }} more
                        </p>
                    </template>

                    <template v-else>
                        <p v-if="total === 0" class="text-sm text-gray-400">No changes for users are listed for this version.</p>
                        <template v-for="group in GROUP_ORDER" :key="group">
                            <component
                                :is="group === 'fixed' && mode === 'major' ? 'details' : 'section'"
                                v-if="groups[group].length"
                                class="mb-5"
                                :data-testid="`whats-new-group-${group}`"
                            >
                                <component
                                    :is="group === 'fixed' && mode === 'major' ? 'summary' : 'h3'"
                                    :class="['mb-2 font-semibold cursor-default', GROUP_CLASS[group], group === 'fixed' && mode === 'major' ? 'cursor-pointer' : '']"
                                >
                                    {{ GROUP_LABEL[group] }}
                                    <span class="text-xs font-normal text-gray-500">({{ groups[group].length }})</span>
                                </component>
                                <ul
                                    :class="[
                                        'space-y-2',
                                        group === 'breaking' ? 'rounded-md border border-amber-500/40 bg-amber-500/10 p-3' : '',
                                    ]"
                                >
                                    <li v-for="(entry, index) in groups[group]" :key="index" class="text-sm text-gray-200">
                                        <span v-if="entry.scope" class="mr-1 rounded bg-gray-700 px-1.5 py-0.5 text-[10px] text-gray-300">{{ entry.scope }}</span>
                                        {{ entry.text }}
                                        <a
                                            v-if="entry.pr"
                                            :href="`${PULL_REQUEST_URL}${entry.pr}`"
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            class="ml-1 text-xs text-blue-300 hover:text-blue-200"
                                        >#{{ entry.pr }}</a>
                                        <span v-if="severalVersions && entry.version" class="ml-1 text-[10px] text-gray-500">v{{ entry.version }}</span>
                                        <p v-if="entry.note" class="mt-0.5 text-xs text-amber-200/80">{{ entry.note }}</p>
                                    </li>
                                </ul>
                            </component>
                        </template>
                    </template>
                </div>
            </div>

            <!-- Footer -->
            <div class="p-4 border-t border-gray-700 flex items-center justify-end gap-3">
                <button
                    v-if="mode === 'compact' && !expanded && total > 0"
                    type="button"
                    class="text-sm text-blue-300 hover:text-blue-200"
                    data-testid="whats-new-show-all"
                    @click="showAll"
                >
                    Show all
                </button>
                <button
                    type="button"
                    data-autofocus
                    class="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded-md font-medium transition-colors shadow-lg active:scale-95"
                    @click="emit('close')"
                >
                    {{ mode === 'browse' ? 'Close' : 'Got it' }}
                </button>
            </div>
        </div>
    </div>
</template>
