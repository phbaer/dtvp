<script setup lang="ts">
// Saved views (each with its short link) and default views of the project review
// (ADR 0015, docs/review-workflows.md#saved-views-and-short-links).
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { Bookmark, Check, ChevronDown, Globe, Link2, Pencil, RefreshCw, Star, Trash2 } from '@lucide/vue'
import {
    createSavedView,
    deleteSavedView,
    listSavedViews,
    setDefaultView,
    updateSavedView,
    type SavedView,
    type SavedViewList,
} from '../lib/api'

const props = defineProps<{
    project: string
    /** The canonical query string of the current filters. */
    currentQuery: string
    /** The full URL of the current filters: unsaved filters have no short link. */
    currentUrl: string
}>()

const emit = defineEmits<{
    apply: [query: string]
    'defaults-changed': []
}>()

const router = useRouter()
const isOpen = ref(false)
const loading = ref(false)
const error = ref('')
const notice = ref('')
const data = ref<SavedViewList | null>(null)
const triggerRef = ref<HTMLElement | null>(null)
const menuRef = ref<HTMLElement | null>(null)
const menuStyle = ref<Record<string, string>>({})
const newName = ref('')
const newAllProjects = ref(false)
const newGlobal = ref(false)
const renaming = ref<string | null>(null)
const renameText = ref('')
const confirmingDelete = ref<string | null>(null)
const roleDefaultScope = ref<'project' | 'all'>('project')

const views = computed(() => data.value?.views || [])
const personalViews = computed(() => views.value.filter(view => view.scope === 'personal'))
const globalViews = computed(() => views.value.filter(view => view.scope === 'global'))
const defaults = computed(() => data.value?.defaults)
const canManageGlobal = computed(() => !!data.value?.can_manage_global)
const currentView = computed(() => views.value.find(view => view.query === props.currentQuery) || null)
const effectiveName = computed(() => {
    const effective = defaults.value?.effective
    if (!effective || effective.source === 'builtin') return 'Built-in'
    return effective.name || effective.code || 'Built-in'
})

const messageOf = (cause: any) => cause?.response?.data?.detail || cause?.message || 'The request failed'

const run = async (action: () => Promise<unknown>, done = '') => {
    try {
        await action()
        error.value = ''
        notice.value = done
        return true
    } catch (cause) {
        notice.value = ''
        error.value = String(messageOf(cause))
        return false
    }
}

const reload = async () => {
    loading.value = true
    try {
        data.value = await listSavedViews(props.project)
    } catch (cause) {
        error.value = String(messageOf(cause))
    } finally {
        loading.value = false
    }
}

// Loaded with the project, so the trigger names the view shown.
onMounted(() => { void reload() })
watch(() => props.project, () => { void reload() })

const updateMenuPosition = () => {
    const trigger = triggerRef.value
    if (!trigger) return
    const rect = trigger.getBoundingClientRect()
    const width = Math.min(352, window.innerWidth - 16)
    const left = Math.min(Math.max(8, rect.right - width), window.innerWidth - width - 8)
    const top = Math.min(window.innerHeight - 16, rect.bottom + 4)
    menuStyle.value = {
        position: 'fixed',
        left: `${left}px`,
        top: `${top}px`,
        width: `${width}px`,
        maxHeight: `${Math.max(240, window.innerHeight - top - 12)}px`,
        zIndex: '11000',
    }
}

const open = async () => {
    if (isOpen.value) return
    isOpen.value = true
    await nextTick()
    updateMenuPosition()
    window.addEventListener('resize', updateMenuPosition)
    void reload()
}

const close = () => {
    isOpen.value = false
    renaming.value = null
    confirmingDelete.value = null
    window.removeEventListener('resize', updateMenuPosition)
}

const toggle = () => (isOpen.value ? close() : open())

const handlePointerDown = (event: MouseEvent) => {
    const target = event.target as Node | null
    if (!isOpen.value || !target) return
    if (triggerRef.value?.contains(target) || menuRef.value?.contains(target)) return
    close()
}
const handleKeydown = (event: KeyboardEvent) => {
    if (event.key === 'Escape' && isOpen.value) close()
}
document.addEventListener('mousedown', handlePointerDown)
document.addEventListener('keydown', handleKeydown)
onBeforeUnmount(() => {
    document.removeEventListener('mousedown', handlePointerDown)
    document.removeEventListener('keydown', handleKeydown)
    window.removeEventListener('resize', updateMenuPosition)
})

const copyText = async (text: string) => {
    if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text)
        return
    }
    const textarea = document.createElement('textarea')
    document.body.appendChild(textarea)
    textarea.value = text
    textarea.select()
    document.execCommand('copy')
    document.body.removeChild(textarea)
}

const linkUrl = (code: string, project?: string | null) => {
    const href = router.resolve({ path: `/v/${code}`, query: project ? { project } : {} }).href
    return `${window.location.origin}${href}`
}

const copyCurrentLink = () => run(() => copyText(props.currentUrl), 'Link copied')

const copyViewLink = (view: SavedView) => run(
    () => copyText(linkUrl(view.code, view.project ? null : props.project)),
    'Short link copied',
)

const applyView = (view: SavedView) => {
    emit('apply', view.query)
    close()
}

const saveCurrent = async () => {
    const name = newName.value.trim()
    if (!name) {
        error.value = 'Name the view first'
        return
    }
    const saved = await run(() => createSavedView({
        name,
        scope: newGlobal.value ? 'global' : 'personal',
        project: newAllProjects.value ? null : props.project,
        query: props.currentQuery,
    }), `Saved “${name}”`)
    if (saved) {
        newName.value = ''
        newGlobal.value = false
        await reload()
    }
}

const updateWithCurrent = async (view: SavedView) => {
    if (await run(() => updateSavedView(view.code, { query: props.currentQuery }), `Updated “${view.name}”`)) await reload()
}

const startRename = (view: SavedView) => {
    renaming.value = view.code
    renameText.value = view.name || ''
}

const finishRename = async (view: SavedView) => {
    const name = renameText.value.trim()
    renaming.value = null
    if (!name || name === view.name) return
    if (await run(() => updateSavedView(view.code, { name }), 'Renamed')) await reload()
}

const shareGlobally = async (view: SavedView) => {
    if (await run(() => updateSavedView(view.code, { scope: 'global' }), `“${view.name}” is shared with everyone`)) await reload()
}

const removeView = async (view: SavedView) => {
    if (confirmingDelete.value !== view.code) {
        confirmingDelete.value = view.code
        return
    }
    confirmingDelete.value = null
    if (await run(() => deleteSavedView(view.code), `Deleted “${view.name}”`)) {
        await reload()
        emit('defaults-changed')
    }
}

const isMyDefault = (view: SavedView) => defaults.value?.user_project === view.code
    || (!defaults.value?.user_project && defaults.value?.user_all === view.code)

const setMyDefault = async (view: SavedView) => {
    const clear = defaults.value?.user_project === view.code
    if (await run(
        () => setDefaultView({ target: 'user', project: props.project, code: clear ? null : view.code }),
        clear ? 'Default cleared for this project' : `“${view.name}” is your default for this project`,
    )) {
        await reload()
        emit('defaults-changed')
    }
}

const setMyDefaultEverywhere = async (code: string) => {
    if (await run(
        () => setDefaultView({ target: 'user', project: null, code: code || null }),
        'Default for all projects saved',
    )) {
        await reload()
        emit('defaults-changed')
    }
}

const roleDefault = (role: string) => {
    const entry = defaults.value?.roles?.[role]
    return (roleDefaultScope.value === 'project' ? entry?.project : entry?.all) || ''
}

const setRoleDefault = async (role: string, code: string) => {
    if (await run(
        () => setDefaultView({
            target: 'role',
            role,
            project: roleDefaultScope.value === 'project' ? props.project : null,
            code: code || null,
        }),
        `Default for ${role === 'REVIEWER' ? 'reviewers' : 'analysts'} saved`,
    )) {
        await reload()
        emit('defaults-changed')
    }
}

const chip = 'inline-flex h-6 w-6 items-center justify-center rounded border border-transparent text-gray-400 hover:border-white/10 hover:bg-white/10 hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-400'
</script>

<template>
    <div ref="triggerRef" class="relative flex-none">
        <button
            type="button"
            data-testid="saved-views-trigger"
            :aria-expanded="isOpen"
            aria-haspopup="dialog"
            title="Saved views and short links"
            class="h-10 max-w-[8.5rem] inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-slate-900/10 px-3 text-xs font-semibold text-slate-200 transition-colors hover:bg-slate-900/20 hover:text-white"
            @click="toggle"
        >
            <Bookmark :size="14" class="shrink-0" />
            <span class="truncate">{{ currentView?.name || 'Views' }}</span>
            <ChevronDown :size="12" class="shrink-0 text-gray-400 transition-transform" :class="isOpen && 'rotate-180'" />
        </button>

        <Teleport to="body">
            <div
                v-if="isOpen"
                ref="menuRef"
                :style="menuStyle"
                role="dialog"
                aria-label="Saved views"
                data-testid="saved-views-menu"
                class="overflow-y-auto rounded-xl border border-white/10 bg-[#1e1e2e] p-3 text-xs text-gray-200 shadow-2xl space-y-3"
            >
                <div class="flex items-center justify-between gap-2">
                    <div class="text-[10px] font-semibold uppercase tracking-widest text-gray-500">Views</div>
                    <button
                        type="button"
                        data-testid="copy-link"
                        class="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-[11px] font-semibold text-gray-200 hover:bg-white/10 hover:text-white"
                        title="Copy the full link to the current filters; save them as a view for a short link"
                        @click="copyCurrentLink"
                    >
                        <Link2 :size="12" /> Copy link
                    </button>
                </div>

                <div class="min-h-7">
                    <p v-if="error" class="rounded-lg border border-red-500/30 bg-red-500/10 px-2 py-1 text-red-200" role="alert" data-testid="saved-views-error">{{ error }}</p>
                    <p
                        v-else
                        role="status"
                        data-testid="saved-views-notice"
                        :class="notice ? 'rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-emerald-200' : ''"
                    >{{ notice }}</p>
                </div>

                <div v-if="loading && !data" class="text-gray-500">Loading views…</div>
                <template v-else>
                    <section v-for="section in [
                        { key: 'personal', title: 'My views', items: personalViews, empty: 'No views yet: save the current filters below.' },
                        { key: 'global', title: 'Shared views', items: globalViews, empty: 'No shared views.' },
                    ]" :key="section.key" class="space-y-1">
                        <h4 class="text-[10px] font-semibold uppercase tracking-widest text-gray-500">{{ section.title }}</h4>
                        <p v-if="!section.items.length" class="text-[11px] text-gray-500">{{ section.empty }}</p>
                        <ul class="space-y-0.5">
                            <li
                                v-for="view in section.items"
                                :key="view.code"
                                class="group flex items-center gap-1 rounded-lg px-1 py-0.5 hover:bg-white/5"
                                :class="currentView?.code === view.code ? 'bg-blue-500/10' : ''"
                            >
                                <input
                                    v-if="renaming === view.code"
                                    v-model="renameText"
                                    :data-testid="`saved-view-rename-input-${view.code}`"
                                    class="min-w-0 flex-1 rounded border border-white/10 bg-black/40 px-1.5 py-0.5 text-xs text-white focus:border-blue-400/50 focus:outline-none"
                                    aria-label="View name"
                                    @keydown.enter.prevent="finishRename(view)"
                                    @keydown.escape.stop="renaming = null"
                                    @blur="finishRename(view)"
                                />
                                <button
                                    v-else
                                    type="button"
                                    :data-testid="`saved-view-${view.code}`"
                                    class="min-w-0 flex-1 truncate text-left text-xs text-gray-200 hover:text-white"
                                    :title="view.query || 'Built-in filters'"
                                    @click="applyView(view)"
                                >
                                    <Check v-if="currentView?.code === view.code" :size="11" class="mr-1 inline text-blue-300" />{{ view.name }}
                                    <span v-if="!view.project" class="ml-1 text-[9px] uppercase text-gray-500">all projects</span>
                                </button>
                                <button
                                    type="button"
                                    :data-testid="`saved-view-default-${view.code}`"
                                    :aria-pressed="isMyDefault(view)"
                                    :class="[chip, isMyDefault(view) ? 'text-amber-300' : '']"
                                    :title="isMyDefault(view) ? 'Your default (click to clear for this project)' : 'Set as my default for this project'"
                                    @click="setMyDefault(view)"
                                >
                                    <Star :size="12" :fill="isMyDefault(view) ? 'currentColor' : 'none'" />
                                </button>
                                <button type="button" :data-testid="`saved-view-link-${view.code}`" :class="chip" title="Copy short link" @click="copyViewLink(view)"><Link2 :size="12" /></button>
                                <template v-if="view.editable">
                                    <button type="button" :data-testid="`saved-view-update-${view.code}`" :class="chip" title="Update with the current filters" @click="updateWithCurrent(view)"><RefreshCw :size="12" /></button>
                                    <button type="button" :data-testid="`saved-view-rename-${view.code}`" :class="chip" title="Rename" @click="startRename(view)"><Pencil :size="12" /></button>
                                    <button
                                        v-if="view.scope === 'personal' && canManageGlobal"
                                        type="button"
                                        :data-testid="`saved-view-share-${view.code}`"
                                        :class="chip"
                                        title="Share with everyone"
                                        @click="shareGlobally(view)"
                                    ><Globe :size="12" /></button>
                                    <button
                                        type="button"
                                        :data-testid="`saved-view-delete-${view.code}`"
                                        :class="[chip, confirmingDelete === view.code ? 'w-auto px-1.5 text-red-300 border-red-500/30' : '']"
                                        :title="confirmingDelete === view.code ? 'Click again to delete' : 'Delete'"
                                        @click="removeView(view)"
                                    >
                                        <Trash2 :size="12" />
                                        <span v-if="confirmingDelete === view.code" class="ml-1 text-[10px]">Delete?</span>
                                    </button>
                                </template>
                            </li>
                        </ul>
                    </section>

                    <form class="space-y-1.5 rounded-lg border border-white/10 bg-white/3 p-2" @submit.prevent="saveCurrent">
                        <label class="block text-[10px] font-semibold uppercase tracking-widest text-gray-500" for="saved-view-name">Save current filters as</label>
                        <div class="flex gap-1.5">
                            <input
                                id="saved-view-name"
                                v-model="newName"
                                data-testid="saved-view-name"
                                maxlength="80"
                                placeholder="Release 7.2 freeze"
                                class="min-w-0 flex-1 rounded-lg border border-white/10 bg-black/40 px-2 py-1 text-xs text-white focus:border-blue-400/50 focus:outline-none"
                            />
                            <button type="submit" data-testid="saved-view-save" class="rounded-lg border border-blue-400/40 bg-blue-500/20 px-2.5 py-1 text-xs font-semibold text-blue-100 hover:bg-blue-500/30">Save</button>
                        </div>
                        <div class="flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-gray-400">
                            <label class="inline-flex items-center gap-1.5"><input v-model="newAllProjects" type="checkbox" data-testid="saved-view-all-projects" class="accent-blue-500" /> For all projects</label>
                            <label v-if="canManageGlobal" class="inline-flex items-center gap-1.5"><input v-model="newGlobal" type="checkbox" data-testid="saved-view-global" class="accent-blue-500" /> Shared with everyone</label>
                        </div>
                    </form>

                    <section class="space-y-1.5 border-t border-white/10 pt-2">
                        <div class="flex items-center justify-between gap-2 text-[11px] text-gray-400">
                            <span>Default here: <span class="font-semibold text-gray-200" data-testid="saved-views-effective">{{ effectiveName }}</span></span>
                        </div>
                        <label class="flex items-center justify-between gap-2 text-[11px] text-gray-400">
                            <span>My default for all projects</span>
                            <select
                                data-testid="default-everywhere"
                                :value="defaults?.user_all || ''"
                                class="max-w-[11rem] rounded border border-white/10 bg-black/40 px-1.5 py-0.5 text-xs text-gray-200"
                                @change="setMyDefaultEverywhere(($event.target as HTMLSelectElement).value)"
                            >
                                <option value="">None</option>
                                <option v-for="view in views.filter(item => !item.project)" :key="view.code" :value="view.code">{{ view.name }}</option>
                            </select>
                        </label>
                        <details v-if="canManageGlobal" class="rounded-lg border border-dashed border-white/10 p-2" data-testid="role-defaults">
                            <summary class="cursor-pointer text-[11px] text-gray-400">Role defaults</summary>
                            <div class="mt-2 space-y-1.5">
                                <div class="flex gap-3 text-[11px] text-gray-400">
                                    <label class="inline-flex items-center gap-1"><input v-model="roleDefaultScope" type="radio" value="project" class="accent-blue-500" /> This project</label>
                                    <label class="inline-flex items-center gap-1"><input v-model="roleDefaultScope" type="radio" value="all" class="accent-blue-500" /> All projects</label>
                                </div>
                                <label v-for="role in ['ANALYST', 'REVIEWER']" :key="role" class="flex items-center justify-between gap-2 text-[11px] text-gray-400">
                                    <span>{{ role === 'REVIEWER' ? 'Reviewers' : 'Analysts' }}</span>
                                    <select
                                        :data-testid="`role-default-${role}`"
                                        :value="roleDefault(role)"
                                        class="max-w-[11rem] rounded border border-white/10 bg-black/40 px-1.5 py-0.5 text-xs text-gray-200"
                                        @change="setRoleDefault(role, ($event.target as HTMLSelectElement).value)"
                                    >
                                        <option value="">Built-in</option>
                                        <option
                                            v-for="view in globalViews.filter(item => roleDefaultScope === 'project' || !item.project)"
                                            :key="view.code"
                                            :value="view.code"
                                        >{{ view.name }}</option>
                                    </select>
                                </label>
                                <p class="text-[10px] text-gray-500">Role defaults use shared views. A user's own default comes first.</p>
                            </div>
                        </details>
                    </section>
                </template>
            </div>
        </Teleport>
    </div>
</template>
