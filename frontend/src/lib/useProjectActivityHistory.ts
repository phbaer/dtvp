import { computed, onBeforeUnmount, ref, watch, type Ref } from 'vue'
import type { GroupedVuln } from '../types'

export interface ProjectActivity {
    id: string
    title: string
    at: number
    action: 'opened' | 'updated'
}

const LIMIT = 50
const validEntry = (entry: any): entry is ProjectActivity =>
    entry && typeof entry.id === 'string' && entry.id.length > 0 && entry.id.length <= 200
    && typeof entry.title === 'string' && entry.title.length <= 500
    && Number.isFinite(entry.at) && entry.at > 0 && entry.at <= 8.64e15
    && ['opened', 'updated'].includes(entry.action)

export function useProjectActivityHistory(project: Ref<string>, username: Ref<string>) {
    const entries = ref<ProjectActivity[]>([])
    const persistent = ref(true)
    const key = computed(() => project.value && username.value
        ? `dtvp:project-activity:v1:${JSON.stringify([username.value, project.value])}`
        : '')

    const read = (): ProjectActivity[] => {
        if (!key.value) return []
        try {
            const raw = localStorage.getItem(key.value)
            if (!raw || raw.length > 100_000) return []
            const parsed: unknown = JSON.parse(raw)
            return Array.isArray(parsed) ? parsed.filter(validEntry).slice(0, LIMIT) : []
        } catch {
            persistent.value = false
            return []
        }
    }
    watch(key, () => {
        persistent.value = true
        entries.value = read()
    }, { immediate: true, flush: 'sync' })

    const record = (group: Pick<GroupedVuln, 'id' | 'title'>, action: ProjectActivity['action']) => {
        if (!key.value || !group.id) return
        const entry: ProjectActivity = { id: group.id, title: (group.title || '').slice(0, 500), at: Date.now(), action }
        if (!validEntry(entry)) return
        const merged = new Map<string, ProjectActivity>()
        for (const item of [entry, ...entries.value, ...read()]) {
            merged.set(JSON.stringify([item.id, item.action, item.at]), item)
        }
        entries.value = [...merged.values()].sort((a, b) => b.at - a.at).slice(0, LIMIT)
        try { localStorage.setItem(key.value, JSON.stringify(entries.value)); persistent.value = true }
        catch { persistent.value = false }
    }

    const clear = () => {
        entries.value = []
        if (!key.value) return
        try { localStorage.removeItem(key.value) }
        catch { persistent.value = false }
    }
    const sync = (event: StorageEvent) => {
        if (event.key === key.value || event.key === null) entries.value = read()
    }
    window.addEventListener('storage', sync)
    onBeforeUnmount(() => window.removeEventListener('storage', sync))

    return { entries, persistent, key, record, clear }
}
