import { ref, triggerRef } from 'vue'
import type { GroupedVuln } from '../types'

export interface VulnModalEntry {
    group: GroupedVuln
    minimized: boolean
    zIndex: number
    // Cascade offset so stacked modals don't perfectly overlap
    offsetX: number
    offsetY: number
}

// Module-level singleton state — shared across all component instances
const openModals = ref<Map<string, VulnModalEntry>>(new Map())
let zCounter = 200

const CASCADE_STEP = 28 // px cascade offset per modal

function getNextOffset(): { offsetX: number; offsetY: number } {
    const count = openModals.value.size
    const step = (count % 6) * CASCADE_STEP
    return { offsetX: step, offsetY: step }
}

function openModal(group: GroupedVuln): void {
    const id = group.id
    const existing = openModals.value.get(id)
    if (existing) {
        // Already open — just restore + focus
        existing.minimized = false
        existing.zIndex = ++zCounter
        triggerRef(openModals)
        return
    }
    const { offsetX, offsetY } = getNextOffset()
    const entry: VulnModalEntry = {
        group,
        minimized: false,
        zIndex: ++zCounter,
        offsetX,
        offsetY,
    }
    openModals.value.set(id, entry)
    triggerRef(openModals)
}

function closeModal(id: string): void {
    openModals.value.delete(id)
    triggerRef(openModals)
}

function minimizeModal(id: string): void {
    const entry = openModals.value.get(id)
    if (!entry) return
    entry.minimized = true
    triggerRef(openModals)
}

function restoreModal(id: string): void {
    const entry = openModals.value.get(id)
    if (!entry) return
    entry.minimized = false
    entry.zIndex = ++zCounter
    triggerRef(openModals)
}

function focusModal(id: string): void {
    const entry = openModals.value.get(id)
    if (!entry || entry.minimized) return
    entry.zIndex = ++zCounter
    triggerRef(openModals)
}

function updateModalGroup(id: string, group: GroupedVuln): void {
    const entry = openModals.value.get(id)
    if (!entry) return
    entry.group = group
    triggerRef(openModals)
}

export function useVulnModals() {
    return {
        openModals,
        openModal,
        closeModal,
        minimizeModal,
        restoreModal,
        focusModal,
        updateModalGroup,
    }
}
