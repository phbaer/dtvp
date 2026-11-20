<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import type { GroupedVuln } from '../types'
import type { AutomaticAssessmentStatus } from '../lib/vulnListIndex'
import VulnGroupCard from './VulnGroupCard.vue'

// The root is a Teleport, so attributes from the host (class="h-full")
// are bound to the aside explicitly.
defineOptions({ inheritAttrs: false })

const props = defineProps<{
    group: GroupedVuln
    hasAutomaticAssessment?: boolean
    automaticAssessmentStatus?: AutomaticAssessmentStatus | null
    activeTeamFilter?: string
    /** The viewport is wide enough for the assessment workspace. */
    workspaceAvailable?: boolean
}>()

const emit = defineEmits<{
    (e: 'close'): void
    (e: 'update', group?: GroupedVuln): void
    (e: 'update:assessment', data: any): void
}>()

const cardRef = ref<{
    confirmApplyDraftBeforeLeave?: () => Promise<boolean>
    hasOpenOverlay?: () => boolean
} | null>(null)
const asideRef = ref<HTMLElement | null>(null)

// The assessment workspace is the same card, moved to the body and shown
// full screen. It is not remembered: leaving the vulnerability ends it.
const workspaceOpen = ref(false)
const workspaceActive = computed(() => workspaceOpen.value && !!props.workspaceAvailable)

const focusWorkspaceToggle = () => {
    void nextTick(() => {
        asideRef.value?.querySelector<HTMLElement>('[data-testid="workspace-toggle"]')?.focus()
    })
}

const closeWorkspace = () => {
    if (!workspaceOpen.value) return
    workspaceOpen.value = false
    focusWorkspaceToggle()
}

const toggleWorkspace = () => {
    if (workspaceOpen.value) {
        closeWorkspace()
        return
    }
    if (props.workspaceAvailable) workspaceOpen.value = true
}

// A viewport that became too narrow ends the workspace. The toggle is gone
// then, so focus goes to the Assessment tab instead of falling to the body.
watch(() => props.workspaceAvailable, (available) => {
    if (available || !workspaceOpen.value) return
    workspaceOpen.value = false
    void nextTick(() => {
        const tab = document.getElementById(`vuln-${props.group.id}-detail-tab-review`)
        const target = tab ?? asideRef.value?.querySelector<HTMLElement>('button:not([disabled])')
        target?.focus()
    })
})

// Input types without their own use for Esc; everything else typed text.
const NON_TEXT_INPUT_TYPES = new Set([
    'button', 'checkbox', 'color', 'file', 'hidden', 'image', 'radio', 'range', 'reset', 'submit',
])

/** A control in which the user types text; Esc there belongs to the field. */
const isTextEntryTarget = (target: EventTarget | null) => {
    if (!(target instanceof HTMLElement)) return false
    if (target instanceof HTMLInputElement) return !NON_TEXT_INPUT_TYPES.has(target.type)
    if (target.tagName === 'TEXTAREA' || target.tagName === 'SELECT') return true
    if (target.isContentEditable) return true
    const editable = target.closest('[contenteditable]')
    return !!editable && editable.getAttribute('contenteditable') !== 'false'
}

/** A menu or modal teleported out of the aside is open; keys belong to it. */
const hasOpenOverlay = () => Boolean(
    cardRef.value?.hasOpenOverlay?.()
    || document.querySelector('[data-testid="custom-select-menu"]')
)

const FOCUSABLE_SELECTOR = [
    'button:not([disabled])',
    '[href]',
    'input:not([disabled]):not([type="hidden"])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
].join(',')

const focusableInAside = () => {
    const aside = asideRef.value
    if (!aside) return []
    return [...aside.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)]
        .filter(element => element.tabIndex !== -1 && element.getClientRects().length > 0)
}

/** Tab and Shift+Tab wrap inside the workspace, as aria-modal promises. */
const trapTab = (event: KeyboardEvent) => {
    const aside = asideRef.value
    if (!aside || hasOpenOverlay()) return
    const focusable = focusableInAside()
    const active = document.activeElement
    if (!focusable.length) {
        event.preventDefault()
        aside.focus()
        return
    }
    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    if (!(active instanceof Node) || !aside.contains(active)) {
        event.preventDefault()
        ;(event.shiftKey ? last : first).focus()
    } else if (event.shiftKey && (active === first || active === aside)) {
        event.preventDefault()
        last.focus()
    } else if (!event.shiftKey && active === last) {
        event.preventDefault()
        first.focus()
    }
}

/**
 * Esc leaves the workspace, but only when nothing else claims it: an open
 * menu or modal closes first, and Esc in a text field stays with the field.
 * The listener sits on the document, so Esc also works when focus fell to
 * the body, for example after a click on plain text or a closed menu.
 */
const handleWorkspaceKeydown = (event: KeyboardEvent) => {
    if (!workspaceActive.value || event.defaultPrevented) return
    if (event.key === 'Tab') {
        trapTab(event)
        return
    }
    if (event.key !== 'Escape') return
    if (isTextEntryTarget(event.target)) return
    if (hasOpenOverlay()) return
    closeWorkspace()
}

watch(workspaceActive, (active) => {
    if (active) document.addEventListener('keydown', handleWorkspaceKeydown)
    else document.removeEventListener('keydown', handleWorkspaceKeydown)
})

onBeforeUnmount(() => document.removeEventListener('keydown', handleWorkspaceKeydown))

const confirmApplyDraftBeforeLeave = () =>
    cardRef.value?.confirmApplyDraftBeforeLeave?.() ?? Promise.resolve(true)

defineExpose({
    confirmApplyDraftBeforeLeave,
})
</script>

<template>
    <Teleport to="body" :disabled="!workspaceActive">
        <aside
            v-bind="$attrs"
            ref="asideRef"
            :class="workspaceActive
                ? 'fixed inset-0 z-[65] flex flex-col bg-gray-950 p-2 outline-none'
                : 'relative flex h-full min-h-0 flex-col overflow-hidden'"
            data-testid="vuln-detail-inspector"
            :data-workspace="workspaceActive ? 'open' : 'closed'"
            :role="workspaceActive ? 'dialog' : undefined"
            :aria-modal="workspaceActive ? 'true' : undefined"
            :aria-label="workspaceActive ? `Assessment workspace for ${group.id}` : undefined"
            :tabindex="workspaceActive ? -1 : undefined"
        >
            <div
                :class="workspaceActive
                    ? 'flex min-h-0 grow flex-col overflow-hidden'
                    : 'min-h-0 grow overflow-y-auto overscroll-contain'"
            >
                <VulnGroupCard
                    ref="cardRef"
                    :group="group"
                    :inModal="true"
                    :hasAutomaticAssessment="hasAutomaticAssessment"
                    :automaticAssessmentStatus="automaticAssessmentStatus"
                    :activeTeamFilter="activeTeamFilter"
                    :workspace="workspaceActive"
                    :workspaceAvailable="workspaceAvailable"
                    @close="emit('close')"
                    @update="(updatedGroup) => emit('update', updatedGroup)"
                    @update:assessment="(data) => emit('update:assessment', data)"
                    @toggle-workspace="toggleWorkspace"
                />
            </div>
        </aside>
    </Teleport>
</template>
