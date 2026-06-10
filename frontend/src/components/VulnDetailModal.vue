<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { Minus, X, GripHorizontal } from 'lucide-vue-next'
import type { VulnModalEntry } from '../lib/useVulnModals'
import { useVulnModals } from '../lib/useVulnModals'
import VulnGroupCard from './VulnGroupCard.vue'
import type { GroupedVuln } from '../types'

const props = defineProps<{
    id: string
    entry: VulnModalEntry
}>()

const emit = defineEmits<{
    (e: 'update', group?: GroupedVuln): void
    (e: 'update:assessment', data: any): void
}>()

const { openModals, closeModal, minimizeModal, focusModal, updateModalGroup } = useVulnModals()

// --- Dragging ---
const isDragging = ref(false)
const dragOffsetX = ref(0)
const dragOffsetY = ref(0)
const hasPosition = ref(false)

const viewportWidth = ref(1024)
const viewportHeight = ref(768)

const VIEWPORT_MARGIN = 16
const COMPACT_MARGIN = 8
const DESKTOP_TOP_OFFSET = 72
const DESKTOP_MAX_WIDTH = 1100
const DESKTOP_MIN_WIDTH = 640
const DESKTOP_MIN_HEIGHT = 360
const TASKBAR_RESERVE = 52

const getViewportSize = () => {
    if (typeof window === 'undefined') {
        return { width: 1024, height: 768 }
    }

    return {
        width: Math.round(window.visualViewport?.width ?? window.innerWidth),
        height: Math.round(window.visualViewport?.height ?? window.innerHeight),
    }
}

const updateViewport = () => {
    const size = getViewportSize()
    viewportWidth.value = size.width
    viewportHeight.value = size.height
}

updateViewport()

const isCompactViewport = computed(() =>
    viewportWidth.value < 768 || viewportHeight.value < 560
)
const margin = computed(() => isCompactViewport.value ? COMPACT_MARGIN : VIEWPORT_MARGIN)
const hasMinimizedModals = computed(() =>
    Array.from(openModals.value.values()).some((entry) => entry.minimized)
)
const bottomReserve = computed(() => hasMinimizedModals.value ? TASKBAR_RESERVE : 0)
const modalWidth = computed(() => {
    const availableWidth = Math.max(0, viewportWidth.value - margin.value * 2)
    if (isCompactViewport.value) return availableWidth
    return Math.min(DESKTOP_MAX_WIDTH, Math.max(DESKTOP_MIN_WIDTH, Math.floor(viewportWidth.value * 0.78)), availableWidth)
})
const modalHeight = computed(() => {
    const availableHeight = Math.max(0, viewportHeight.value - margin.value * 2 - bottomReserve.value)
    if (isCompactViewport.value) return availableHeight
    return Math.min(availableHeight, Math.max(DESKTOP_MIN_HEIGHT, Math.floor(viewportHeight.value * 0.86)))
})
const maxLeft = computed(() => Math.max(margin.value, viewportWidth.value - modalWidth.value - margin.value))
const maxTop = computed(() => Math.max(margin.value, viewportHeight.value - modalHeight.value - margin.value))
const defaultLeft = computed(() => {
    if (isCompactViewport.value) return margin.value
    return Math.round((viewportWidth.value - modalWidth.value) / 2) + props.entry.offsetX
})
const defaultTop = computed(() => {
    if (isCompactViewport.value) return margin.value
    return Math.min(DESKTOP_TOP_OFFSET + props.entry.offsetY, maxTop.value)
})

const clamp = (value: number, min: number, max: number) => Math.min(Math.max(value, min), max)

const posX = ref(defaultLeft.value)
const posY = ref(defaultTop.value)

const setPosition = (x: number, y: number) => {
    posX.value = clamp(x, margin.value, maxLeft.value)
    posY.value = clamp(y, margin.value, maxTop.value)
}

const initializePosition = () => {
    setPosition(defaultLeft.value, defaultTop.value)
    hasPosition.value = true
}

const clampCurrentPosition = () => {
    if (isCompactViewport.value) {
        initializePosition()
        return
    }
    if (!hasPosition.value) {
        initializePosition()
        return
    }
    setPosition(posX.value, posY.value)
}

const onDragMove = (e: PointerEvent | MouseEvent) => {
    if (!isDragging.value) return
    setPosition(e.clientX - dragOffsetX.value, e.clientY - dragOffsetY.value)
}

const stopDragging = () => {
    isDragging.value = false
    if (typeof window === 'undefined') return
    window.removeEventListener('pointermove', onDragMove)
    window.removeEventListener('pointerup', stopDragging)
    window.removeEventListener('pointercancel', stopDragging)
    window.removeEventListener('mousemove', onDragMove)
    window.removeEventListener('mouseup', stopDragging)
}

const handleTitlebarPointerdown = (e: PointerEvent) => {
    if ((e.target as HTMLElement).closest('button')) return
    focusModal(props.id)
    if (isDragging.value) return
    if (isCompactViewport.value) return
    if (e.pointerType === 'mouse' && e.button !== 0) return
    e.preventDefault()
    isDragging.value = true
    dragOffsetX.value = e.clientX - posX.value
    dragOffsetY.value = e.clientY - posY.value
    window.addEventListener('pointermove', onDragMove)
    window.addEventListener('pointerup', stopDragging)
    window.addEventListener('pointercancel', stopDragging)
}

const handleTitlebarMousedown = (e: MouseEvent) => {
    if ((e.target as HTMLElement).closest('button')) return
    focusModal(props.id)
    if (isDragging.value) return
    if (isCompactViewport.value) return
    if (e.button !== 0) return
    e.preventDefault()
    isDragging.value = true
    dragOffsetX.value = e.clientX - posX.value
    dragOffsetY.value = e.clientY - posY.value
    window.addEventListener('mousemove', onDragMove)
    window.addEventListener('mouseup', stopDragging)
}

onMounted(() => {
    updateViewport()
    initializePosition()
    window.addEventListener('resize', updateViewport)
    window.visualViewport?.addEventListener('resize', updateViewport)
})

onUnmounted(() => {
    stopDragging()
    if (typeof window === 'undefined') return
    window.removeEventListener('resize', updateViewport)
    window.visualViewport?.removeEventListener('resize', updateViewport)
})

watch([viewportWidth, viewportHeight, modalWidth, modalHeight], clampCurrentPosition)

const modalStyle = computed(() => ({
    left: `${posX.value}px`,
    top: `${posY.value}px`,
    zIndex: props.entry.zIndex,
    width: `${modalWidth.value}px`,
    height: `${modalHeight.value}px`,
    maxWidth: `calc(100vw - ${margin.value * 2}px)`,
    maxHeight: `calc(100dvh - ${margin.value * 2}px)`,
}))

const handleMousedown = () => focusModal(props.id)

const handleAssessmentUpdate = (data: any) => {
    emit('update:assessment', data)
}
const handleUpdate = (group?: GroupedVuln) => {
    if (group) updateModalGroup(props.id, group)
    emit('update', group)
}

// Severity header colour
const SEVERITY_BG: Record<string, string> = {
    CRITICAL: 'bg-violet-900',
    HIGH: 'bg-red-900',
    MEDIUM: 'bg-amber-900',
    LOW: 'bg-blue-900',
    INFO: 'bg-gray-800',
}
const severityClass = computed(() => {
    const score = props.entry.group.cvss ?? props.entry.group.cvss_score ?? 0
    if (score >= 9) return SEVERITY_BG.CRITICAL
    if (score >= 7) return SEVERITY_BG.HIGH
    if (score >= 4) return SEVERITY_BG.MEDIUM
    if (score > 0) return SEVERITY_BG.LOW
    return SEVERITY_BG.INFO
})
const vulnId = computed(() => props.entry.group.id)
</script>

<template>
    <Teleport to="body">
        <div
            v-if="!entry.minimized"
            class="fixed flex min-w-0 flex-col rounded-xl shadow-2xl border border-gray-700 bg-gray-900 overflow-hidden"
            :class="isCompactViewport ? 'rounded-lg' : 'rounded-xl'"
            :style="modalStyle"
            role="dialog"
            aria-modal="false"
            :aria-label="`${vulnId} details`"
            data-testid="vuln-detail-modal"
            @mousedown="handleMousedown"
        >
            <!-- Title bar -->
            <div
                :class="[
                    'flex items-center gap-2 px-3 py-2 select-none touch-none',
                    isCompactViewport ? 'cursor-default' : 'cursor-grab active:cursor-grabbing',
                    severityClass,
                ]"
                data-testid="vuln-detail-modal-titlebar"
                @pointerdown="handleTitlebarPointerdown"
                @mousedown="handleTitlebarMousedown"
            >
                <GripHorizontal :size="14" class="text-white/40 shrink-0" />
                <span class="text-xs font-mono font-semibold text-white truncate grow">{{ vulnId }}</span>
                <button
                    class="p-1 rounded hover:bg-white/20 text-white/70 hover:text-white transition-colors shrink-0"
                    title="Minimize"
                    @click.stop="minimizeModal(id)"
                >
                    <Minus :size="13" />
                </button>
                <button
                    class="p-1 rounded hover:bg-red-500/40 text-white/70 hover:text-white transition-colors shrink-0"
                    title="Close"
                    @click.stop="closeModal(id)"
                >
                    <X :size="13" />
                </button>
            </div>

            <!-- Content: full VulnGroupCard in modal mode -->
            <div class="min-h-0 grow overflow-y-auto overscroll-contain">
                <VulnGroupCard
                    :group="entry.group"
                    :inModal="true"
                    @update:assessment="handleAssessmentUpdate"
                    @update="handleUpdate"
                />
            </div>
        </div>
    </Teleport>
</template>
