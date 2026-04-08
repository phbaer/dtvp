<script setup lang="ts">
import { ref, computed, watch, nextTick, onBeforeUnmount } from 'vue'
import { ChevronDown } from 'lucide-vue-next'

export interface SelectOption {
    value: string
    label: string
    description?: string
}

const props = withDefaults(defineProps<{
    modelValue: string
    options: SelectOption[]
    placeholder?: string
    size?: 'sm' | 'md'
}>(), {
    placeholder: 'Select...',
    size: 'md',
})

const emit = defineEmits<{
    'update:modelValue': [value: string]
}>()

const isOpen = ref(false)
const triggerRef = ref<HTMLElement | null>(null)
const menuRef = ref<HTMLElement | null>(null)
const menuStyle = ref<Record<string, string>>({})
const VIEWPORT_MARGIN = 8
const MENU_GAP = 4
const MENU_MAX_HEIGHT = 208

const updateMenuPosition = () => {
    const trigger = triggerRef.value
    if (!trigger) return

    const rect = trigger.getBoundingClientRect()
    const viewportWidth = window.innerWidth
    const viewportHeight = window.innerHeight
    const availableBelow = Math.max(96, viewportHeight - rect.bottom - MENU_GAP - VIEWPORT_MARGIN)
    const availableAbove = Math.max(96, rect.top - MENU_GAP - VIEWPORT_MARGIN)
    const placeAbove = availableBelow < 140 && availableAbove > availableBelow
    const maxHeight = Math.min(MENU_MAX_HEIGHT, placeAbove ? availableAbove : availableBelow)
    const width = Math.min(rect.width, viewportWidth - VIEWPORT_MARGIN * 2)
    const left = Math.min(Math.max(VIEWPORT_MARGIN, rect.left), viewportWidth - width - VIEWPORT_MARGIN)

    if (placeAbove) {
        menuStyle.value = {
            position: 'fixed',
            left: `${left}px`,
            bottom: `${Math.max(VIEWPORT_MARGIN, viewportHeight - rect.top + MENU_GAP)}px`,
            width: `${width}px`,
            maxHeight: `${maxHeight}px`,
            zIndex: '9999',
        }
        return
    }

    menuStyle.value = {
        position: 'fixed',
        left: `${left}px`,
        top: `${Math.min(viewportHeight - maxHeight - VIEWPORT_MARGIN, rect.bottom + MENU_GAP)}px`,
        width: `${width}px`,
        maxHeight: `${maxHeight}px`,
        zIndex: '9999',
    }
}

const toggle = () => {
    isOpen.value = !isOpen.value
}

const close = () => {
    isOpen.value = false
}

const open = () => {
    if (!isOpen.value) {
        isOpen.value = true
    }
}

const selectOption = (value: string) => {
    emit('update:modelValue', value)
    close()
}

const currentLabel = computed(() => {
    return props.options.find(o => o.value === props.modelValue)?.label ?? props.placeholder
})

const btnClass = computed(() =>
    props.size === 'sm'
        ? 'px-2.5 h-8 text-xs'
        : 'px-3 h-10 text-sm'
)

const handleDocumentPointerDown = (event: MouseEvent) => {
    const target = event.target as Node | null
    if (target && (triggerRef.value?.contains(target) || menuRef.value?.contains(target))) {
        return
    }
    close()
}

const handleDocumentFocusIn = (event: FocusEvent) => {
    const target = event.target as Node | null
    if (target && (triggerRef.value?.contains(target) || menuRef.value?.contains(target))) {
        return
    }
    close()
}

const handleDocumentKeydown = (event: KeyboardEvent) => {
    if (event.key === 'Escape') {
        close()
    }
}

watch(isOpen, async (open) => {
    if (!open) {
        document.removeEventListener('mousedown', handleDocumentPointerDown)
        document.removeEventListener('focusin', handleDocumentFocusIn)
        document.removeEventListener('keydown', handleDocumentKeydown)
        window.removeEventListener('resize', updateMenuPosition)
        window.removeEventListener('scroll', updateMenuPosition, true)
        return
    }

    await nextTick()
    updateMenuPosition()
    document.addEventListener('mousedown', handleDocumentPointerDown)
    document.addEventListener('focusin', handleDocumentFocusIn)
    document.addEventListener('keydown', handleDocumentKeydown)
    window.addEventListener('resize', updateMenuPosition)
    window.addEventListener('scroll', updateMenuPosition, true)
})

watch(() => props.options, async () => {
    if (!isOpen.value) return
    await nextTick()
    updateMenuPosition()
}, { deep: true })

onBeforeUnmount(() => {
    document.removeEventListener('mousedown', handleDocumentPointerDown)
    document.removeEventListener('focusin', handleDocumentFocusIn)
    document.removeEventListener('keydown', handleDocumentKeydown)
    window.removeEventListener('resize', updateMenuPosition)
    window.removeEventListener('scroll', updateMenuPosition, true)
})
</script>

<template>
    <div ref="triggerRef" class="relative" tabindex="-1">
        <slot name="trigger" :toggle="toggle" :open="open" :isOpen="isOpen">
            <button
                type="button"
                @click="toggle"
                :aria-expanded="isOpen"
                :class="[
                    'flex items-center justify-between w-full bg-black/40 border border-white/10 rounded-lg font-medium text-gray-200',
                    'hover:border-white/20 hover:bg-black/50 focus:border-blue-500/50 focus:shadow-[0_0_0_2px_rgba(59,130,246,0.15)]',
                    'outline-none transition-all cursor-pointer',
                    btnClass,
                ]"
            >
                <span class="truncate">{{ currentLabel }}</span>
                <ChevronDown :size="14" class="text-gray-400 ml-2 shrink-0 transition-transform" :class="isOpen && 'rotate-180'" />
            </button>
        </slot>
        <Teleport to="body">
            <div
                v-if="isOpen"
                ref="menuRef"
                data-testid="custom-select-menu"
                :style="menuStyle"
                class="absolute z-50 overflow-y-auto bg-[#1e1e2e] border border-white/10 rounded-lg shadow-xl"
            >
                <slot name="menu">
                    <button
                        v-for="opt in options"
                        :key="opt.value"
                        type="button"
                        @mousedown.prevent="selectOption(opt.value)"
                        :title="opt.description"
                        :class="[
                            'w-full text-left px-3 py-1.5 transition-colors flex items-center justify-between',
                            props.size === 'sm' ? 'text-xs' : 'text-sm',
                            modelValue === opt.value
                                ? 'bg-blue-500/15 text-blue-200'
                                : 'text-gray-300 hover:bg-white/5'
                        ]"
                    >
                        <span class="truncate">{{ opt.label }}</span>
                        <span v-if="modelValue === opt.value" class="text-blue-400 text-xs ml-2 shrink-0">&#10003;</span>
                    </button>
                </slot>
            </div>
        </Teleport>
    </div>
</template>
