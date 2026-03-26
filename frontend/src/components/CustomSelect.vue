<script setup lang="ts">
import { ref, computed } from 'vue'
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
let closeTimer: ReturnType<typeof globalThis.setTimeout> | null = null

const close = () => {
    closeTimer = globalThis.setTimeout(() => { isOpen.value = false }, 150)
}

const toggle = () => {
    if (closeTimer) { clearTimeout(closeTimer); closeTimer = null }
    isOpen.value = !isOpen.value
}

const selectOption = (value: string) => {
    emit('update:modelValue', value)
    isOpen.value = false
}

const currentLabel = computed(() => {
    return props.options.find(o => o.value === props.modelValue)?.label ?? props.placeholder
})

const btnClass = computed(() =>
    props.size === 'sm'
        ? 'px-2.5 h-8 text-xs'
        : 'px-3 h-10 text-sm'
)
</script>

<template>
    <div class="relative" @focusout="close" tabindex="-1">
        <button
            type="button"
            @click="toggle"
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
        <div
            v-if="isOpen"
            class="absolute z-50 mt-1 w-full max-h-52 overflow-y-auto bg-[#1e1e2e] border border-white/10 rounded-lg shadow-xl"
        >
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
        </div>
    </div>
</template>
