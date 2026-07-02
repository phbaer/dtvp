<script setup lang="ts">
import { ref, computed, onBeforeUnmount, nextTick } from 'vue'
import { Clock, X, ChevronDown } from 'lucide-vue-next'
import { getAttributionAgeFilterDays } from '../lib/attributionAgePresets'

const props = defineProps<{
    days: number | null
    mode: 'older' | 'younger'
    count?: number
}>()

const emit = defineEmits<{
    'update:days': [value: number | null]
    'update:mode': [value: 'older' | 'younger']
}>()

const presets = getAttributionAgeFilterDays()

const isOpen = ref(false)
const triggerRef = ref<HTMLElement | null>(null)
const menuRef = ref<HTMLElement | null>(null)
const menuStyle = ref<Record<string, string>>({})

const isActive = computed(() => props.days != null && props.days > 0)

const summary = computed(() => {
    if (!isActive.value) return 'Any age'
    const verb = props.mode === 'younger' ? 'Younger than' : 'Older than'
    return `${verb} ${props.days}d`
})

const updateMenuPosition = () => {
    const trigger = triggerRef.value
    if (!trigger) return
    const rect = trigger.getBoundingClientRect()
    const width = Math.max(rect.width, 240)
    const left = Math.min(Math.max(8, rect.left), window.innerWidth - width - 8)
    const top = Math.min(window.innerHeight - 16, rect.bottom + 4)
    menuStyle.value = {
        position: 'fixed',
        left: `${left}px`,
        top: `${top}px`,
        width: `${width}px`,
        zIndex: '11000',
    }
}

const open = async () => {
    if (isOpen.value) return
    isOpen.value = true
    await nextTick()
    updateMenuPosition()
    window.addEventListener('resize', updateMenuPosition)
    window.addEventListener('scroll', updateMenuPosition, true)
}

const close = () => {
    isOpen.value = false
    window.removeEventListener('resize', updateMenuPosition)
    window.removeEventListener('scroll', updateMenuPosition, true)
}

const toggle = () => (isOpen.value ? close() : open())

const applyPreset = (preset: number) => emit('update:days', preset)
const onInput = (value: string) => {
    const parsed = Math.floor(Number(value))
    emit('update:days', Number.isFinite(parsed) && parsed > 0 ? parsed : null)
}
const clear = () => {
    emit('update:days', null)
    close()
}

const handlePointerDown = (event: MouseEvent) => {
    const target = event.target as Node | null
    if (target && (triggerRef.value?.contains(target) || menuRef.value?.contains(target))) return
    close()
}

document.addEventListener('mousedown', handlePointerDown)
onBeforeUnmount(() => {
    document.removeEventListener('mousedown', handlePointerDown)
    window.removeEventListener('resize', updateMenuPosition)
    window.removeEventListener('scroll', updateMenuPosition, true)
})
</script>

<template>
    <div ref="triggerRef" class="relative">
        <button
            type="button"
            @click="toggle"
            :class="[
                'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95 flex items-center gap-1.5',
                isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/20'
                    : 'bg-white/5 text-gray-400 border-white/10 hover:bg-white/10 hover:text-white'
            ]"
        >
            <Clock :size="12" class="shrink-0" />
            <span class="truncate">{{ summary }}</span>
            <span v-if="count != null" class="px-1.5 py-0.5 rounded-md text-[9px] bg-black/20" :class="isActive ? 'text-white' : 'text-gray-500'">{{ count }}</span>
            <X v-if="isActive" :size="12" class="text-gray-400 hover:text-white" @click.stop="clear" />
            <ChevronDown :size="12" class="shrink-0 text-gray-400 transition-transform" :class="isOpen && 'rotate-180'" />
        </button>

        <Teleport to="body">
            <div
                v-if="isOpen"
                ref="menuRef"
                :style="menuStyle"
                class="bg-[#1e1e2e] border border-white/10 rounded-lg shadow-xl p-3 space-y-3"
            >
                <div class="grid grid-cols-2 gap-1.5">
                    <button
                        type="button"
                        @click="emit('update:mode', 'older')"
                        :class="[
                            'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95',
                            mode === 'older'
                                ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/20'
                                : 'bg-white/5 text-gray-400 border-white/10 hover:bg-white/10 hover:text-white'
                        ]"
                    >Older than</button>
                    <button
                        type="button"
                        @click="emit('update:mode', 'younger')"
                        :class="[
                            'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95',
                            mode === 'younger'
                                ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/20'
                                : 'bg-white/5 text-gray-400 border-white/10 hover:bg-white/10 hover:text-white'
                        ]"
                    >Younger than</button>
                </div>
                <div class="flex items-center gap-2">
                    <input
                        type="number"
                        min="1"
                        :value="days ?? ''"
                        @input="onInput(($event.target as HTMLInputElement).value)"
                        placeholder="Days"
                        class="flex-1 min-w-0 bg-black/40 border border-white/10 rounded-lg px-2 h-9 text-sm text-gray-200 focus:outline-none focus:border-cyan-500/50"
                    />
                    <span class="text-[10px] font-semibold uppercase tracking-wider text-gray-500">days</span>
                </div>
                <div class="grid grid-cols-3 gap-1.5">
                    <button
                        v-for="preset in presets"
                        :key="preset"
                        type="button"
                        @click="applyPreset(preset)"
                        :class="[
                            'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95',
                            days === preset
                                ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/20'
                                : 'bg-white/5 text-gray-400 border-white/10 hover:bg-white/10 hover:text-white'
                        ]"
                    >{{ preset }}d</button>
                </div>
                <button
                    type="button"
                    @click="clear"
                    class="px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border bg-white/5 text-gray-400 border-white/10 hover:bg-white/10 hover:text-white outline-none active:scale-95"
                >Clear</button>
            </div>
        </Teleport>
    </div>
</template>
