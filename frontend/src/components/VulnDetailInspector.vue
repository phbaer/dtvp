<script setup lang="ts">
import type { GroupedVuln } from '../types'
import VulnGroupCard from './VulnGroupCard.vue'

defineProps<{
    group: GroupedVuln
}>()

const emit = defineEmits<{
    (e: 'close'): void
    (e: 'update', group?: GroupedVuln): void
    (e: 'update:assessment', data: any): void
}>()
</script>

<template>
    <aside
        class="relative flex h-full min-h-0 flex-col overflow-hidden"
        data-testid="vuln-detail-inspector"
    >
        <div class="min-h-0 grow overflow-y-auto overscroll-contain">
            <VulnGroupCard
                :group="group"
                :inModal="true"
                @close="emit('close')"
                @update="(updatedGroup) => emit('update', updatedGroup)"
                @update:assessment="(data) => emit('update:assessment', data)"
            />
        </div>
    </aside>
</template>
