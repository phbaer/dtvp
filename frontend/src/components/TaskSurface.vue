<script setup lang="ts">
import { computed, inject, watch } from 'vue'
import { taskActive, taskReady } from '../lib/productNavigation'
const props = withDefaults(defineProps<{ title: string; active?: boolean }>(), { active: undefined })
const emit = defineEmits<{ active: [boolean] }>()
const active = inject(taskActive, computed(() => true))
const ready = inject(taskReady, computed(() => true))
watch(() => (props.active ?? active.value) && ready.value, value => emit('active', value), { immediate: true })
</script>
<template><section class="task-surface"><h2 tabindex="-1">{{ title }}</h2><slot /></section></template>
<style scoped>.task-surface{min-width:0}.task-surface>h2{font-size:1.2rem;margin:0 0 16px}</style>
