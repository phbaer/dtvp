<script setup lang="ts">
import { computed, provide } from 'vue'
import { taskActive } from '../lib/productNavigation'
const props = defineProps<{ active: boolean; id: string; view: string }>()
provide(taskActive, computed(() => props.active))
</script>
<template><section v-show="active" :data-task="id" :data-task-view="view" class="workflow-task"><slot /></section></template>
<style scoped>.workflow-task{min-width:0;margin-block:20px}</style>
