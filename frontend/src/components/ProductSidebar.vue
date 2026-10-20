<script setup lang="ts">
import { productPages, type ProductNavigation } from '../lib/productNavigation'
defineProps<{ navigation: ProductNavigation; disabled: boolean }>()
const emit = defineEmits<{ navigate: [view: string, task?: string] }>()
</script>
<template>
  <nav aria-label="Product" class="product-sidebar">
    <p class="product-name" :title="navigation.name">{{ navigation.name }}</p>
    <div v-for="group in productPages" :key="group.id" class="product-group">
      <button :data-product-view="group.id" :class="{ selected: navigation.view === group.id }" :aria-current="navigation.view === group.id && group.tasks.length === 1 ? 'page' : undefined" :disabled="disabled || navigation.locked" @click="emit('navigate', group.id)">{{ group.id }}</button>
      <nav v-if="navigation.view === group.id && group.tasks.length > 1" :aria-label="group.id === 'Settings' ? 'Product settings' : `${group.id} pages`" class="task-links">
        <button v-for="task in group.tasks" :key="task.id" :data-task-link="task.id" :aria-current="navigation.task === task.id ? 'page' : undefined" :disabled="disabled || navigation.locked" @click="emit('navigate', group.id, task.id)">{{ task.label }}</button>
      </nav>
    </div>
  </nav>
</template>
<style scoped>
.product-sidebar{display:flex;flex-direction:column;width:100%}.product-sidebar button{display:flex;justify-content:flex-start;text-align:left;border:0;background:none;padding:8px 12px;border-radius:5px}.task-links{display:flex;flex-direction:column}
.product-sidebar{border-top:1px solid var(--line);padding-top:14px;gap:2px!important}.product-name{font-size:.76rem;font-weight:650;color:var(--muted);padding:0 12px;margin:0 0 8px;overflow-wrap:anywhere}.product-group{min-width:0}.product-group>button{width:100%;font-size:.85rem}.product-group>button.selected{font-weight:650;color:var(--ink)}.task-links{border-left:1px solid var(--line);margin:2px 0 6px 15px;width:calc(100% - 15px)!important;gap:2px!important}.task-links button{font-size:.8rem;text-align:left;white-space:normal;padding:7px 10px!important;min-height:32px}.task-links button[aria-current=page]{background:var(--accent-soft);color:var(--accent);font-weight:600}
</style>
