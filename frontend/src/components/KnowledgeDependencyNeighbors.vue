<script setup lang="ts">
import { onBeforeUnmount, reactive, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
type Neighbor = { ref: string; name: string; version: string; resolved: boolean }
type Direction = 'incoming' | 'outgoing'
type Page = { state: string; component_ref: string; direction: Direction; items: Neighbor[]; total: number; declared_total: number; next_offset: number | null }
type Listing = { items: Neighbor[]; total: number; declared: number; next: number | null; offset: number; previous: number[]; query: string; applied: string; busy: boolean; error: string; sequence: number }
const props = defineProps<{ project: string; state: string; componentRef: string; incoming: Neighbor[]; outgoing: Neighbor[]; incomingTotal: number; outgoingTotal: number; disabled?: boolean }>()
const directions: Direction[] = ['incoming', 'outgoing']
const title = (direction: Direction) => direction === 'incoming' ? 'Direct consumers' : 'Direct dependencies'
function initial(direction: Direction): Listing {
  const items = props[direction], total = direction === 'incoming' ? props.incomingTotal : props.outgoingTotal
  return { items, total, declared: total, next: items.length < total ? items.length : null, offset: 0, previous: [], query: '', applied: '', busy: false, error: '', sequence: 0 }
}
const lists = reactive({ incoming: initial('incoming'), outgoing: initial('outgoing') })
async function load(direction: Direction, offset: number, query: string, movement: 'search' | 'next' | 'previous') {
  const list = lists[direction]
  if (props.disabled || list.busy) return
  const current = ++list.sequence, oldOffset = list.offset
  list.busy = true; list.error = ''
  try {
    const params = new URLSearchParams({ component_ref: props.componentRef, direction, q: query, offset: String(offset), limit: '50' })
    const value = await knowledgeApi<Page>(`/projects/${encodeURIComponent(props.project)}/states/${props.state}/component-neighbors?${params}`)
    if (current !== list.sequence) return
    if (value.state !== props.state || value.component_ref !== props.componentRef || value.direction !== direction) throw new Error('Dependency page does not match the selected state and component')
    list.items = value.items; list.total = value.total; list.declared = value.declared_total; list.next = value.next_offset; list.offset = offset; list.applied = query
    if (movement === 'search') list.previous = []
    else if (movement === 'next') list.previous.push(oldOffset)
    else list.previous.pop()
  } catch (value) { if (current === list.sequence) list.error = value instanceof Error ? value.message : 'Dependency page failed' }
  finally { if (current === list.sequence) list.busy = false }
}
function page(direction: Direction, forward: boolean) {
  const list = lists[direction], offset = forward ? list.next : list.previous.at(-1)
  if (offset !== null && offset !== undefined) void load(direction, offset, list.applied, forward ? 'next' : 'previous')
}
watch(() => [props.project, props.state, props.componentRef, props.incoming, props.outgoing], () => {
  for (const direction of directions) { const sequence = lists[direction].sequence + 1; Object.assign(lists[direction], initial(direction), { sequence }) }
})
onBeforeUnmount(() => { for (const direction of directions) ++lists[direction].sequence })
</script>
<template>
  <div class="dependency-neighbors"><section v-for="direction in directions" :key="direction" :aria-label="title(direction)">
    <strong>{{ title(direction) }}</strong>
    <form :aria-label="`Search ${title(direction).toLowerCase()}`" @submit.prevent="load(direction, 0, lists[direction].query, 'search')"><label>Find neighbor<input v-model="lists[direction].query" type="search" maxlength="500" :disabled="disabled || lists[direction].busy"></label><button :disabled="disabled || lists[direction].busy">Search</button></form>
    <p role="status">{{ lists[direction].total }} matching / {{ lists[direction].declared }} declared neighbors<span v-if="lists[direction].busy"> · Loading…</span></p>
    <p v-if="lists[direction].error" role="alert">{{ lists[direction].error }}. Displayed results and paging scope are retained.</p>
    <ul><li v-for="neighbor in lists[direction].items" :key="neighbor.ref">{{ neighbor.name || neighbor.ref }}<span v-if="neighbor.version"> @ {{ neighbor.version }}</span><small v-if="!neighbor.resolved"> · unresolved reference</small><details v-if="neighbor.name && neighbor.name !== neighbor.ref"><summary>Source-local reference</summary><code>{{ neighbor.ref }}</code></details></li></ul>
    <p v-if="!lists[direction].items.length && !lists[direction].busy">No matching declared neighbors. This does not establish non-use.</p>
    <nav :aria-label="`${title(direction)} pages`"><button :disabled="disabled || lists[direction].busy || !lists[direction].previous.length" @click="page(direction, false)">Previous neighbors</button><button :disabled="disabled || lists[direction].busy || lists[direction].next === null" @click="page(direction, true)">Next neighbors</button></nav>
  </section></div>
</template>
<style scoped>
.dependency-neighbors{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.8rem}.dependency-neighbors section{min-width:0}.dependency-neighbors form{display:flex;align-items:end;gap:.4rem}.dependency-neighbors label{display:grid;min-width:0}.dependency-neighbors input{width:100%;box-sizing:border-box}.dependency-neighbors li,.dependency-neighbors code{overflow-wrap:anywhere}.dependency-neighbors nav{display:flex;gap:.4rem}.dependency-neighbors p{font-size:.85rem}@media(max-width:550px){.dependency-neighbors{grid-template-columns:1fr}}
</style>
