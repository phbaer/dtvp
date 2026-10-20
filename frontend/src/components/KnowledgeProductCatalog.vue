<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { api } from '../api'
import type { Me, Project } from '../types'
type CatalogProject = Project & { version_count?: number }
const props = defineProps<{ me: Me; disabled?: boolean }>()
const emit = defineEmits<{ open: [project: Project] }>()
const query = ref(''), workspace = ref(''), products = ref<CatalogProject[]>([]), cursor = ref<string | null>(null)
const loading = ref(false), error = ref('')
let sequence = 0, timer: ReturnType<typeof setTimeout>
async function load(append = false) {
  const current = ++sequence; loading.value = true; error.value = ''
  try {
    const params = new URLSearchParams({ q: query.value, limit: '25' })
    if (workspace.value) params.set('workspace_id', workspace.value)
    if (append && cursor.value) params.set('cursor', cursor.value)
    const result = await api<{ items: CatalogProject[]; next_cursor: string | null }>(`/catalog/projects?${params}`)
    if (current !== sequence) return
    products.value = append ? [...products.value, ...result.items] : result.items
    cursor.value = result.next_cursor
  } catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Unable to load products' }
  finally { if (current === sequence) loading.value = false }
}
watch([query, workspace], () => { ++sequence; products.value = []; cursor.value = null; clearTimeout(timer); timer = setTimeout(() => { void load() }, 180) })
void load()
onBeforeUnmount(() => { ++sequence; clearTimeout(timer) })
</script>
<template>
  <section aria-label="Product catalog" class="product-catalog">
    <p class="catalog-intro">Open a product to explore versions, evidence and review work.</p>
    <div class="filters"><label class="search">Search products<input v-model="query" type="search" placeholder="Product name…" :disabled="disabled"></label><label v-if="me.workspaces.length > 1">Product owner team<select v-model="workspace" :disabled="disabled"><option value="">All product owners</option><option v-for="team in me.workspaces" :key="team.id" :value="team.id">{{ team.name }}</option></select></label></div>
    <p v-if="error" role="alert" class="message error">{{ error }} <button :disabled="loading || disabled" @click="load()">Try again</button></p>
    <p v-if="loading" role="status">Loading products…</p>
    <div v-if="products.length" class="table-wrap"><table><thead><tr><th>Product</th><th>Product owner team</th><th>Versions</th><th>Action</th></tr></thead><tbody><tr v-for="product in products" :key="product.id"><td><strong>{{ product.name }}</strong></td><td>{{ product.workspace || me.workspaces.find(team => team.id === product.workspace_id)?.name || 'Not supplied' }}</td><td>{{ product.version_count ?? 'Not supplied' }}</td><td><button :aria-label="`Open ${product.name}`" :disabled="disabled || loading" @click="emit('open', product)">Open product</button></td></tr></tbody></table></div>
    <p v-else-if="!loading && !error" class="empty">{{ query || workspace ? 'No products match this search.' : 'No accessible products yet. An authorized importer can create a product through SBOM intake.' }}</p>
    <button v-if="cursor" :disabled="loading || disabled" @click="load(true)">Load more products</button>
  </section>
</template>
<style scoped>
.product-catalog { max-width:1100px; }
.search { max-width:560px; }
.product-catalog .message { margin:12px 0; }
td:first-child { overflow-wrap:anywhere; }
@media(max-width:650px) { th,td { padding:9px; } th:nth-child(2),td:nth-child(2) { display:none; } }
</style>
