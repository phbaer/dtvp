<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
type Status = { available: boolean; generation: string | null; records?: number; assurance?: string; source?: string; synthetic?: boolean; limitations: string[] }
type Item = { record: { cpe: { cpeName: string; cpeNameId: string; deprecated: boolean; titles?: { title: string; lang?: string }[] } }; record_sha256: string; member: string }
type Page = { generation: string; archive_sha256: string; meta_sha256: string; query: string; total: number; items: Item[]; next_offset: number | null; limitations: string[] }
type Export = { content_base64: string; artifact_sha256: string; capture: Page; unprojected_record_fields: string[]; selection_scope: string }
const props = defineProps<{ project: string; disabled?: boolean }>()
const emit = defineEmits<{ locked: [boolean] }>()
const status = ref<Status | null>(null), page = ref<Page | null>(null), busy = ref(false), expanded = ref(false)
const query = ref(''), deprecated = ref(false), capturedDeprecated = ref(false), offset = ref(0), error = ref('')
const download = ref(''), downloadHash = ref(''), exportFields = ref<string[]>([])
const blocked = computed(() => busy.value || props.disabled)
let sequence = 0
const root = () => `/projects/${encodeURIComponent(props.project)}/cpe/catalog`
watch(busy, value => emit('locked', value), { flush: 'sync' })
function clearDownload() { if (download.value) URL.revokeObjectURL(download.value); download.value = ''; downloadHash.value = ''; exportFields.value = [] }
function failed(err: unknown) { error.value = err instanceof Error ? err.message : 'Catalog unavailable' }
async function inspect() {
  if (blocked.value) return
  const current = ++sequence; busy.value = true; error.value = ''
  try {
    const result = await knowledgeApi<Status>(root())
    if (current !== sequence) return
    if (result.available && !/^[a-f0-9]{64}$/.test(result.generation || '')) throw new Error('Catalog status lacks an exact generation pin.')
    status.value = result; page.value = null; offset.value = 0; clearDownload()
  } catch (err) { if (current === sequence) failed(err) }
  finally { if (current === sequence) busy.value = false }
}
async function search(next?: number) {
  if (blocked.value || !status.value?.generation) return
  const generation = next === undefined ? status.value.generation : page.value?.generation
  const text = next === undefined ? query.value.trim() : page.value?.query
  const includeDeprecated = next === undefined ? deprecated.value : capturedDeprecated.value
  if (!generation || !text || text.length < 2) return
  const current = ++sequence; busy.value = true; error.value = ''
  try {
    const result = await knowledgeApi<Page>(`${root()}/search?${new URLSearchParams({ q: text, generation, offset: String(next || 0), limit: '25', include_deprecated: String(includeDeprecated) })}`)
    if (current !== sequence) return
    if (result.generation !== generation || result.query !== text) throw new Error('Catalog search changed its requested generation or query.')
    page.value = result; offset.value = next || 0; capturedDeprecated.value = includeDeprecated; clearDownload()
  } catch (err) { if (current === sequence) failed(err) }
  finally { if (current === sequence) busy.value = false }
}
async function prepareDownload() {
  if (blocked.value || !page.value) return
  const pin = page.value, current = ++sequence; busy.value = true; error.value = ''
  try {
    const result = await knowledgeApi<Export>(`${root()}/export?${new URLSearchParams({ q: pin.query, generation: pin.generation, offset: String(offset.value), limit: '25', include_deprecated: String(capturedDeprecated.value) })}`)
    if (current !== sequence) return
    if (result.capture.generation !== pin.generation || result.capture.query !== pin.query || result.capture.archive_sha256 !== pin.archive_sha256 || result.capture.meta_sha256 !== pin.meta_sha256 || JSON.stringify(result.capture.items.map(item => item.record_sha256)) !== JSON.stringify(pin.items.map(item => item.record_sha256))) throw new Error('Catalog export differs from the selected result page.')
    if (!/^[a-f0-9]{64}$/.test(result.artifact_sha256) || typeof result.content_base64 !== 'string' || result.content_base64.length > 4 * Math.ceil(2 * 1024 * 1024 / 3)) throw new Error('Catalog export lacks bounded exact bytes.')
    const bytes = Uint8Array.from(atob(result.content_base64), char => char.charCodeAt(0))
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), byte => byte.toString(16).padStart(2, '0')).join('')
    if (current !== sequence) return
    if (hash !== result.artifact_sha256) throw new Error('Catalog export byte hash differs from its receipt.')
    clearDownload(); download.value = URL.createObjectURL(new Blob([bytes], { type: 'application/json' })); downloadHash.value = hash; exportFields.value = result.unprojected_record_fields
  } catch (err) { if (current === sequence) failed(err) }
  finally { if (current === sequence) busy.value = false }
}
function toggle(event: Event) { expanded.value = (event.target as HTMLDetailsElement).open; if (expanded.value && !status.value) void inspect() }
watch(() => props.project, () => { ++sequence; busy.value = false; status.value = null; page.value = null; query.value = ''; error.value = ''; clearDownload(); if (expanded.value) void inspect() })
onBeforeUnmount(() => { ++sequence; clearDownload(); emit('locked', false) })
</script>
<template>
  <details class="cpe-catalog" aria-label="Local CPE catalog" @toggle="toggle">
    <summary>Local catalog (optional)</summary>
    <p v-if="error" role="alert">{{ error }}</p>
    <button type="button" :disabled="blocked" @click="inspect">Refresh catalog availability</button>
    <p v-if="status && !status.available" class="hint">No catalog installed. An instance operator can import the official archive and META file locally. Project mappings are unchanged.</p>
    <template v-if="status?.available">
      <p>{{ status.records }} captured CPE records. Catalog search does not apply mappings.</p><p v-if="status.synthetic" class="hint">Synthetic demonstration catalog: these records are invented.</p><p v-if="status.source" class="hint">{{ status.source }}</p>
      <form @submit.prevent="search()"><label>Search local CPE catalog<input v-model="query" minlength="2" maxlength="200" :disabled="blocked"></label><label class="check"><input v-model="deprecated" type="checkbox" :disabled="blocked">Include deprecated CPE names</label><button :disabled="blocked || query.trim().length < 2">Search catalog</button></form>
      <section v-if="page" aria-label="Pinned catalog results"><p>{{ page.total }} matches for “{{ page.query }}” · {{ page.items.length }} on this page</p>
        <article v-for="item in page.items" :key="item.record_sha256"><strong>{{ item.record.cpe.titles?.find(title => title.lang === 'en')?.title || item.record.cpe.cpeName }}</strong><span v-if="item.record.cpe.deprecated"> · Deprecated</span><code>{{ item.record.cpe.cpeName }}</code><details><summary>Candidate source details</summary><p>{{ item.record.cpe.cpeNameId }} · {{ item.member }}</p><code>{{ item.record_sha256 }}</code></details></article>
        <div class="actions"><button type="button" :disabled="blocked || offset === 0" @click="search(Math.max(0, offset - 25))">Previous catalog page</button><button type="button" :disabled="blocked || page.next_offset === null" @click="search(page.next_offset || 0)">Next catalog page</button><button type="button" :disabled="blocked || !page.items.length" @click="prepareDownload">Prepare this candidate page</button></div>
        <a v-if="download" :href="download" :download="`cpe-candidates-${page.generation.slice(0,12)}.json`">Download candidate dictionary</a>
        <p v-if="download" class="hint">Only this page is exported. Upload it through the explicit curated source preview below; no project policy or reviewed mapping has been changed.</p>
        <details><summary>Catalog generation and export provenance</summary><code>{{ page.generation }}</code><code>{{ page.archive_sha256 }}</code><code>{{ page.meta_sha256 }}</code><code v-if="downloadHash">{{ downloadHash }}</code><p v-if="exportFields.length">Original fields retained in archive, outside the curated export: {{ exportFields.join(', ') }}</p><p v-for="text in page.limitations" :key="text" class="hint">{{ text }}</p></details>
      </section>
    </template>
  </details>
</template>
<style scoped>
.cpe-catalog{margin-block:.75rem;min-width:0}.cpe-catalog summary{cursor:pointer}.cpe-catalog label{display:grid;gap:.3rem;margin-block:.6rem}.cpe-catalog input:not([type=checkbox]){width:100%;box-sizing:border-box}.cpe-catalog .check{display:flex;align-items:center;gap:.4rem}.cpe-catalog code{display:block;font-size:.75rem;overflow-wrap:anywhere}.cpe-catalog article{padding-block:.5rem;border-top:1px solid var(--line);overflow-wrap:anywhere}.actions{display:flex;flex-wrap:wrap;gap:.4rem;margin-block:.6rem}.hint{font-size:.8rem;color:var(--muted)}
</style>
