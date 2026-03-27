<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ChevronLeft, ShieldCheck, Upload } from 'lucide-vue-next'
import { getTMRescoreContext, runTMRescoreAnalysis } from '../lib/api'
import { getRuntimeConfig } from '../lib/env'
import type { TMRescoreAnalysisResult, TMRescoreContext } from '../types'

const route = useRoute()
const projectName = computed(() => String(route.params.name || ''))

const context = ref<TMRescoreContext | null>(null)
const loading = ref(true)
const error = ref('')

const selectedScope = ref<'latest_only' | 'merged_versions'>('merged_versions')
const threatModelFile = ref<File | null>(null)
const itemsCsvFile = ref<File | null>(null)
const configFile = ref<File | null>(null)
const chainAnalysis = ref(true)
const prioritize = ref(true)
const whatIf = ref(false)
const enrich = ref(false)
const ollamaModel = ref('qwen2.5:7b')
const submitting = ref(false)
const result = ref<TMRescoreAnalysisResult | null>(null)
const submitError = ref('')

const contextPathRaw = getRuntimeConfig('DTVP_CONTEXT_PATH', '')
const contextPath = contextPathRaw ? (contextPathRaw.startsWith('/') ? contextPathRaw.replace(/\/$/, '') : '/' + contextPathRaw.replace(/\/$/, '')) : ''
const apiPrefix = `${contextPath || ''}/api`
const refreshSignalKey = computed(() => `dtvp:tmrescore-refresh:${projectName.value}`)
const projectReturnUrl = computed(() => `/project/${projectName.value}?refreshThreatModel=1`)

const outputFiles = computed(() => Object.keys(result.value?.outputs || {}))

const enrichmentStatus = computed(() => context.value?.llm_enrichment?.status || 'integration_disabled')
const enrichmentBadgeLabel = computed(() => {
  switch (enrichmentStatus.value) {
  case 'available':
    return 'Available'
  case 'not_configured':
    return 'Not Configured'
  case 'unreachable':
    return 'Unavailable'
  default:
    return 'Disabled'
  }
})
const enrichmentBadgeClass = computed(() => {
  switch (enrichmentStatus.value) {
  case 'available':
    return 'bg-emerald-500/15 text-emerald-200 border border-emerald-500/25'
  case 'unreachable':
    return 'bg-rose-500/10 text-rose-200 border border-rose-500/20'
  default:
    return 'bg-amber-500/10 text-amber-200 border border-amber-500/20'
  }
})

const getOutputUrl = (filename: string) => {
    if (!result.value?.session_id) return '#'
    return `${apiPrefix}/tmrescore/sessions/${encodeURIComponent(result.value.session_id)}/outputs/${encodeURIComponent(filename)}`
}

const handleFileChange = (event: Event, target: 'threatmodel' | 'items' | 'config') => {
    const input = event.target as HTMLInputElement
    const file = input.files?.[0] || null
    if (target === 'threatmodel') threatModelFile.value = file
    if (target === 'items') itemsCsvFile.value = file
    if (target === 'config') configFile.value = file
}

const loadContext = async () => {
    loading.value = true
    error.value = ''
    try {
        context.value = await getTMRescoreContext(projectName.value)
        selectedScope.value = context.value.recommended_scope
      ollamaModel.value = context.value.llm_enrichment?.default_model || 'qwen2.5:7b'
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Failed to load threat-model analysis context.'
    } finally {
        loading.value = false
    }
}

const submit = async () => {
    if (!threatModelFile.value) {
        submitError.value = 'A threat model file is required.'
        return
    }

    submitting.value = true
    submitError.value = ''
    result.value = null

    try {
        result.value = await runTMRescoreAnalysis(projectName.value, {
            scope: selectedScope.value,
            threatmodel: threatModelFile.value,
            itemsCsv: itemsCsvFile.value,
            config: configFile.value,
            chainAnalysis: chainAnalysis.value,
            prioritize: prioritize.value,
            whatIf: whatIf.value,
            enrich: enrich.value,
            ollamaModel: ollamaModel.value,
        })
      if (typeof window !== 'undefined' && window.sessionStorage) {
        window.sessionStorage.setItem(refreshSignalKey.value, String(Date.now()))
      }
    } catch (err: any) {
        submitError.value = err?.response?.data?.detail || err?.message || 'Threat-model analysis failed.'
    } finally {
        submitting.value = false
    }
}

onMounted(() => {
    loadContext()
})
</script>

<template>
  <div class="mx-auto space-y-6">
    <div class="flex flex-col gap-3">
      <router-link :to="projectReturnUrl" class="text-blue-400 hover:text-blue-300 text-sm flex items-center gap-1.5 font-medium transition-colors">
        <ChevronLeft :size="16" />
        Back to Project View
      </router-link>

      <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
        <div>
          <h2 class="text-4xl font-extrabold tracking-tight text-white leading-none">Threat-Model Analysis for {{ projectName }}</h2>
          <p class="mt-2 text-sm text-gray-400 max-w-3xl">
            This runs the external tmrescore service from DTVP. The recommended mode builds an analysis-only synthetic SBOM across all versions so historical vulnerabilities remain attached to the versioned components that actually carried them.
          </p>
        </div>
      </div>
    </div>

    <div v-if="loading" class="rounded-2xl border border-gray-800 bg-gray-900/80 p-6 text-gray-300">
      Loading threat-model analysis context...
    </div>

    <div v-else-if="error" class="rounded-2xl border border-red-800/40 bg-red-950/30 p-6 text-red-200">
      {{ error }}
    </div>

    <template v-else-if="context">
      <div class="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
        <section class="rounded-2xl border border-gray-800 bg-gray-900/80 p-6 shadow-xl shadow-black/20">
          <div class="flex items-center gap-3 mb-4">
            <ShieldCheck :size="18" class="text-blue-400" />
            <div>
              <h3 class="text-lg font-bold text-white">Analysis Input</h3>
              <p class="text-sm text-gray-400">Latest detected version: {{ context.latest_version }}</p>
            </div>
          </div>

          <div v-if="!context.enabled" class="rounded-xl border border-amber-700/40 bg-amber-950/30 p-4 text-sm text-amber-100">
            TMRescore is not configured on the backend. Set <span class="font-mono">DTVP_TMRESCORE_URL</span> and reload the app.
          </div>

          <form v-else class="space-y-5" @submit.prevent="submit">
            <div>
              <label class="block text-[11px] font-bold uppercase tracking-widest text-gray-400 mb-2">Scope</label>
              <div class="grid gap-3 md:grid-cols-2">
                <button
                  v-for="scopeOption in context.scopes"
                  :key="scopeOption.id"
                  type="button"
                  @click="selectedScope = scopeOption.id"
                  :class="[
                    'rounded-2xl border p-4 text-left transition-colors',
                    selectedScope === scopeOption.id
                      ? 'border-blue-500/60 bg-blue-500/10 text-white'
                      : 'border-gray-800 bg-gray-950/60 text-gray-300 hover:border-gray-700'
                  ]"
                  :data-testid="`scope-${scopeOption.id}`"
                >
                  <div class="flex items-center justify-between gap-3">
                    <span class="font-semibold">{{ scopeOption.label }}</span>
                    <span v-if="scopeOption.id === context.recommended_scope" class="rounded-full bg-blue-500/20 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-blue-200">Recommended</span>
                  </div>
                  <p class="mt-2 text-sm text-gray-400">{{ scopeOption.description }}</p>
                </button>
              </div>
            </div>

            <div class="grid gap-4 md:grid-cols-3">
              <label class="block rounded-2xl border border-gray-800 bg-gray-950/60 p-4">
                <span class="block text-[11px] font-bold uppercase tracking-widest text-gray-400 mb-2">Threat Model</span>
                <input type="file" accept=".tm7" @change="handleFileChange($event, 'threatmodel')" data-testid="threatmodel-input" class="block w-full text-sm text-gray-300 file:mr-3 file:rounded-lg file:border-0 file:bg-blue-600 file:px-3 file:py-2 file:text-white" />
                <span class="mt-2 block text-xs text-gray-500">Required. Upload the current TM7 export.</span>
              </label>

              <label class="block rounded-2xl border border-gray-800 bg-gray-950/60 p-4">
                <span class="block text-[11px] font-bold uppercase tracking-widest text-gray-400 mb-2">items.csv</span>
                <input type="file" accept=".csv" @change="handleFileChange($event, 'items')" class="block w-full text-sm text-gray-300 file:mr-3 file:rounded-lg file:border-0 file:bg-gray-700 file:px-3 file:py-2 file:text-white" />
                <span class="mt-2 block text-xs text-gray-500">Optional component-to-threat-model mapping.</span>
              </label>

              <label class="block rounded-2xl border border-gray-800 bg-gray-950/60 p-4">
                <span class="block text-[11px] font-bold uppercase tracking-widest text-gray-400 mb-2">Config YAML</span>
                <input type="file" accept=".yaml,.yml" @change="handleFileChange($event, 'config')" class="block w-full text-sm text-gray-300 file:mr-3 file:rounded-lg file:border-0 file:bg-gray-700 file:px-3 file:py-2 file:text-white" />
                <span class="mt-2 block text-xs text-gray-500">Optional rescoring config for trust boundaries and overrides.</span>
              </label>
            </div>

            <div class="grid gap-3 md:grid-cols-3">
              <label class="flex items-center gap-3 rounded-xl border border-gray-800 bg-gray-950/60 px-4 py-3 text-sm text-gray-300">
                <input v-model="chainAnalysis" type="checkbox" class="h-4 w-4 rounded border-gray-600 bg-gray-900 text-blue-500" />
                Chain analysis
              </label>
              <label class="flex items-center gap-3 rounded-xl border border-gray-800 bg-gray-950/60 px-4 py-3 text-sm text-gray-300">
                <input v-model="prioritize" type="checkbox" class="h-4 w-4 rounded border-gray-600 bg-gray-900 text-blue-500" />
                Prioritize results
              </label>
              <label class="flex items-center gap-3 rounded-xl border border-gray-800 bg-gray-950/60 px-4 py-3 text-sm text-gray-300">
                <input v-model="whatIf" type="checkbox" class="h-4 w-4 rounded border-gray-600 bg-gray-900 text-blue-500" />
                What-if mode
              </label>
            </div>

            <div class="rounded-2xl border border-gray-800 bg-gray-950/60 p-4 space-y-3">
              <div class="flex items-center justify-between gap-4">
                <label class="flex items-center gap-3 text-sm text-gray-300">
                  <input
                    v-model="enrich"
                    type="checkbox"
                    class="h-4 w-4 rounded border-gray-600 bg-gray-900 text-blue-500"
                    :disabled="!context.llm_enrichment?.available"
                  />
                  LLM enrichment
                </label>
                <span
                  data-testid="llm-enrichment-status"
                  class="rounded-full px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider"
                  :class="enrichmentBadgeClass"
                >
                  {{ enrichmentBadgeLabel }}
                </span>
              </div>

              <div class="grid gap-3 md:grid-cols-[1fr_auto] md:items-end">
                <label class="block">
                  <span class="block text-[11px] font-bold uppercase tracking-widest text-gray-400 mb-2">Ollama Model</span>
                  <input
                    v-model="ollamaModel"
                    type="text"
                    placeholder="qwen2.5:7b"
                    class="block w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200"
                    :disabled="!context.llm_enrichment?.available || !enrich"
                    data-testid="ollama-model-input"
                  />
                </label>
                <div class="text-xs text-gray-500 md:max-w-xs">
                  Adds LLM-based threat justification enrichment before analysis when the tmrescore backend has Ollama configured.
                </div>
              </div>

              <div v-if="context.llm_enrichment?.warning" class="text-xs text-amber-200/80">
                {{ context.llm_enrichment.warning }}
              </div>
            </div>

            <div v-if="submitError" class="rounded-xl border border-red-800/40 bg-red-950/30 px-4 py-3 text-sm text-red-200">
              {{ submitError }}
            </div>

            <div class="flex items-center gap-4">
              <button
                type="submit"
                :disabled="submitting || !context.enabled"
                class="inline-flex items-center gap-2 rounded-xl border border-blue-500/30 bg-blue-600/15 px-4 py-2 text-sm font-semibold text-blue-200 transition-colors hover:bg-blue-600/25 disabled:cursor-not-allowed disabled:opacity-50"
                data-testid="run-tmrescore-analysis"
              >
                <Upload :size="16" />
                {{ submitting ? 'Running Analysis...' : 'Run Threat-Model Analysis' }}
              </button>

              <div class="text-sm text-gray-500">
                {{ context.versions.length }} version<span v-if="context.versions.length !== 1">s</span> available in DTVP
              </div>
            </div>
          </form>
        </section>

        <aside class="space-y-4">
          <section class="rounded-2xl border border-gray-800 bg-gray-900/80 p-6 shadow-xl shadow-black/20">
            <h3 class="text-lg font-bold text-white">Version Scope</h3>
            <div class="mt-4 flex flex-wrap gap-2">
              <span v-for="version in context.versions" :key="version" class="rounded-full border border-gray-700 bg-gray-950/70 px-3 py-1 text-xs text-gray-300">
                v{{ version }}
              </span>
            </div>
          </section>

          <section class="rounded-2xl border border-gray-800 bg-gray-900/80 p-6 shadow-xl shadow-black/20">
            <h3 class="text-lg font-bold text-white">Why Merged Mode</h3>
            <ul class="mt-4 space-y-3 text-sm text-gray-300">
              <li v-for="warning in context.warnings" :key="warning" class="rounded-xl border border-gray-800 bg-gray-950/60 px-4 py-3">
                {{ warning }}
              </li>
            </ul>
          </section>
        </aside>
      </div>

      <section v-if="result" class="rounded-2xl border border-gray-800 bg-gray-900/80 p-6 shadow-xl shadow-black/20">
        <div class="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <h3 class="text-2xl font-bold text-white">Analysis Result</h3>
            <p class="text-sm text-gray-400">{{ result.strategy_note }}</p>
          </div>
          <span class="rounded-full border border-green-500/30 bg-green-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-green-200">
            {{ result.status }}
          </span>
        </div>

        <div class="mt-6 grid gap-4 md:grid-cols-4">
          <div class="rounded-2xl border border-gray-800 bg-gray-950/60 p-4">
            <div class="text-[11px] uppercase tracking-widest text-gray-500">Analyzed Versions</div>
            <div class="mt-2 text-2xl font-bold text-white">{{ result.analyzed_versions.length }}</div>
          </div>
          <div class="rounded-2xl border border-gray-800 bg-gray-950/60 p-4">
            <div class="text-[11px] uppercase tracking-widest text-gray-500">SBOM Components</div>
            <div class="mt-2 text-2xl font-bold text-white">{{ result.sbom_component_count }}</div>
          </div>
          <div class="rounded-2xl border border-gray-800 bg-gray-950/60 p-4">
            <div class="text-[11px] uppercase tracking-widest text-gray-500">Total CVEs</div>
            <div class="mt-2 text-2xl font-bold text-white">{{ result.total_cves }}</div>
          </div>
          <div class="rounded-2xl border border-gray-800 bg-gray-950/60 p-4">
            <div class="text-[11px] uppercase tracking-widest text-gray-500">Rescored</div>
            <div class="mt-2 text-2xl font-bold text-white">{{ result.rescored_count }}</div>
          </div>
        </div>

        <div class="mt-6 grid gap-6 lg:grid-cols-[1fr_0.8fr]">
          <div class="rounded-2xl border border-gray-800 bg-gray-950/60 p-5">
            <div class="text-[11px] uppercase tracking-widest text-gray-500">Summary</div>
            <dl class="mt-4 space-y-3 text-sm text-gray-300">
              <div class="flex items-center justify-between gap-4">
                <dt>Session ID</dt>
                <dd class="font-mono text-xs text-gray-400">{{ result.session_id }}</dd>
              </div>
              <div class="flex items-center justify-between gap-4">
                <dt>Scope</dt>
                <dd>{{ result.scope }}</dd>
              </div>
              <div class="flex items-center justify-between gap-4">
                <dt>Latest Version</dt>
                <dd>{{ result.latest_version }}</dd>
              </div>
              <div class="flex items-center justify-between gap-4">
                <dt>Elapsed Seconds</dt>
                <dd>{{ result.elapsed_seconds }}</dd>
              </div>
              <div class="flex items-center justify-between gap-4">
                <dt>Average Score Reduction</dt>
                <dd>{{ result.avg_score_reduction }}</dd>
              </div>
              <div class="flex items-center justify-between gap-4">
                <dt>LLM Enrichment</dt>
                <dd>{{ result.llm_enrichment?.enabled ? `Enabled (${result.llm_enrichment?.ollama_model || 'default'})` : 'Disabled' }}</dd>
              </div>
            </dl>
          </div>

          <div class="rounded-2xl border border-gray-800 bg-gray-950/60 p-5">
            <div class="text-[11px] uppercase tracking-widest text-gray-500">Downloads</div>
            <div class="mt-4 flex flex-col gap-3 text-sm">
              <a :href="result.download_urls.json" target="_blank" rel="noopener noreferrer" class="rounded-xl border border-blue-500/30 bg-blue-600/10 px-4 py-3 text-blue-200 transition-colors hover:bg-blue-600/20">
                Download Raw JSON Results
              </a>
              <a :href="result.download_urls.vex" target="_blank" rel="noopener noreferrer" class="rounded-xl border border-blue-500/30 bg-blue-600/10 px-4 py-3 text-blue-200 transition-colors hover:bg-blue-600/20">
                Download CycloneDX VEX
              </a>
              <a
                v-for="filename in outputFiles"
                :key="filename"
                :href="getOutputUrl(filename)"
                target="_blank"
                rel="noopener noreferrer"
                class="rounded-xl border border-gray-700 bg-gray-900 px-4 py-3 text-gray-200 transition-colors hover:border-gray-600"
              >
                Download {{ filename }}
              </a>
            </div>
          </div>
        </div>
      </section>
    </template>
  </div>
</template>