<script setup lang="ts">
import { computed, inject, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { CheckCircle2, ChevronLeft, Download, ExternalLink, RefreshCw, ShieldCheck, Upload, WandSparkles } from 'lucide-vue-next'
import {
  getPreparedVScorerThreatModelDownloadUrl,
  getPreparedVScorerWizardEditor,
  getVScorerContext,
  getVScorerProjectState,
  getVScorerSyntheticSbomDownloadUrl,
  getVScorerSyntheticSbomSummary,
  patchPreparedVScorerWizardEditor,
  prepareVScorerAnalysis,
  refreshPreparedVScorerWizardContext,
  resumeVScorerAnalysis,
  runPreparedVScorerAnalysis,
  runVScorerAnalysis,
  validatePreparedVScorerWizardInputs,
} from '../lib/api'
import { getRuntimeConfig } from '../lib/env'
import type {
  TMRescoreAnalysisProgress,
  TMRescoreProjectState,
  TMRescoreAnalysisResult,
  TMRescoreContext,
  TMRescoreSyntheticSbomSummary,
  VScorerThreatModelEditorIssue,
} from '../types'

const route = useRoute()
const projectName = computed(() => String(route.params.name || ''))
const realRole = inject<any>('realRole', ref('ANALYST'))
const isReviewer = computed(() => realRole.value === 'REVIEWER')

const context = ref<TMRescoreContext | null>(null)
const loading = ref(true)
const error = ref('')
const progressMessage = ref('Initializing threat-model analysis...')
const progressValue = ref(0)
const progressLog = ref<string[]>([])
const logContainer = ref<HTMLElement | null>(null)

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
const preparingWizard = ref(false)
const refreshingWizardContext = ref(false)
const validatingWizardInputs = ref(false)
const loadingWizardEditor = ref(false)
const applyingWizardIssueId = ref('')
const result = ref<TMRescoreAnalysisResult | null>(null)
const submitError = ref('')
const syntheticSbomSummary = ref<TMRescoreSyntheticSbomSummary | null>(null)
const syntheticSbomSummaryLoading = ref(false)
const syntheticSbomSummaryError = ref('')
const syntheticSbomSummaryRequestId = ref(0)
const cachedProjectState = ref<TMRescoreProjectState | null>(null)
const refreshingCachedState = ref(false)

const contextPathRaw = getRuntimeConfig('DTVP_CONTEXT_PATH', '')
const contextPath = contextPathRaw ? (contextPathRaw.startsWith('/') ? contextPathRaw.replace(/\/$/, '') : '/' + contextPathRaw.replace(/\/$/, '')) : ''
const apiPrefix = `${contextPath || ''}/api`
const refreshSignalKey = computed(() => `dtvp:vscorer-refresh:${projectName.value}`)
const legacyRefreshSignalKey = computed(() => `dtvp:tmrescore-refresh:${projectName.value}`)
const projectReturnUrl = computed(() => `/project/${projectName.value}`)
const syntheticSbomDownloadUrl = computed(() => getVScorerSyntheticSbomDownloadUrl(projectName.value, selectedScope.value))

const outputFiles = computed(() => Object.keys(result.value?.outputs || {}))
const preparedVScorerState = computed(() => (
  cachedProjectState.value?.status === 'prepared' ? cachedProjectState.value : null
))
const wizardContext = computed(() => cachedProjectState.value?.wizard_context || null)
const wizardCatalogs = computed(() => cachedProjectState.value?.wizard_catalogs || null)
const wizardValidationSummary = computed(() => wizardContext.value?.validation?.summary || null)
const wizardValidationReports = computed(() => wizardContext.value?.validation?.reports || [])
const wizardThreatModelElementCount = computed(() => wizardContext.value?.threat_model?.elements?.length ?? null)
const wizardThreatBoundaryCount = computed(() => wizardContext.value?.threat_model?.boundaries?.length ?? null)
const wizardEditor = computed(() => wizardContext.value?.editor || wizardContext.value?.threat_model_editor || null)
const wizardEditorIssues = computed(() => wizardEditor.value?.issues || [])
const wizardEditorIssueCount = computed(() => wizardEditorIssues.value.length)
const wizardOpenEditorIssueCount = computed(() => wizardEditorIssues.value.filter(issue => !issue.kept).length)
const wizardRuleTypes = computed(() => {
  const ruleTypes = wizardCatalogs.value?.rescoring_rule_types
  if (Array.isArray(ruleTypes)) return ruleTypes
  if (ruleTypes && typeof ruleTypes === 'object') {
    return Object.values(ruleTypes).flatMap((items: any) => Array.isArray(items) ? items : [])
  }
  return []
})
const wizardRuleTypeCount = computed(() => wizardRuleTypes.value.length)
const wizardAttackMitigationCount = computed(() => wizardCatalogs.value?.attack_mitigations?.length ?? null)
const preparedThreatModelDownloadUrl = computed(() => (
  cachedProjectState.value?.session_id ? getPreparedVScorerThreatModelDownloadUrl(cachedProjectState.value.session_id) : '#'
))

const progressTimer = ref<number | null>(null)
const stagedProgressTimers: number[] = []

const stopProgressTimer = () => {
  if (progressTimer.value !== null && typeof window !== 'undefined') {
    window.clearInterval(progressTimer.value)
  }
  progressTimer.value = null
}

const clearStagedProgressTimers = () => {
  if (typeof window === 'undefined') return
  while (stagedProgressTimers.length > 0) {
    const timerId = stagedProgressTimers.pop()
    if (timerId !== undefined) {
      window.clearTimeout(timerId)
    }
  }
}

const getScopeLabel = (scope: 'latest_only' | 'merged_versions') => (
  scope === 'merged_versions' ? 'merged multi-version' : 'latest-only'
)

const formatCachedTimestamp = (timestamp?: number | null) => {
  if (!timestamp || Number.isNaN(timestamp)) return 'Not available'
  return new Date(timestamp * 1000).toLocaleString()
}

const formatRelativeTimestamp = (timestamp?: number | null) => {
  if (!timestamp || Number.isNaN(timestamp)) return 'Not available'
  const diffSeconds = Math.round((Date.now() / 1000) - timestamp)
  const absoluteDiff = Math.abs(diffSeconds)
  if (absoluteDiff < 60) return `${absoluteDiff} second${absoluteDiff === 1 ? '' : 's'} ago`
  if (absoluteDiff < 3600) {
    const minutes = Math.round(absoluteDiff / 60)
    return `${minutes} minute${minutes === 1 ? '' : 's'} ago`
  }
  if (absoluteDiff < 86400) {
    const hours = Math.round(absoluteDiff / 3600)
    return `${hours} hour${hours === 1 ? '' : 's'} ago`
  }
  const days = Math.round(absoluteDiff / 86400)
  return `${days} day${days === 1 ? '' : 's'} ago`
}

const updateCachedProjectState = (state: Partial<TMRescoreProjectState | TMRescoreAnalysisProgress>) => {
  if (!state.session_id) return
  const previous = cachedProjectState.value
  cachedProjectState.value = {
    session_id: state.session_id,
    status: state.status || previous?.status || 'running',
    progress: state.progress ?? previous?.progress ?? 0,
    message: state.message || previous?.message || '',
    log: state.log || previous?.log || [],
    error: state.error ?? previous?.error ?? null,
    scope: (state as Partial<TMRescoreProjectState>).scope || previous?.scope || selectedScope.value,
    latest_version: (state as Partial<TMRescoreProjectState>).latest_version || previous?.latest_version || context.value?.latest_version || '',
    analyzed_versions: (state as Partial<TMRescoreProjectState>).analyzed_versions || previous?.analyzed_versions || [],
    llm_enrichment: (state as Partial<TMRescoreProjectState>).llm_enrichment || previous?.llm_enrichment || { enabled: false, ollama_model: null },
    created_at: state.created_at ?? previous?.created_at ?? null,
    updated_at: state.updated_at ?? previous?.updated_at ?? null,
    completed_at: state.completed_at ?? previous?.completed_at ?? null,
    result: state.result ?? previous?.result ?? null,
    wizard_url: state.wizard_url ?? previous?.wizard_url ?? null,
    wizard_context: state.wizard_context ?? previous?.wizard_context ?? null,
    wizard_catalogs: state.wizard_catalogs ?? previous?.wizard_catalogs ?? null,
  }
}

const clearPreparedWizardState = () => {
  if (preparedVScorerState.value) {
    cachedProjectState.value = null
  }
}

const loadSyntheticSbomSummary = async (mode: 'initial' | 'refresh' = 'refresh') => {
  if (!context.value?.enabled || !projectName.value) {
    syntheticSbomSummary.value = null
    syntheticSbomSummaryError.value = ''
    syntheticSbomSummaryLoading.value = false
    return
  }

  const requestId = syntheticSbomSummaryRequestId.value + 1
  syntheticSbomSummaryRequestId.value = requestId
  syntheticSbomSummaryLoading.value = true
  syntheticSbomSummaryError.value = ''

  if (mode === 'initial') {
    setProgressState(
      `Preparing ${getScopeLabel(selectedScope.value)} synthetic SBOM preview from Dependency-Track data...`,
      62,
    )
    driftProgressTo(86)
  }

  try {
    const summary = await getVScorerSyntheticSbomSummary(projectName.value, selectedScope.value)
    if (syntheticSbomSummaryRequestId.value !== requestId) return
    syntheticSbomSummary.value = summary
    if (mode === 'initial') {
      setProgressState(
        `Prepared SBOM preview for ${summary.analyzed_versions.length} version${summary.analyzed_versions.length === 1 ? '' : 's'} with ${summary.component_count} components and ${summary.vulnerability_count} vulnerabilities.`,
        92,
      )
    }
  } catch (err: any) {
    if (syntheticSbomSummaryRequestId.value !== requestId) return
    syntheticSbomSummary.value = null
    syntheticSbomSummaryError.value = err?.response?.data?.detail || err?.message || 'Failed to prepare analysis SBOM summary.'
    if (mode === 'initial') {
      setProgressState(syntheticSbomSummaryError.value, 100)
    }
  } finally {
    if (syntheticSbomSummaryRequestId.value === requestId) {
      syntheticSbomSummaryLoading.value = false
    }
  }
}
const appendProgressLog = (message: string) => {
  if (!message) return
  if (progressLog.value[progressLog.value.length - 1] === message) return
  progressLog.value.push(message)
}

const setProgressState = (message: string, progress: number, writeLog = true) => {
  progressMessage.value = message
  progressValue.value = Math.max(progressValue.value, Math.min(progress, 100))
  if (writeLog) {
    appendProgressLog(message)
  }
}

const resetProgressState = (message: string) => {
  stopProgressTimer()
  clearStagedProgressTimers()
  progressMessage.value = message
  progressValue.value = 0
  progressLog.value = []
  appendProgressLog(message)
}

const driftProgressTo = (target: number, intervalMs = 400) => {
  stopProgressTimer()
  if (typeof window === 'undefined') return
  progressTimer.value = window.setInterval(() => {
    if (progressValue.value >= target) {
      stopProgressTimer()
      return
    }
    progressValue.value += progressValue.value < 30 ? 4 : 2
  }, intervalMs)
}

const scheduleProgressState = (delayMs: number, message: string, progress: number) => {
  if (typeof window === 'undefined') return
  const timerId = window.setTimeout(() => {
    setProgressState(message, progress)
  }, delayMs)
  stagedProgressTimers.push(timerId)
}

watch(() => progressLog.value.length, () => {
  nextTick(() => {
    if (logContainer.value) {
      logContainer.value.scrollTop = logContainer.value.scrollHeight
    }
  })
})

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
    return `${apiPrefix}/vscorer/sessions/${encodeURIComponent(result.value.session_id)}/outputs/${encodeURIComponent(filename)}`
}

const handleFileChange = (event: Event, target: 'threatmodel' | 'items' | 'config') => {
    const input = event.target as HTMLInputElement
    const file = input.files?.[0] || null
    if (target === 'threatmodel') threatModelFile.value = file
    if (target === 'items') itemsCsvFile.value = file
    if (target === 'config') configFile.value = file
    clearPreparedWizardState()
}

const applyAnalysisProgress = (progress: TMRescoreAnalysisProgress) => {
  stopProgressTimer()
  clearStagedProgressTimers()
  updateCachedProjectState(progress)
  progressMessage.value = progress.message || progressMessage.value
  progressValue.value = Math.max(progressValue.value, Math.min(progress.progress || 0, 100))
  if (progress.log && progress.log.length > 0) {
    progressLog.value = progress.log
  } else if (progress.message) {
    appendProgressLog(progress.message)
  }
}

const restoreCachedAnalysisState = async (state: TMRescoreProjectState) => {
  cachedProjectState.value = state
  selectedScope.value = state.scope
  enrich.value = Boolean(state.llm_enrichment?.enabled)
  if (state.llm_enrichment?.ollama_model) {
    ollamaModel.value = state.llm_enrichment.ollama_model
  }

  submitError.value = ''
  result.value = null
  applyAnalysisProgress(state)

  if (state.status === 'failed') {
    submitError.value = state.error || state.message || 'Threat-model analysis failed.'
    setProgressState(submitError.value, 100)
    submitting.value = false
    return
  }

  if (state.status === 'completed' && state.result) {
    result.value = state.result
    setProgressState(`Restored cached analysis result for session ${state.session_id}.`, 100)
    submitting.value = false
    return
  }

  if (state.status === 'prepared') {
    setProgressState(`Restored prepared VScorer wizard session ${state.session_id}.`, 100)
    submitting.value = false
    return
  }

  submitting.value = true
  appendProgressLog(`Restoring cached VScorer session ${state.session_id} after page reload...`)
  try {
    result.value = await resumeVScorerAnalysis(state.session_id, state, {
      onAnalysisProgress: (progress) => {
        applyAnalysisProgress(progress)
      },
    })
    setProgressState(`Analysis completed. ${result.value.rescored_count} of ${result.value.total_cves} CVEs were rescored.`, 100)
    if (typeof window !== 'undefined' && window.sessionStorage) {
      window.sessionStorage.setItem(refreshSignalKey.value, String(Date.now()))
      window.sessionStorage.setItem(legacyRefreshSignalKey.value, String(Date.now()))
    }
  } catch (err: any) {
    submitError.value = err?.response?.data?.detail || err?.message || 'Threat-model analysis failed.'
    setProgressState(submitError.value, 100)
  } finally {
    submitting.value = false
  }
}

const refreshCachedAnalysisState = async () => {
  if (!projectName.value || refreshingCachedState.value || submitting.value) return

  refreshingCachedState.value = true
  submitError.value = ''
  try {
    const latestState = await getVScorerProjectState(projectName.value)
    selectedScope.value = latestState.scope
    appendProgressLog(`Refreshed cached VScorer session ${latestState.session_id}.`)
    await loadSyntheticSbomSummary('refresh')
    await restoreCachedAnalysisState(latestState)
  } catch (err: any) {
    submitError.value = err?.response?.data?.detail || err?.message || 'Failed to refresh cached VScorer state.'
    appendProgressLog(submitError.value)
  } finally {
    refreshingCachedState.value = false
  }
}

const prepareWizardSession = async () => {
    if (!threatModelFile.value) {
        submitError.value = 'A threat model file is required to prepare a VScorer wizard session.'
        return
    }

    preparingWizard.value = true
    submitError.value = ''
    result.value = null
    clearPreparedWizardState()
    resetProgressState('Preparing VScorer wizard session...')
    setProgressState(`Building ${getScopeLabel(selectedScope.value)} analysis inventory from Dependency-Track data.`, 18)
    driftProgressTo(56)
    scheduleProgressState(900, 'Uploading threat model and synthetic SBOM to VScorer...', 64)
    scheduleProgressState(1800, 'Loading VScorer wizard context and catalogs...', 78)

    try {
        const preparedState = await prepareVScorerAnalysis(projectName.value, {
            scope: selectedScope.value,
            threatmodel: threatModelFile.value,
            itemsCsv: itemsCsvFile.value,
            config: configFile.value,
          }, {
            onUploadProgress: (event) => {
              const total = event.total || 0
              if (total <= 0) return
              const uploadPercent = Math.round((event.loaded / total) * 100)
              progressMessage.value = `Uploading VScorer wizard inputs... ${uploadPercent}%`
              progressValue.value = Math.max(progressValue.value, Math.min(70, 24 + Math.round(uploadPercent * 0.46)))
            },
        })
        stopProgressTimer()
        clearStagedProgressTimers()
        cachedProjectState.value = preparedState
        applyAnalysisProgress(preparedState)
        setProgressState(`Prepared VScorer wizard session ${preparedState.session_id}.`, 100)
    } catch (err: any) {
        stopProgressTimer()
        clearStagedProgressTimers()
        submitError.value = err?.response?.data?.detail || err?.message || 'Failed to prepare VScorer wizard session.'
        setProgressState(submitError.value, 100)
    } finally {
        preparingWizard.value = false
    }
}

const refreshWizardContext = async () => {
    const sessionId = cachedProjectState.value?.session_id
    if (!sessionId) return

    refreshingWizardContext.value = true
    submitError.value = ''
    appendProgressLog(`Refreshing VScorer wizard context for session ${sessionId}...`)
    try {
      const refreshedState = await refreshPreparedVScorerWizardContext(sessionId)
      updateCachedProjectState(refreshedState)
      applyAnalysisProgress(refreshedState)
      setProgressState('Refreshed VScorer wizard context.', Math.max(progressValue.value, refreshedState.progress || 25))
    } catch (err: any) {
      submitError.value = err?.response?.data?.detail || err?.message || 'Failed to refresh VScorer wizard context.'
      appendProgressLog(submitError.value)
    } finally {
      refreshingWizardContext.value = false
    }
}

const validateWizardInputs = async () => {
    const sessionId = cachedProjectState.value?.session_id
    if (!sessionId) return

    validatingWizardInputs.value = true
    submitError.value = ''
    appendProgressLog(`Validating VScorer wizard inputs for session ${sessionId}...`)
    try {
      const validatedState = await validatePreparedVScorerWizardInputs(sessionId)
      updateCachedProjectState(validatedState)
      applyAnalysisProgress(validatedState)
      setProgressState('Validated VScorer wizard inputs.', Math.max(progressValue.value, validatedState.progress || 28))
    } catch (err: any) {
      submitError.value = err?.response?.data?.detail || err?.message || 'Failed to validate VScorer wizard inputs.'
      appendProgressLog(submitError.value)
    } finally {
      validatingWizardInputs.value = false
    }
}

const loadWizardEditor = async () => {
    const sessionId = cachedProjectState.value?.session_id
    if (!sessionId) return

    loadingWizardEditor.value = true
    submitError.value = ''
    appendProgressLog(`Loading VScorer threat-model editor state for session ${sessionId}...`)
    try {
      const editorState = await getPreparedVScorerWizardEditor(sessionId)
      updateCachedProjectState(editorState)
      applyAnalysisProgress(editorState)
      setProgressState('Loaded VScorer threat-model editor state.', Math.max(progressValue.value, editorState.progress || 28))
    } catch (err: any) {
      submitError.value = err?.response?.data?.detail || err?.message || 'Failed to load VScorer threat-model editor state.'
      appendProgressLog(submitError.value)
    } finally {
      loadingWizardEditor.value = false
    }
}

const keepWizardEditorIssue = async (issue: VScorerThreatModelEditorIssue) => {
    const sessionId = cachedProjectState.value?.session_id
    const issueId = issue.issue_id
    if (!sessionId || !issueId) return

    applyingWizardIssueId.value = issueId
    submitError.value = ''
    appendProgressLog(`Marking VScorer editor issue ${issueId} as kept...`)
    try {
      const patchedState = await patchPreparedVScorerWizardEditor(sessionId, [{
        issue_id: issueId,
        action: 'keep',
        target_type: issue.target_type || null,
        target_id: issue.target_id || null,
        note: issue.note || 'Kept from DTVP.',
      }])
      updateCachedProjectState(patchedState)
      applyAnalysisProgress(patchedState)
      setProgressState('Updated VScorer threat-model editor state.', Math.max(progressValue.value, patchedState.progress || 30))
    } catch (err: any) {
      submitError.value = err?.response?.data?.detail || err?.message || 'Failed to update VScorer threat-model editor state.'
      appendProgressLog(submitError.value)
    } finally {
      applyingWizardIssueId.value = ''
    }
}

const loadContext = async () => {
    loading.value = true
    error.value = ''
  resetProgressState('Opening threat-model analysis page...')
  setProgressState('Loading project versions, VScorer settings, and enrichment options...', 18)
  driftProgressTo(46)
    try {
        context.value = await getVScorerContext(projectName.value)
        selectedScope.value = context.value.recommended_scope
    let cachedState: TMRescoreProjectState | null = null
    try {
      cachedState = await getVScorerProjectState(projectName.value)
      cachedProjectState.value = cachedState
      selectedScope.value = cachedState.scope
      setProgressState(
        `Found cached VScorer session ${cachedState.session_id}. Preparing the ${getScopeLabel(selectedScope.value)} analysis preview...`,
        52,
      )
    } catch (stateErr: any) {
      if (stateErr?.response?.status !== 404) {
        appendProgressLog(
          stateErr?.response?.data?.detail || stateErr?.message || 'Could not restore cached VScorer state.',
        )
      }
    }
    ollamaModel.value = context.value.llm_enrichment?.default_model || 'qwen2.5:7b'
    if (!cachedState) {
      setProgressState(`Loaded ${context.value.versions.length} project version${context.value.versions.length === 1 ? '' : 's'}. Preparing the ${getScopeLabel(selectedScope.value)} analysis preview...`, 52)
    }
    await loadSyntheticSbomSummary('initial')
    if (context.value.llm_enrichment?.warning) {
      appendProgressLog(context.value.llm_enrichment.warning)
    }
    if (!cachedState) {
      setProgressState('Threat-model analysis page is ready.', 100)
    }
    loading.value = false
    if (cachedState) {
      void restoreCachedAnalysisState(cachedState)
    }
    return
    } catch (err: any) {
    stopProgressTimer()
        error.value = err?.response?.data?.detail || err?.message || 'Failed to load threat-model analysis context.'
    setProgressState(error.value, 100)
    } finally {
    stopProgressTimer()
    clearStagedProgressTimers()
        if (!context.value || error.value) {
            loading.value = false
        }
    }
}

const submit = async () => {
    const preparedSession = preparedVScorerState.value
    if (!preparedSession && !threatModelFile.value) {
        submitError.value = 'A threat model file is required.'
        return
    }

    submitting.value = true
    submitError.value = ''
    result.value = null
    resetProgressState(preparedSession ? 'Starting prepared VScorer analysis...' : 'Preparing VScorer analysis request...')
    setProgressState(`Queued ${selectedScope.value === 'merged_versions' ? 'merged multi-version' : 'latest-only'} analysis scope.`, 10)
    if (enrich.value) {
      appendProgressLog(`LLM enrichment enabled with model ${ollamaModel.value}.`)
    }
    if (preparedSession) {
      setProgressState('Submitting prepared VScorer wizard session for analysis...', 28)
      driftProgressTo(70)
      scheduleProgressState(1200, 'Waiting for VScorer analysis results...', 84)
    } else {
      setProgressState('Uploading threat model and analysis inputs...', 18)
      driftProgressTo(58)
      scheduleProgressState(900, 'Building analysis inventory from Dependency-Track versions...', 62)
      scheduleProgressState(1800, 'Submitting synthetic SBOM and threat model to VScorer...', 72)
      scheduleProgressState(3200, 'Waiting for VScorer analysis results...', 84)
    }

    try {
        result.value = preparedSession
          ? await runPreparedVScorerAnalysis(preparedSession.session_id, {
            chainAnalysis: chainAnalysis.value,
            prioritize: prioritize.value,
            whatIf: whatIf.value,
            enrich: enrich.value,
            ollamaModel: ollamaModel.value,
          }, {
            onAnalysisProgress: (progress) => {
              applyAnalysisProgress(progress)
            },
          })
          : await runVScorerAnalysis(projectName.value, {
            scope: selectedScope.value,
            threatmodel: threatModelFile.value as File,
            itemsCsv: itemsCsvFile.value,
            config: configFile.value,
            chainAnalysis: chainAnalysis.value,
            prioritize: prioritize.value,
            whatIf: whatIf.value,
            enrich: enrich.value,
            ollamaModel: ollamaModel.value,
          }, {
            onUploadProgress: (event) => {
              const total = event.total || 0
              if (total <= 0) return
              const uploadPercent = Math.round((event.loaded / total) * 100)
              const mappedProgress = Math.min(58, 18 + Math.round(uploadPercent * 0.4))
              progressMessage.value = `Uploading threat model and analysis inputs... ${uploadPercent}%`
              progressValue.value = Math.max(progressValue.value, mappedProgress)
              if (uploadPercent === 100) {
                appendProgressLog('Upload complete. Waiting for VScorer processing...')
              }
            },
            onAnalysisProgress: (progress) => {
              applyAnalysisProgress(progress)
            },
        })
          stopProgressTimer()
          clearStagedProgressTimers()
          setProgressState(`Analysis completed. ${result.value.rescored_count} of ${result.value.total_cves} CVEs were rescored.`, 100)
          if (typeof window !== 'undefined' && window.sessionStorage) {
            window.sessionStorage.setItem(refreshSignalKey.value, String(Date.now()))
            window.sessionStorage.setItem(legacyRefreshSignalKey.value, String(Date.now()))
          }
    } catch (err: any) {
          stopProgressTimer()
          clearStagedProgressTimers()
        submitError.value = err?.response?.data?.detail || err?.message || 'Threat-model analysis failed.'
          setProgressState(submitError.value, 100)
    } finally {
        submitting.value = false
    }
}

onMounted(() => {
    loadContext()
})

watch(selectedScope, () => {
  if (!context.value?.enabled) return
  clearPreparedWizardState()
  void loadSyntheticSbomSummary()
})
      onBeforeUnmount(() => {
        stopProgressTimer()
        clearStagedProgressTimers()
      })
</script>

<template>
  <div class="w-full space-y-6">
    <div class="flex flex-col gap-3">
      <router-link :to="projectReturnUrl" class="text-blue-400 hover:text-blue-300 text-sm flex items-center gap-1.5 font-medium transition-colors">
        <ChevronLeft :size="16" />
        Back to Project View
      </router-link>

      <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
        <div>
          <h2 class="text-4xl font-extrabold tracking-tight text-white leading-none">VScorer Analysis for {{ projectName }}</h2>
          <p class="mt-2 text-sm text-gray-400 max-w-3xl">
            This runs the external VScorer service from DTVP. The recommended mode builds an analysis-only synthetic SBOM across all versions so historical vulnerabilities remain attached to the versioned components that actually carried them.
          </p>
        </div>
        <a
          v-if="context?.enabled && context.wizard_url && isReviewer"
          :href="context.wizard_url"
          target="_blank"
          rel="noopener noreferrer"
          class="inline-flex items-center justify-center gap-2 rounded-xl border border-blue-500/30 bg-blue-600/15 px-4 py-2 text-sm font-semibold text-blue-200 transition-colors hover:bg-blue-600/25"
          data-testid="open-vscorer-wizard"
        >
          <ExternalLink :size="16" />
          Open VScorer Wizard
        </a>
      </div>
    </div>

    <div v-if="loading" class="rounded-2xl border border-gray-800 bg-gray-900/80 p-6 text-gray-300 shadow-xl shadow-black/20">
      <div class="text-lg font-semibold text-white">{{ progressMessage }}</div>
      <div class="mt-4 h-3 w-full overflow-hidden rounded-full bg-gray-800">
        <div class="h-full rounded-full bg-blue-500 transition-all duration-300" :style="{ width: `${progressValue}%` }"></div>
      </div>
      <div class="mt-2 text-sm text-gray-400">{{ progressValue }}%</div>
      <div ref="logContainer" data-testid="tmrescore-progress-log" class="mt-4 max-h-48 overflow-y-auto rounded-xl border border-gray-700 bg-black/30 p-3 text-left">
        <div v-for="(entry, index) in progressLog" :key="`${index}-${entry}`" class="py-0.5 font-mono text-xs text-gray-300">
          <span class="select-none text-gray-600">{{ String(index + 1).padStart(2, '0') }}</span>
          {{ entry }}
        </div>
      </div>
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
            VScorer is not configured on the backend. Set <span class="font-mono">DTVP_TMRESCORE_URL</span> and reload the app.
          </div>

          <template v-else-if="!isReviewer">
            <div class="rounded-2xl border border-gray-800 bg-gray-900/80 p-6 shadow-xl shadow-black/20">
              <h3 class="text-lg font-bold text-white">Reviewer access required</h3>
              <p class="mt-3 text-sm text-gray-400">
                VScorer analysis controls are available only to users with the reviewer role.
              </p>
              <router-link
                :to="projectReturnUrl"
                class="mt-5 inline-flex items-center justify-center rounded-xl border border-gray-700 bg-gray-900 px-4 py-2 text-sm font-semibold text-gray-200 transition-colors hover:border-gray-600"
              >
                Return to project
              </router-link>
            </div>
          </template>

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
                  Adds LLM-based threat justification enrichment before analysis when the VScorer backend has Ollama configured.
                </div>
              </div>

              <div v-if="context.llm_enrichment?.warning" class="text-xs text-amber-200/80">
                {{ context.llm_enrichment.warning }}
              </div>
            </div>

            <div v-if="submitError" class="rounded-xl border border-red-800/40 bg-red-950/30 px-4 py-3 text-sm text-red-200">
              {{ submitError }}
            </div>

            <div class="rounded-2xl border border-gray-800 bg-gray-950/60 p-4">
              <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <div class="text-[11px] font-bold uppercase tracking-widest text-gray-500">Synthetic Analysis SBOM</div>
                  <div class="mt-1 text-sm text-gray-300">
                    Download the generated CycloneDX input for the currently selected scope before sending it to VScorer.
                  </div>
                </div>
                <a
                  :href="syntheticSbomDownloadUrl"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="inline-flex items-center justify-center rounded-xl border border-gray-700 bg-gray-900 px-4 py-2 text-sm font-semibold text-gray-200 transition-colors hover:border-gray-600"
                  data-testid="download-analysis-sbom"
                >
                  Download Analysis SBOM
                </a>
              </div>
              <div class="mt-4 grid gap-3 md:grid-cols-3">
                <div class="rounded-xl border border-gray-800 bg-black/20 px-4 py-3">
                  <div class="text-[11px] font-bold uppercase tracking-widest text-gray-500">Versions</div>
                  <div v-if="syntheticSbomSummary" data-testid="analysis-sbom-summary-versions" class="mt-1 text-lg font-semibold text-white">
                    {{ syntheticSbomSummary.analyzed_versions.length }}
                  </div>
                  <div v-else class="mt-1 text-sm text-gray-500">{{ syntheticSbomSummaryLoading ? 'Preparing...' : 'Unavailable' }}</div>
                </div>
                <div class="rounded-xl border border-gray-800 bg-black/20 px-4 py-3">
                  <div class="text-[11px] font-bold uppercase tracking-widest text-gray-500">Components</div>
                  <div v-if="syntheticSbomSummary" data-testid="analysis-sbom-summary-components" class="mt-1 text-lg font-semibold text-white">
                    {{ syntheticSbomSummary.component_count }}
                  </div>
                  <div v-else class="mt-1 text-sm text-gray-500">{{ syntheticSbomSummaryLoading ? 'Preparing...' : 'Unavailable' }}</div>
                </div>
                <div class="rounded-xl border border-gray-800 bg-black/20 px-4 py-3">
                  <div class="text-[11px] font-bold uppercase tracking-widest text-gray-500">Vulnerabilities</div>
                  <div v-if="syntheticSbomSummary" data-testid="analysis-sbom-summary-vulnerabilities" class="mt-1 text-lg font-semibold text-white">
                    {{ syntheticSbomSummary.vulnerability_count }}
                  </div>
                  <div v-else class="mt-1 text-sm text-gray-500">{{ syntheticSbomSummaryLoading ? 'Preparing...' : 'Unavailable' }}</div>
                </div>
              </div>
              <div v-if="syntheticSbomSummary" class="mt-3 text-sm text-gray-400" data-testid="analysis-sbom-summary-note">
                {{ syntheticSbomSummary.strategy_note }}
              </div>
              <div v-else-if="syntheticSbomSummaryError" class="mt-3 text-sm text-amber-200" data-testid="analysis-sbom-summary-error">
                {{ syntheticSbomSummaryError }}
              </div>
              <div v-if="cachedProjectState" class="mt-4 rounded-xl border border-gray-800 bg-black/20 p-4" data-testid="cached-analysis-state-meta">
                <div class="flex items-center justify-between gap-3">
                  <div class="text-[11px] font-bold uppercase tracking-widest text-gray-500">Cached VScorer State</div>
                  <button
                    type="button"
                    class="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs font-semibold text-gray-200 transition-colors hover:border-gray-600 disabled:cursor-not-allowed disabled:opacity-50"
                    :disabled="refreshingCachedState || submitting"
                    data-testid="refresh-cached-analysis-state"
                    @click="refreshCachedAnalysisState"
                  >
                    {{ refreshingCachedState ? 'Refreshing...' : 'Refresh Cached State' }}
                  </button>
                </div>
                <dl class="mt-3 grid gap-3 text-sm text-gray-300 md:grid-cols-2">
                  <div>
                    <dt class="text-gray-500">Session</dt>
                    <dd class="font-mono text-xs text-gray-200">{{ cachedProjectState.session_id }}</dd>
                  </div>
                  <div>
                    <dt class="text-gray-500">Scope</dt>
                    <dd>{{ getScopeLabel(cachedProjectState.scope) }}</dd>
                  </div>
                  <div>
                    <dt class="text-gray-500">Latest Version</dt>
                    <dd>{{ cachedProjectState.latest_version }}</dd>
                  </div>
                  <div>
                    <dt class="text-gray-500">Last Updated</dt>
                    <dd>
                      <div>{{ formatCachedTimestamp(cachedProjectState.updated_at) }}</div>
                      <div class="text-xs text-gray-500">{{ formatRelativeTimestamp(cachedProjectState.updated_at) }}</div>
                    </dd>
                  </div>
                  <div>
                    <dt class="text-gray-500">Created</dt>
                    <dd>
                      <div>{{ formatCachedTimestamp(cachedProjectState.created_at) }}</div>
                      <div class="text-xs text-gray-500">{{ formatRelativeTimestamp(cachedProjectState.created_at) }}</div>
                    </dd>
                  </div>
                  <div>
                    <dt class="text-gray-500">Completed</dt>
                    <dd>
                      <div>{{ formatCachedTimestamp(cachedProjectState.completed_at) }}</div>
                      <div class="text-xs text-gray-500">{{ formatRelativeTimestamp(cachedProjectState.completed_at) }}</div>
                    </dd>
                  </div>
                </dl>
              </div>
            </div>

            <div
              v-if="wizardContext || wizardCatalogs"
              class="rounded-2xl border border-blue-500/20 bg-blue-950/20 p-4"
              data-testid="vscorer-wizard-summary"
            >
              <div class="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <div class="text-[11px] font-bold uppercase tracking-widest text-blue-200/70">VScorer Wizard Context</div>
                  <div class="mt-1 text-sm text-blue-100">
                    Session {{ cachedProjectState?.session_id }}
                  </div>
                </div>
                <div class="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    class="inline-flex items-center justify-center gap-2 rounded-xl border border-blue-400/30 bg-blue-500/10 px-3 py-2 text-xs font-semibold text-blue-100 transition-colors hover:bg-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                    :disabled="refreshingWizardContext || preparingWizard || submitting"
                    data-testid="refresh-vscorer-wizard-context"
                    @click="refreshWizardContext"
                  >
                    <RefreshCw :size="14" />
                    {{ refreshingWizardContext ? 'Refreshing...' : 'Refresh Context' }}
                  </button>
                  <a
                    v-if="cachedProjectState?.wizard_url || context.wizard_url"
                    :href="cachedProjectState?.wizard_url || context.wizard_url || '#'"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="inline-flex items-center justify-center gap-2 rounded-xl border border-blue-400/30 bg-blue-500/10 px-3 py-2 text-xs font-semibold text-blue-100 transition-colors hover:bg-blue-500/20"
                    data-testid="open-prepared-vscorer-wizard"
                  >
                    <ExternalLink :size="14" />
                    Open Wizard
                  </a>
                </div>
              </div>
              <div class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                <div class="rounded-xl border border-blue-400/15 bg-black/20 px-4 py-3">
                  <div class="text-[10px] font-bold uppercase tracking-widest text-blue-200/60">Validation</div>
                  <div class="mt-1 text-sm text-blue-50" data-testid="vscorer-wizard-validation">
                    {{ wizardValidationSummary?.errors ?? 0 }} errors / {{ wizardValidationSummary?.warnings ?? 0 }} warnings
                  </div>
                </div>
                <div class="rounded-xl border border-blue-400/15 bg-black/20 px-4 py-3">
                  <div class="text-[10px] font-bold uppercase tracking-widest text-blue-200/60">Threat Model</div>
                  <div class="mt-1 text-sm text-blue-50" data-testid="vscorer-wizard-threatmodel">
                    {{ wizardThreatModelElementCount ?? 0 }} elements / {{ wizardThreatBoundaryCount ?? 0 }} boundaries
                  </div>
                </div>
                <div class="rounded-xl border border-blue-400/15 bg-black/20 px-4 py-3">
                  <div class="text-[10px] font-bold uppercase tracking-widest text-blue-200/60">Editor Issues</div>
                  <div class="mt-1 text-sm text-blue-50" data-testid="vscorer-wizard-editor-issues">
                    {{ wizardEditorIssueCount ?? 0 }}
                  </div>
                </div>
                <div class="rounded-xl border border-blue-400/15 bg-black/20 px-4 py-3">
                  <div class="text-[10px] font-bold uppercase tracking-widest text-blue-200/60">Rule Types</div>
                  <div class="mt-1 text-sm text-blue-50" data-testid="vscorer-wizard-rule-types">
                    {{ wizardRuleTypeCount ?? 0 }}
                  </div>
                </div>
                <div class="rounded-xl border border-blue-400/15 bg-black/20 px-4 py-3">
                  <div class="text-[10px] font-bold uppercase tracking-widest text-blue-200/60">ATT&CK Mitigations</div>
                  <div class="mt-1 text-sm text-blue-50" data-testid="vscorer-wizard-attack-mitigations">
                    {{ wizardAttackMitigationCount ?? 0 }}
                  </div>
                </div>
                <div class="rounded-xl border border-blue-400/15 bg-black/20 px-4 py-3">
                  <div class="text-[10px] font-bold uppercase tracking-widest text-blue-200/60">Status</div>
                  <div class="mt-1 text-sm text-blue-50" data-testid="vscorer-wizard-status">
                    {{ cachedProjectState?.status || 'prepared' }}
                  </div>
                </div>
              </div>
            </div>

            <div
              v-if="progressLog.length > 0"
              class="rounded-2xl border border-gray-800 bg-gray-950/60 p-4"
            >
              <div class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <div class="text-[11px] font-bold uppercase tracking-widest text-gray-500">Progress Log</div>
                  <div class="mt-1 text-sm text-gray-300">{{ progressMessage }}</div>
                </div>
                <div class="text-sm font-medium text-gray-400">{{ progressValue }}%</div>
              </div>
              <div class="mt-3 h-2 w-full overflow-hidden rounded-full bg-gray-800">
                <div class="h-full rounded-full bg-blue-500 transition-all duration-300" :style="{ width: `${progressValue}%` }"></div>
              </div>
              <div ref="logContainer" data-testid="tmrescore-progress-log" class="mt-4 max-h-52 overflow-y-auto rounded-xl border border-gray-700 bg-black/30 p-3 text-left">
                <div v-for="(entry, index) in progressLog" :key="`${index}-${entry}`" class="py-0.5 font-mono text-xs text-gray-300">
                  <span class="select-none text-gray-600">{{ String(index + 1).padStart(2, '0') }}</span>
                  {{ entry }}
                </div>
              </div>
            </div>

            <div class="flex items-center gap-4">
              <button
                type="button"
                :disabled="preparingWizard || submitting || !context.enabled"
                class="inline-flex items-center gap-2 rounded-xl border border-purple-400/30 bg-purple-500/10 px-4 py-2 text-sm font-semibold text-purple-100 transition-colors hover:bg-purple-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                data-testid="prepare-vscorer-wizard"
                @click="prepareWizardSession"
              >
                <WandSparkles :size="16" />
                {{ preparingWizard ? 'Preparing Wizard...' : 'Prepare VScorer Wizard' }}
              </button>

              <button
                type="submit"
                :disabled="submitting || preparingWizard || !context.enabled"
                class="inline-flex items-center gap-2 rounded-xl border border-blue-500/30 bg-blue-600/15 px-4 py-2 text-sm font-semibold text-blue-200 transition-colors hover:bg-blue-600/25 disabled:cursor-not-allowed disabled:opacity-50"
                data-testid="run-tmrescore-analysis"
              >
                <Upload :size="16" />
                {{ submitting ? 'Running Analysis...' : (preparedVScorerState ? 'Run Prepared VScorer Analysis' : 'Run VScorer Analysis') }}
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
