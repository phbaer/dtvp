<script setup lang="ts">
import { ref } from 'vue'
import { codeAnalysisDownloadDiagnostics, type CodeAnalysisErrorDetails } from '../lib/api'
const props = defineProps<{ jobId?: string | null; errorDetails?: CodeAnalysisErrorDetails | null }>()
const busy = ref(false)
const message = ref('')
async function copyId() {
    try { await navigator.clipboard.writeText(props.jobId || ''); message.value = 'Job ID copied.' }
    catch { message.value = 'Copy unavailable. Select the job ID to copy it.' }
}
async function download() {
    if (!props.jobId || busy.value) return
    busy.value = true
    message.value = ''
    try {
        const blob = await codeAnalysisDownloadDiagnostics(props.jobId)
        const url = URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = `agentyzer-${props.jobId.replace(/[^a-zA-Z0-9_-]/g, '_')}-diagnostics.json`
        link.click()
        URL.revokeObjectURL(url)
        message.value = 'Debug download ready. Saved DTVP details are used if the analyzer job is unavailable.'
    } catch (error: any) {
        message.value = error?.response?.status === 404
            ? 'Job unavailable: it may have expired, been deleted, belong to another analyzer instance, or diagnostics may be unsupported. No saved DTVP failure details are available.'
            : 'Debug download unavailable. Retry later; any saved error details remain shown below.'
    } finally { busy.value = false }
}
</script>

<template>
    <div v-if="jobId" class="mt-2 space-y-1 text-xs text-gray-400" data-testid="job-diagnostics">
        <div class="flex flex-wrap items-center gap-2">
            <span>Analyzer job <code class="select-all text-gray-200">{{ jobId }}</code></span>
            <button type="button" class="text-cyan-300 hover:underline" @click.stop="copyId">Copy ID</button>
            <button type="button" class="text-cyan-300 hover:underline disabled:opacity-50" :disabled="busy" @click.stop="download">{{ busy ? 'Downloading…' : 'Download debug JSON' }}</button>
        </div>
        <details v-if="errorDetails">
            <summary class="cursor-pointer text-red-300">Saved error details: {{ errorDetails.code }}</summary>
            <div>Retryable: {{ errorDetails.retryable === true ? 'yes' : errorDetails.retryable === false ? 'no' : 'unknown' }}</div>
            <dl v-if="errorDetails.diagnostics">
                <template v-for="key in ['stage', 'exception_type', 'failure_category', 'http_status', 'timeout_seconds']" :key="key">
                    <div v-if="errorDetails.diagnostics[key] !== undefined"><dt class="inline">{{ key }}: </dt><dd class="inline">{{ errorDetails.diagnostics[key] }}</dd></div>
                </template>
            </dl>
        </details>
        <p v-if="message" role="status">{{ message }}</p>
    </div>
</template>
