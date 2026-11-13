<script setup lang="ts">
import { ref } from 'vue'
import { codeAnalysisDownloadDiagnostics, codeAnalysisDownloadReport, codeAnalysisGetResult, type CodeAnalysisErrorDetails } from '../lib/api'
const props = defineProps<{ jobId?: string | null; errorDetails?: CodeAnalysisErrorDetails | null; status?: string; analysisRunId?: string | null; reportMarkdown?: string | null }>()
const busy = ref(false)
const message = ref('')
const reportBusy = ref(false)
async function downloadReport() {
    if (reportBusy.value) return
    reportBusy.value = true
    message.value = ''
    try {
        let report = props.reportMarkdown
        if (!report && props.analysisRunId) {
            try {
                const record = await codeAnalysisGetResult(props.analysisRunId)
                report = record.result?.assessment?.report_markdown
            } catch { /* Try the configured analyzer if saved evidence is unavailable. */ }
        }
        if (!report && !props.jobId) {
            message.value = 'This saved assessment has no Markdown report. Run a new analysis with an updated analyzer.'
            return
        }
        const blob = report ? new Blob([report], { type: 'text/markdown;charset=utf-8' })
            : await codeAnalysisDownloadReport(props.jobId!)
        const url = URL.createObjectURL(blob)
        try {
            const link = document.createElement('a')
            link.href = url
            link.download = `agentyzer-${(props.jobId || props.analysisRunId || 'report').replace(/[^a-zA-Z0-9_-]/g, '_')}-assessment.md`
            link.click()
        } finally { URL.revokeObjectURL(url) }
        message.value = 'Assessment report downloaded. It includes repository evidence; review before sharing or applying.'
    } catch (error: any) {
        message.value = [404, 409].includes(error?.response?.status)
            ? 'Report unavailable: the job may have expired, be incomplete, or predate Markdown reports. Run a new analysis with an updated analyzer.'
            : 'Assessment report download unavailable. Retry later.'
    } finally { reportBusy.value = false }
}

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
    <div v-if="jobId || analysisRunId || reportMarkdown" class="mt-2 space-y-1 text-xs text-gray-400" data-testid="job-diagnostics">
        <div class="flex flex-wrap items-center gap-2">
            <span v-if="jobId">Analyzer job <code class="select-all text-gray-200">{{ jobId }}</code></span>
            <button v-if="jobId" type="button" class="text-cyan-300 hover:underline" @click.stop="copyId">Copy ID</button>
            <button v-if="jobId" type="button" class="text-cyan-300 hover:underline disabled:opacity-50" :disabled="busy" @click.stop="download">{{ busy ? 'Downloading…' : 'Download debug JSON' }}</button>
            <button v-if="status === 'completed' || analysisRunId || reportMarkdown" type="button" data-testid="download-assessment-report" class="text-cyan-300 hover:underline disabled:opacity-50" :disabled="reportBusy" @click.stop="downloadReport">{{ reportBusy ? 'Downloading report…' : 'Download assessment (.md)' }}</button>
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
