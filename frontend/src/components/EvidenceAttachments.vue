<script setup lang="ts">
import { ref } from 'vue'
import { uploadCodeEvidenceAttachment, downloadCodeEvidenceMaterial } from '../lib/api'
import type { CodeEvidence, CodeEvidenceAttachment } from '../lib/api'
const props = defineProps<{ evidence: CodeEvidence; canUpload: boolean }>()
const emit = defineEmits<{ (e: 'changed'): void }>()
const busy = ref(false)
const error = ref('')
const description = ref('')
const download = async (attachment?: CodeEvidenceAttachment) => {
    error.value = ''
    try { await downloadCodeEvidenceMaterial(props.evidence.evidence_id, attachment) }
    catch { error.value = 'Download failed. Supporting material may be missing or corrupt.' }
}
const upload = async (event: Event) => {
    const input = event.target as HTMLInputElement
    const file = input.files?.[0]
    if (!file) return
    error.value = ''
    if (file.size < 1 || file.size > 10 * 1024 * 1024) { error.value = 'Choose a file containing 1 byte to 10 MiB.'; input.value = ''; return }
    busy.value = true
    try {
        const previous = [...(props.evidence.attachments || [])].reverse().find(item => item.filename === file.name)
        await uploadCodeEvidenceAttachment(props.evidence.evidence_id, file, description.value, previous?.attachment_id)
        description.value = ''
        emit('changed')
    } catch (err: any) { error.value = err?.response?.data?.detail || 'Upload failed. Retry to reconcile any uncertain upload.' }
    finally { busy.value = false; input.value = '' }
}
</script>
<template>
    <section class="space-y-2 rounded border border-gray-700 p-3" data-testid="evidence-attachments">
        <div class="flex items-center justify-between gap-2">
            <h6 class="text-xs font-bold text-gray-200">Supporting files</h6>
            <button type="button" class="text-xs text-cyan-300" @click="download()">Download evidence package</button>
        </div>
        <p class="text-[11px] text-gray-500">Includes a readable appendix; open appendix.html from the ZIP to print.</p>
        <p v-if="!evidence.attachments?.length" class="text-xs text-gray-500">No files attached.</p>
        <ul class="space-y-2">
            <li v-for="file in evidence.attachments || []" :key="file.attachment_id" class="text-xs text-gray-300">
                <button type="button" class="text-cyan-300 underline" @click="download(file)">{{ file.filename }} · version {{ file.version }}</button>
                <span> · {{ file.size }} bytes · {{ file.uploaded_by }} · {{ file.uploaded_at }}</span>
                <p v-if="file.description">{{ file.description }}</p>
                <p class="break-all font-mono text-[10px] text-gray-500">SHA-256 {{ file.sha256 }}</p>
            </li>
        </ul>
        <div v-if="canUpload" class="space-y-1">
            <label class="block text-xs text-gray-400">File description
                <input v-model="description" maxlength="2000" class="block w-full rounded border border-gray-700 bg-gray-950 p-1" />
            </label>
            <label class="block text-xs text-gray-400">Attach supporting file (10 MiB maximum)
                <input type="file" :disabled="busy" class="block text-xs" @change="upload" />
            </label>
            <p class="text-[11px] text-gray-500">Uploading the same filename adds a version. Earlier versions are preserved. Evidence allows 20 file versions and 50 MiB total.</p>
            <p v-if="busy" role="status" class="text-xs text-gray-400">Uploading…</p>
        </div>
        <p v-if="error" role="alert" class="text-xs text-red-300">{{ error }}</p>
    </section>
</template>
