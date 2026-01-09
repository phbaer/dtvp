<script setup lang="ts">
import { ref } from 'vue'

const fileInput = ref<HTMLInputElement | null>(null)
const uploading = ref(false)
const message = ref('')
const error = ref('')

const handleFileUpload = async () => {
    if (!fileInput.value?.files?.length) return

    const file = fileInput.value.files[0]
    if (!file) return

    const formData = new FormData()
    formData.append('file', file)

    uploading.value = true
    message.value = ''
    error.value = ''

    try {
        const res = await fetch('/api/settings/mapping', {
            method: 'POST',
            body: formData
        })

        if (!res.ok) {
            const data = await res.json()
            throw new Error(data.message || 'Upload failed')
        }

        await res.json()
        message.value = 'Mapping file uploaded successfully!'
        // Reset input
        if (fileInput.value) fileInput.value.value = ''
    } catch (err: any) {
        error.value = err.message
    } finally {
        uploading.value = false
    }
}
</script>

<template>
  <div class="max-w-2xl mx-auto py-8">
    <div class="mb-6 flex items-center gap-4">
        <router-link to="/" class="text-blue-400 hover:underline">&larr; Back to Dashboard</router-link>
        <h2 class="text-3xl font-bold">Settings</h2>
    </div>

    <div class="bg-gray-800 rounded-lg p-6 border border-gray-700 shadow-lg">
        <h3 class="text-xl font-bold mb-4 text-gray-200">Team Mapping Configuration</h3>
        <p class="text-gray-400 mb-6 text-sm">
            Upload a JSON file containing the mapping between components and teams. 
            The file should be a JSON object where keys are component names and values are team names.
        </p>

        <div class="mb-6 bg-gray-900 p-4 rounded border border-gray-700">
            <h4 class="text-xs font-bold uppercase text-gray-500 mb-2">Example Format</h4>
            <pre class="text-xs text-green-400 font-mono overflow-x-auto">{
  "openssl": "Infra Team",
  "spring-web": "Backend Team"
}</pre>
        </div>
        
        <div class="space-y-4">
            <div>
                <label class="block text-sm font-semibold text-gray-300 mb-2">Upload Mapping File (JSON)</label>
                <input 
                    ref="fileInput"
                    type="file" 
                    accept=".json"
                    class="block w-full text-sm text-gray-400
                        file:mr-4 file:py-2 file:px-4
                        file:rounded-full file:border-0
                        file:text-sm file:font-semibold
                        file:bg-blue-900 file:text-blue-200
                        hover:file:bg-blue-800
                        cursor-pointer"
                />
            </div>

            <button 
                @click="handleFileUpload"
                :disabled="uploading"
                class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
                {{ uploading ? 'Uploading...' : 'Upload Mapping' }}
            </button>
            
            <div v-if="message" class="p-3 bg-green-900/30 border border-green-800 text-green-400 rounded">
                {{ message }}
            </div>
            
            <div v-if="error" class="p-3 bg-red-900/30 border border-red-800 text-red-400 rounded">
                {{ error }}
            </div>
        </div>
    </div>
  </div>
</template>
