<script setup lang="ts">
import { ref, onMounted, inject, watch } from 'vue'
import { getRoles, uploadRoles } from '../lib/api'

const user = inject<any>('user')
const activeTab = ref('mapping')

// Mapping state
const fileInput = ref<HTMLInputElement | null>(null)
const uploading = ref(false)
const message = ref('')
const error = ref('')
const currentMapping = ref<Record<string, string> | null>(null)
const mappingJson = ref('')
const savingMapping = ref(false)

// Roles state
const rolesFileInput = ref<HTMLInputElement | null>(null)
const uploadingRoles = ref(false)
const rolesMessage = ref('')
const rolesError = ref('')
const currentRoles = ref<Record<string, string> | null>(null)
const rolesJson = ref('')
const savingRoles = ref(false)

const loadMapping = async () => {
    try {
        const res = await fetch('/api/settings/mapping')
        if (res.ok) {
            currentMapping.value = await res.json()
            mappingJson.value = JSON.stringify(currentMapping.value, null, 2)
        }
    } catch (e) {
        console.error("Failed to load mapping", e)
    }
}

const loadRoles = async () => {
    if (user?.value?.role !== 'REVIEWER') return
    try {
        currentRoles.value = await getRoles()
        rolesJson.value = JSON.stringify(currentRoles.value, null, 2)
    } catch (e) {
        console.error("Failed to load roles", e)
    }
}

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
        await loadMapping()
    } catch (err: any) {
        error.value = err.message
    } finally {
        uploading.value = false
    }
}

const saveMapping = async () => {
    savingMapping.value = true
    message.value = ''
    error.value = ''

    try {
        let parsed = {}
        try {
            parsed = JSON.parse(mappingJson.value)
        } catch (e) {
            throw new Error("Invalid JSON format")
        }

        const res = await fetch('/api/settings/mapping', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(parsed)
        })

        if (!res.ok) {
            const data = await res.json()
            throw new Error(data.message || 'Save failed')
        }

        const data = await res.json()
        message.value = data.message || 'Mapping saved successfully!'
        await loadMapping()
    } catch (err: any) {
        error.value = err.message
    } finally {
        savingMapping.value = false
    }
}

const handleRolesUpload = async () => {
    if (!rolesFileInput.value?.files?.length) return

    const file = rolesFileInput.value.files[0]
    if (!file) return

    uploadingRoles.value = true
    rolesMessage.value = ''
    rolesError.value = ''

    try {
        const res = await uploadRoles(file)
        if (res.status === 'success') {
            rolesMessage.value = res.message
            if (rolesFileInput.value) rolesFileInput.value.value = ''
            await loadRoles()
        } else {
             throw new Error(res.message)
        }
    } catch (err: any) {
        rolesError.value = err.message
    } finally {
        uploadingRoles.value = false
    }
}

const saveRoles = async () => {
    savingRoles.value = true
    rolesMessage.value = ''
    rolesError.value = ''

    try {
        let parsed = {}
        try {
            parsed = JSON.parse(rolesJson.value)
        } catch (e) {
            throw new Error("Invalid JSON format")
        }

        const res = await fetch('/api/settings/roles', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(parsed)
        })

        if (!res.ok) {
            const data = await res.json()
            throw new Error(data.message || 'Save failed')
        }

        const data = await res.json()
        rolesMessage.value = data.message || 'Roles saved successfully!'
        await loadRoles()
    } catch (err: any) {
        rolesError.value = err.message
    } finally {
        savingRoles.value = false
    }
}

onMounted(() => {
    loadMapping()
    if (user?.value?.role === 'REVIEWER') {
        loadRoles()
    }
})

// Reload roles if user role changes or tab becomes active
watch(() => activeTab.value, (newTab) => {
    if (newTab === 'roles' && user?.value?.role === 'REVIEWER') {
        loadRoles()
    }
})
</script>

<template>
  <div class="mx-auto">
    <div class="mb-8 flex flex-col gap-2">
        <router-link to="/" class="text-blue-400 hover:text-blue-300 text-sm flex items-center gap-1">
            &larr; Back to Dashboard
        </router-link>
        <h2 class="text-3xl font-bold">Settings</h2>
    </div>

    <!-- Tabs -->
    <div class="flex border-b border-gray-700 mb-6">
        <button 
            @click="activeTab = 'mapping'"
            :class="['px-4 py-2 text-sm font-medium border-b-2 transition-colors', activeTab === 'mapping' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-400 hover:text-gray-300']"
        >
            Team Mapping
        </button>
        <button 
            v-if="user?.role === 'REVIEWER'"
            @click="activeTab = 'roles'"
            :class="['px-4 py-2 text-sm font-medium border-b-2 transition-colors', activeTab === 'roles' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-400 hover:text-gray-300']"
        >
            User Roles
        </button>
    </div>

    <div v-if="activeTab === 'mapping'" class="bg-gray-800 rounded-lg p-6 border border-gray-700 shadow-lg">
        <h3 class="text-xl font-bold mb-4 text-gray-200">Team Mapping Configuration</h3>
        
        <div class="mb-6">
             <h4 class="text-xs font-bold uppercase text-gray-500 mb-2">Editor</h4>
             <p class="text-gray-400 mb-2 text-xs">
                Edit the JSON below directly or upload a file.
            </p>
             <div class="relative">
                <textarea 
                    v-model="mappingJson"
                    class="w-full h-64 bg-gray-900 p-4 rounded border border-gray-700 font-mono text-blue-300 text-xs focus:ring-2 focus:ring-blue-500 focus:outline-none"
                    spellcheck="false"
                ></textarea>
                <div class="absolute bottom-4 right-4 flex gap-2">
                    <button 
                        @click="saveMapping"
                        :disabled="savingMapping"
                        class="bg-green-600 hover:bg-green-700 text-white font-bold py-1 px-4 rounded text-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
                    >
                        {{ savingMapping ? 'Saving...' : 'Save Changes' }}
                    </button>
                </div>
             </div>
        </div>

        <div class="space-y-4 pt-6 border-t border-gray-700">
            <div>
                <label class="block text-sm font-semibold text-gray-300 mb-2">Or Upload Mapping File (JSON)</label>
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

    <!-- User Roles Tab -->
    <div v-if="activeTab === 'roles' && user?.role === 'REVIEWER'" class="bg-gray-800 rounded-lg p-6 border border-gray-700 shadow-lg">
        <h3 class="text-xl font-bold mb-4 text-gray-200">User Roles Configuration</h3>
        
        <div class="mb-6">
             <h4 class="text-xs font-bold uppercase text-gray-500 mb-2">Editor</h4>
             <p class="text-gray-400 mb-2 text-xs">
                Edit the JSON below directly or upload a file. Allowed roles: <code>REVIEWER</code>, <code>ANALYST</code>.
            </p>
             <div class="relative">
                <textarea 
                    v-model="rolesJson"
                    class="w-full h-64 bg-gray-900 p-4 rounded border border-gray-700 font-mono text-blue-300 text-xs focus:ring-2 focus:ring-blue-500 focus:outline-none"
                    spellcheck="false"
                ></textarea>
                <div class="absolute bottom-4 right-4 flex gap-2">
                    <button 
                        @click="saveRoles"
                        :disabled="savingRoles"
                        class="bg-green-600 hover:bg-green-700 text-white font-bold py-1 px-4 rounded text-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
                    >
                        {{ savingRoles ? 'Saving...' : 'Save Changes' }}
                    </button>
                </div>
             </div>
        </div>
        
        <div class="space-y-4 pt-6 border-t border-gray-700">
            <div>
                <label class="block text-sm font-semibold text-gray-300 mb-2">Or Upload Roles File (JSON)</label>
                <input 
                    ref="rolesFileInput"
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
                @click="handleRolesUpload"
                :disabled="uploadingRoles"
                class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
                {{ uploadingRoles ? 'Uploading...' : 'Upload Roles' }}
            </button>
            
            <div v-if="rolesMessage" class="p-3 bg-green-900/30 border border-green-800 text-green-400 rounded">
                {{ rolesMessage }}
            </div>
            
            <div v-if="rolesError" class="p-3 bg-red-900/30 border border-red-800 text-red-400 rounded">
                {{ rolesError }}
            </div>
        </div>
    </div>
  </div>
</template>
