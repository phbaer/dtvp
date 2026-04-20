<script setup lang="ts">
import { ref, onMounted, inject, watch } from 'vue'
import { X } from 'lucide-vue-next'
import { getRoles, uploadRoles, updateRoles, getTeamMapping, uploadTeamMapping, updateTeamMapping, getRescoreRules, uploadRescoreRules, updateRescoreRules } from '../lib/api'

const user = inject<any>('user', { role: 'ANALYST' })
const realRole = inject<any>('realRole', ref('ANALYST'))
const activeTab = ref('mapping')

// Mapping state
const fileInput = ref<HTMLInputElement | null>(null)
const uploading = ref(false)
const message = ref('')
const error = ref('')
const currentMapping = ref<Record<string, string | string[]> | null>(null)
const mappingJson = ref('')
const mappingRows = ref<Array<{ component: string; main: string; aliases: string }>>([])
const rawJsonError = ref('')
const savingMapping = ref(false)

const mappingToRows = (mapping: Record<string, string | string[]> | null) => {
    if (!mapping) return []
    return Object.entries(mapping)
        .sort(([a], [b]) => a.localeCompare(b, undefined, { sensitivity: 'base' }))
        .map(([component, value]) => {
            if (Array.isArray(value)) {
                return {
                    component,
                    main: value[0] || '',
                    aliases: value.slice(1).join(', '),
                }
            }
            return {
                component,
                main: value || '',
                aliases: '',
            }
        })
}

const rowsToMapping = () => {
    const mapping: Record<string, string | string[]> = {}
    mappingRows.value.forEach((row) => {
        if (!row.component.trim()) return
        const component = row.component.trim()
        const main = row.main.trim()
        const aliases = row.aliases
            .split(',')
            .map((alias) => alias.trim())
            .filter((alias) => alias)

        if (!main && aliases.length === 0) {
            return
        }

        if (aliases.length > 0) {
            mapping[component] = [main, ...aliases]
        } else {
            mapping[component] = main
        }
    })
    return mapping
}

const updateMappingJsonFromRows = () => {
    mappingJson.value = JSON.stringify(rowsToMapping(), null, 2)
}

const addMappingRow = () => {
    mappingRows.value.push({ component: '', main: '', aliases: '' })
}

const removeMappingRow = (index: number) => {
    mappingRows.value.splice(index, 1)
    updateMappingJsonFromRows()
}

// Roles state
const rolesFileInput = ref<HTMLInputElement | null>(null)
const uploadingRoles = ref(false)
const rolesMessage = ref('')
const rolesError = ref('')
const currentRoles = ref<Record<string, string> | null>(null)
const rolesJson = ref('')
const savingRoles = ref(false)

// Rescore Rules state
const rescoreFileInput = ref<HTMLInputElement | null>(null)
const uploadingRescore = ref(false)
const rescoreMessage = ref('')
const rescoreError = ref('')
const currentRescoreRules = ref<Record<string, any> | null>(null)
const rescoreJson = ref('')
const savingRescore = ref(false)

const loadMapping = async () => {
    try {
        currentMapping.value = await getTeamMapping()
        mappingRows.value = mappingToRows(currentMapping.value)
        mappingJson.value = JSON.stringify(currentMapping.value, null, 2)
    } catch (e) {
        console.error("Failed to load mapping", e)
    }
}

watch(mappingRows, () => {
    updateMappingJsonFromRows()
}, { deep: true })

watch(mappingJson, (value) => {
    try {
        const parsed = JSON.parse(value)
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            mappingRows.value = mappingToRows(parsed)
            rawJsonError.value = ''
        } else {
            rawJsonError.value = 'Team mapping JSON must be an object with component keys.'
        }
    } catch (e: any) {
        rawJsonError.value = e.message || 'Invalid JSON format'
    }
})

const loadRoles = async () => {
    if (realRole?.value !== 'REVIEWER') return
    try {
        currentRoles.value = await getRoles()
        rolesJson.value = JSON.stringify(currentRoles.value, null, 2)
    } catch (e) {
        console.error("Failed to load roles", e)
    }
}

const loadRescoreRules = async () => {
    if (realRole?.value !== 'REVIEWER') return
    try {
        currentRescoreRules.value = await getRescoreRules()
        rescoreJson.value = JSON.stringify(currentRescoreRules.value, null, 2)
    } catch (e) {
        console.error("Failed to load rescore rules", e)
    }
}

const handleFileUpload = async () => {
    if (!fileInput.value?.files?.length) return

    const file = fileInput.value.files[0]
    if (!file) return

    uploading.value = true
    message.value = ''
    error.value = ''

    try {
        const res = await uploadTeamMapping(file)
        if (res.status === 'success') {
             message.value = 'Mapping file uploaded successfully!'
             // Reset input
             if (fileInput.value) fileInput.value.value = ''
             await loadMapping()
        } else {
             throw new Error(res.message)
        }
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

        const res = await updateTeamMapping(parsed)
        
        if (res.status === 'success') {
            message.value = res.message || 'Mapping saved successfully!'
            await loadMapping()
        } else {
             throw new Error(res.message)
        }
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

        const res = await updateRoles(parsed)

        if (res.status === 'success') {
            rolesMessage.value = res.message || 'Roles saved successfully!'
            await loadRoles()
        } else {
            throw new Error(res.message)
        }
    } catch (err: any) {
        rolesError.value = err.message
    } finally {
        savingRoles.value = false
    }
}

const handleRescoreUpload = async () => {
    if (!rescoreFileInput.value?.files?.length) return

    const file = rescoreFileInput.value.files[0]
    if (!file) return

    uploadingRescore.value = true
    rescoreMessage.value = ''
    rescoreError.value = ''

    try {
        const res = await uploadRescoreRules(file)
        if (res.status === 'success') {
            rescoreMessage.value = res.message
            if (rescoreFileInput.value) rescoreFileInput.value.value = ''
            await loadRescoreRules()
        } else {
             throw new Error(res.message)
        }
    } catch (err: any) {
        rescoreError.value = err.message
    } finally {
        uploadingRescore.value = false
    }
}

const saveRescoreRules = async () => {
    savingRescore.value = true
    rescoreMessage.value = ''
    rescoreError.value = ''

    try {
        let parsed = {}
        try {
            parsed = JSON.parse(rescoreJson.value)
        } catch (e) {
            throw new Error("Invalid JSON format")
        }

        const res = await updateRescoreRules(parsed)

        if (res.status === 'success') {
            rescoreMessage.value = res.message || 'Rescore rules saved successfully!'
            await loadRescoreRules()
        } else {
            throw new Error(res.message)
        }
    } catch (err: any) {
        rescoreError.value = err.message
    } finally {
        savingRescore.value = false
    }
}

onMounted(() => {
    // Load data once we know the real permission of the user
    if (realRole?.value === 'REVIEWER') {
        loadMapping()
        loadRoles()
        loadRescoreRules()
    }
})

// In case user info loads after the component mounts, reload when role becomes REVIEWER
watch(realRole, (role) => {
    if (role === 'REVIEWER') {
        loadMapping()
        loadRoles()
        loadRescoreRules()
    }
})

// Reload roles if user role changes or tab becomes active
watch(() => activeTab.value, (newTab) => {
    if (newTab === 'roles' && realRole?.value === 'REVIEWER') {
        loadRoles()
    } else if (newTab === 'rescore' && realRole?.value === 'REVIEWER') {
        loadRescoreRules()
    }
})
</script>

<template>
  <div v-if="realRole === 'REVIEWER'" class="w-full">
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
        <button 
            v-if="user?.role === 'REVIEWER'"
            @click="activeTab = 'rescore'"
            :class="['px-4 py-2 text-sm font-medium border-b-2 transition-colors', activeTab === 'rescore' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-400 hover:text-gray-300']"
        >
            Rescore Rules
        </button>
    </div>

    <div v-if="activeTab === 'mapping'" class="bg-gray-800 rounded-lg p-6 border border-gray-700 shadow-lg">
        <h3 class="text-xl font-bold mb-4 text-gray-200">Team Mapping Configuration</h3>
        
        <div class="mb-6">
             <h4 class="text-xs font-bold uppercase text-gray-500 mb-2">Structured Editor</h4>
             <p class="text-gray-400 mb-2 text-xs">
                Configure component mappings using the table below. Aliases are only used to recognize legacy team tags and are not shown in the vulnerability header.
            </p>
            <div class="space-y-2 mb-4">
                <div v-for="(row, index) in mappingRows" :key="`${row.component}-${index}`" class="grid gap-2 md:grid-cols-[2fr_1fr_1fr_auto] items-end">
                    <div>
                        <label class="text-xs text-gray-400">Component</label>
                        <input
                            v-model="row.component"
                            placeholder="Component name"
                            class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-xs text-gray-100"
                        />
                    </div>
                    <div>
                        <label class="text-xs text-gray-400">Main team tag</label>
                        <input
                            v-model="row.main"
                            placeholder="Primary tag"
                            class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-xs text-gray-100"
                        />
                    </div>
                    <div>
                        <label class="text-xs text-gray-400">Aliases</label>
                        <input
                            v-model="row.aliases"
                            placeholder="alias1, alias2"
                            class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-xs text-gray-100"
                        />
                    </div>
                    <button
                        type="button"
                        @click="removeMappingRow(index)"
                        class="self-end flex h-10 min-w-[2.5rem] items-center justify-center rounded bg-red-600 hover:bg-red-700 text-white transition-colors"
                        title="Remove mapping row"
                    >
                        <X :size="14" />
                    </button>
                </div>
                <button
                    type="button"
                    @click="addMappingRow"
                    class="rounded bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold px-3 py-2 transition-colors"
                >
                    Add component mapping
                </button>
            </div>

             <h4 class="text-xs font-bold uppercase text-gray-500 mb-2">Raw JSON Editor</h4>
             <p class="text-gray-400 mb-2 text-xs">
                Edit the underlying mapping JSON directly, or use the structured editor above.
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
             <div v-if="rawJsonError" class="mt-2 p-3 bg-red-900/30 border border-red-800 text-red-400 rounded text-xs">
                 {{ rawJsonError }}
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

    <!-- Rescore Rules Tab -->
    <div v-if="activeTab === 'rescore' && user?.role === 'REVIEWER'" class="bg-gray-800 rounded-lg p-6 border border-gray-700 shadow-lg">
        <h3 class="text-xl font-bold mb-4 text-gray-200">CVSS Rescore Rules Configuration</h3>
        
        <div class="mb-6">
             <h4 class="text-xs font-bold uppercase text-gray-500 mb-2">Editor</h4>
             <p class="text-gray-400 mb-2 text-xs">
                Edit the JSON below directly or upload a file. This controls automated vector changes when analysis states trigger.
            </p>
             <div class="relative">
                <textarea 
                    v-model="rescoreJson"
                    class="w-full h-64 bg-gray-900 p-4 rounded border border-gray-700 font-mono text-blue-300 text-xs focus:ring-2 focus:ring-blue-500 focus:outline-none"
                    spellcheck="false"
                ></textarea>
                <div class="absolute bottom-4 right-4 flex gap-2">
                    <button 
                        @click="saveRescoreRules"
                        :disabled="savingRescore"
                        class="bg-green-600 hover:bg-green-700 text-white font-bold py-1 px-4 rounded text-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
                    >
                        {{ savingRescore ? 'Saving...' : 'Save Changes' }}
                    </button>
                </div>
             </div>
        </div>
        
        <div class="space-y-4 pt-6 border-t border-gray-700">
            <div>
                <label class="block text-sm font-semibold text-gray-300 mb-2">Or Upload Rescore Rules File (JSON)</label>
                <input 
                    ref="rescoreFileInput"
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
                @click="handleRescoreUpload"
                :disabled="uploadingRescore"
                class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
                {{ uploadingRescore ? 'Uploading...' : 'Upload Rules' }}
            </button>
            
            <div v-if="rescoreMessage" class="p-3 bg-green-900/30 border border-green-800 text-green-400 rounded">
                {{ rescoreMessage }}
            </div>
            
            <div v-if="rescoreError" class="p-3 bg-red-900/30 border border-red-800 text-red-400 rounded">
                {{ rescoreError }}
            </div>
        </div>
    </div>
  </div>
  <div v-else class="text-center py-20">
    <h2 class="text-2xl font-bold text-red-400 mb-4">Access Denied</h2>
    <p class="text-gray-400">You do not have permission to access this page.</p>
    <router-link to="/" class="text-blue-400 hover:text-blue-300 mt-4 inline-block">&larr; Back to Dashboard</router-link>
  </div>
</template>
