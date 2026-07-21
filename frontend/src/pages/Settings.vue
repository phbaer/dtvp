<script setup lang="ts">
import { computed, ref, onMounted, inject, watch } from 'vue'
import { Archive, Download, RefreshCw, Upload, X } from 'lucide-vue-next'
import {
    applyProjectArchiveImport,
    getProjectArchiveSnapshotDownloadUrl,
    getProjectArchiveTaskDownloadUrl,
    getPerformanceStatus,
    getRoles,
    getAutoAnalysisGuidance,
    getTeamGroups,
    listProjectArchiveSnapshots,
    startProjectArchiveExport,
    updateAutoAnalysisGuidance,
    updateRescoreRules,
    updateRoles,
    updateTeamGroups,
    updateTeamMapping,
    uploadAutoAnalysisGuidance,
    uploadProjectArchiveImport,
    uploadRescoreRules,
    uploadRoles,
    uploadTeamMapping,
    waitForProjectArchiveTask,
    getTeamMapping,
    getRescoreRules,
} from '../lib/api'
import type { TeamGroupConfig } from '../lib/api'
import type {
    BackendPerformanceStatus,
    ProjectArchiveApplyResult,
    ProjectArchivePreview,
    ProjectArchiveSnapshot,
    ProjectArchiveTask,
} from '../types'
import {
    DEFAULT_VULNERABILITY_BACKEND,
    VULNERABILITY_BACKEND_KEY,
    backendSupports,
} from '../lib/vulnerabilityBackend'

const user = inject<any>('user', { role: 'ANALYST' })
const realRole = inject<any>('realRole', ref('ANALYST'))
const vulnerabilityBackend = inject(
    VULNERABILITY_BACKEND_KEY,
    computed(() => DEFAULT_VULNERABILITY_BACKEND),
)
const canExportArchives = computed(() => backendSupports(
    vulnerabilityBackend.value,
    'finding_read',
    'sbom_read',
    'assessment_read',
))
const canPreviewArchiveImports = computed(() => backendSupports(
    vulnerabilityBackend.value,
    'project_search',
))
const canApplyArchiveImports = computed(() => backendSupports(
    vulnerabilityBackend.value,
    'assessment_write',
    'sbom_upload',
    'project_create',
))
const activeTab = ref('mapping')

// Runtime diagnostics state
const runtimeStatus = ref<BackendPerformanceStatus | null>(null)
const runtimeLoading = ref(false)
const runtimeError = ref('')

const runtimeExecutors = computed(() => {
    if (!runtimeStatus.value) return []
    return [
        { key: 'queries', label: 'Search queries', status: runtimeStatus.value.group_queries },
        { key: 'builds', label: 'Snapshot builds', status: runtimeStatus.value.group_builds },
        { key: 'postprocess', label: 'Snapshot post-processing', status: runtimeStatus.value.group_postprocessing },
        { key: 'details', label: 'Detail hydration', status: runtimeStatus.value.group_details },
    ]
})

const loadRuntimeStatus = async () => {
    if (realRole?.value !== 'REVIEWER') return
    runtimeLoading.value = true
    runtimeError.value = ''
    try {
        runtimeStatus.value = await getPerformanceStatus()
    } catch (err: any) {
        runtimeError.value = err?.response?.data?.detail || err?.message || 'Unable to load backend runtime information.'
    } finally {
        runtimeLoading.value = false
    }
}

// Mapping state
const fileInput = ref<HTMLInputElement | null>(null)
const uploading = ref(false)
const message = ref('')
const error = ref('')
const currentMapping = ref<Record<string, string | string[]> | null>(null)
const mappingJson = ref('')
interface MappingRow {
    id: string
    component: string
    main: string
    aliases: string
}

let nextMappingRowId = 1
let lastJsonFromRows = ''
let skipNextRowsSync = false
const mappingRows = ref<MappingRow[]>([])
const rawJsonError = ref('')
const savingMapping = ref(false)

const createMappingRow = (values: Omit<MappingRow, 'id'>): MappingRow => ({
    id: `mapping-row-${nextMappingRowId++}`,
    ...values,
})

const mappingToRows = (mapping: Record<string, string | string[]> | null) => {
    if (!mapping) return []
    return Object.entries(mapping)
        .sort(([a], [b]) => a.localeCompare(b, undefined, { sensitivity: 'base' }))
        .map(([component, value]) => {
            if (Array.isArray(value)) {
                return createMappingRow({
                    component,
                    main: value[0] || '',
                    aliases: value.slice(1).join(', '),
                })
            }
            return createMappingRow({
                component,
                main: value || '',
                aliases: '',
            })
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
    lastJsonFromRows = JSON.stringify(rowsToMapping(), null, 2)
    mappingJson.value = lastJsonFromRows
    rawJsonError.value = ''
}

const addMappingRow = () => {
    mappingRows.value.push(createMappingRow({ component: '', main: '', aliases: '' }))
}

const removeMappingRow = (index: number) => {
    mappingRows.value.splice(index, 1)
    updateMappingJsonFromRows()
}

// Team groups state
interface TeamGroupRow {
    id: string
    name: string
    teams: string[]
    groups: string[]
}

let nextTeamGroupRowId = 1
let lastTeamGroupsJsonFromRows = ''
let skipNextTeamGroupRowsSync = false
const teamGroupRows = ref<TeamGroupRow[]>([])
const teamGroupsJson = ref('')
const teamGroupsRawJsonError = ref('')
const teamGroupsMessage = ref('')
const teamGroupsError = ref('')
const savingTeamGroups = ref(false)

const createTeamGroupRow = (
    values: Omit<TeamGroupRow, 'id'>,
): TeamGroupRow => ({
    id: `team-group-row-${nextTeamGroupRowId++}`,
    ...values,
})

const teamGroupsToRows = (config: TeamGroupConfig | null): TeamGroupRow[] =>
    Object.entries(config || {})
        .sort(([left], [right]) => left.localeCompare(
            right,
            undefined,
            { sensitivity: 'base' },
        ))
        .map(([name, definition]) => createTeamGroupRow({
            name,
            teams: Array.isArray(definition?.teams) ? [...definition.teams] : [],
            groups: Array.isArray(definition?.groups) ? [...definition.groups] : [],
        }))

const uniqueTrimmed = (values: string[]): string[] => {
    const seen = new Set<string>()
    return values
        .map(value => value.trim())
        .filter((value) => {
            const normalized = value.toLowerCase()
            if (!value || seen.has(normalized)) return false
            seen.add(normalized)
            return true
        })
}

const rowsToTeamGroups = (): TeamGroupConfig => {
    const groups: TeamGroupConfig = {}
    teamGroupRows.value.forEach((row) => {
        const name = row.name.trim()
        if (!name) return
        groups[name] = {
            teams: uniqueTrimmed(row.teams),
            groups: uniqueTrimmed(row.groups),
        }
    })
    return groups
}

const updateTeamGroupsJsonFromRows = () => {
    lastTeamGroupsJsonFromRows = JSON.stringify(rowsToTeamGroups(), null, 2)
    teamGroupsJson.value = lastTeamGroupsJsonFromRows
    teamGroupsRawJsonError.value = ''
}

const addTeamGroupRow = () => {
    teamGroupRows.value.push(createTeamGroupRow({
        name: '',
        teams: [],
        groups: [],
    }))
}

const removeTeamGroupRow = (index: number) => {
    teamGroupRows.value.splice(index, 1)
    updateTeamGroupsJsonFromRows()
}

const canonicalTeams = computed(() => {
    const teams = new Map<string, string>()
    Object.values(currentMapping.value || {}).forEach((value) => {
        const primary = (Array.isArray(value) ? value[0] : value)?.trim()
        if (primary && !teams.has(primary.toLowerCase())) {
            teams.set(primary.toLowerCase(), primary)
        }
    })
    return [...teams.values()].sort((left, right) => left.localeCompare(
        right,
        undefined,
        { numeric: true, sensitivity: 'base' },
    ))
})

const nestedGroupOptions = (row: TeamGroupRow): string[] =>
    teamGroupRows.value
        .filter(candidate => candidate.id !== row.id && candidate.name.trim())
        .map(candidate => candidate.name.trim())
        .sort((left, right) => left.localeCompare(
            right,
            undefined,
            { numeric: true, sensitivity: 'base' },
        ))

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

// Config state
const autoGuidanceFileInput = ref<HTMLInputElement | null>(null)
const uploadingAutoGuidance = ref(false)
const autoGuidanceMessage = ref('')
const autoGuidanceError = ref('')
const currentAutoGuidance = ref<Record<string, any> | null>(null)
const autoGuidanceJson = ref('')
const savingAutoGuidance = ref(false)

// Project archive state
const archiveProjectName = ref('')
const archiveExportTask = ref<ProjectArchiveTask | null>(null)
const archiveExporting = ref(false)
const archiveExportError = ref('')
const archiveFileInput = ref<HTMLInputElement | null>(null)
const archiveImportTask = ref<ProjectArchiveTask | null>(null)
const archiveImporting = ref(false)
const archiveImportError = ref('')
const archiveApplying = ref(false)
const archiveApplyError = ref('')
const archiveSnapshots = ref<ProjectArchiveSnapshot[]>([])
const archiveSnapshotsLoading = ref(false)

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
    if (skipNextRowsSync) {
        skipNextRowsSync = false
        return
    }
    updateMappingJsonFromRows()
}, { deep: true })

watch(mappingJson, (value) => {
    if (value === lastJsonFromRows) {
        return
    }
    try {
        const parsed = JSON.parse(value)
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            skipNextRowsSync = true
            mappingRows.value = mappingToRows(parsed)
            rawJsonError.value = ''
        } else {
            rawJsonError.value = 'Team mapping JSON must be an object with component keys.'
        }
    } catch (e: any) {
        rawJsonError.value = e.message || 'Invalid JSON format'
    }
})

watch(teamGroupRows, () => {
    if (skipNextTeamGroupRowsSync) {
        skipNextTeamGroupRowsSync = false
        return
    }
    updateTeamGroupsJsonFromRows()
}, { deep: true })

watch(teamGroupsJson, (value) => {
    if (value === lastTeamGroupsJsonFromRows) return
    try {
        const parsed = JSON.parse(value)
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            skipNextTeamGroupRowsSync = true
            teamGroupRows.value = teamGroupsToRows(parsed as TeamGroupConfig)
            teamGroupsRawJsonError.value = ''
        } else {
            teamGroupsRawJsonError.value = 'Team groups JSON must be an object.'
        }
    } catch (e: any) {
        teamGroupsRawJsonError.value = e.message || 'Invalid JSON format'
    }
})

const loadTeamGroups = async () => {
    if (realRole?.value !== 'REVIEWER') return
    try {
        const config = await getTeamGroups()
        teamGroupRows.value = teamGroupsToRows(config)
        lastTeamGroupsJsonFromRows = JSON.stringify(config, null, 2)
        teamGroupsJson.value = lastTeamGroupsJsonFromRows
    } catch (e) {
        console.error('Failed to load team groups', e)
    }
}

const saveTeamGroups = async () => {
    savingTeamGroups.value = true
    teamGroupsMessage.value = ''
    teamGroupsError.value = ''
    try {
        const parsed = JSON.parse(teamGroupsJson.value)
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new Error('Team groups JSON must be an object')
        }
        const res = await updateTeamGroups(parsed as TeamGroupConfig)
        if (res.status !== 'success') throw new Error(res.message)
        teamGroupsMessage.value = res.message || 'Team groups saved successfully!'
        await loadTeamGroups()
    } catch (err: any) {
        teamGroupsError.value = err.message || 'Failed to save team groups'
    } finally {
        savingTeamGroups.value = false
    }
}

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

const loadAutoGuidance = async () => {
    if (realRole?.value !== 'REVIEWER') return
    try {
        currentAutoGuidance.value = await getAutoAnalysisGuidance()
        autoGuidanceJson.value = JSON.stringify(currentAutoGuidance.value, null, 2)
    } catch (e) {
        console.error("Failed to load auto-analysis guidance", e)
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

const handleAutoGuidanceUpload = async () => {
    if (!autoGuidanceFileInput.value?.files?.length) return

    const file = autoGuidanceFileInput.value.files[0]
    if (!file) return

    uploadingAutoGuidance.value = true
    autoGuidanceMessage.value = ''
    autoGuidanceError.value = ''

    try {
        const res = await uploadAutoAnalysisGuidance(file)
        if (res.status === 'success') {
            autoGuidanceMessage.value = res.message
            if (autoGuidanceFileInput.value) autoGuidanceFileInput.value.value = ''
            await loadAutoGuidance()
        } else {
             throw new Error(res.message)
        }
    } catch (err: any) {
        autoGuidanceError.value = err.message
    } finally {
        uploadingAutoGuidance.value = false
    }
}

const saveAutoGuidance = async () => {
    savingAutoGuidance.value = true
    autoGuidanceMessage.value = ''
    autoGuidanceError.value = ''

    try {
        let parsed = {}
        try {
            parsed = JSON.parse(autoGuidanceJson.value)
        } catch (e) {
            throw new Error("Invalid JSON format")
        }
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new Error("Auto-analysis guidance JSON must be an object")
        }

        const res = await updateAutoAnalysisGuidance(parsed)

        if (res.status === 'success') {
            autoGuidanceMessage.value = res.message || 'Auto-analysis guidance saved successfully!'
            await loadAutoGuidance()
        } else {
            throw new Error(res.message)
        }
    } catch (err: any) {
        autoGuidanceError.value = err.message
    } finally {
        savingAutoGuidance.value = false
    }
}

const updateArchiveTask = (status: ProjectArchiveTask) => {
    if (status.kind === 'export') {
        archiveExportTask.value = status
    } else {
        archiveImportTask.value = status
    }
}

const loadArchiveSnapshots = async () => {
    if (realRole?.value !== 'REVIEWER') return
    archiveSnapshotsLoading.value = true
    try {
        archiveSnapshots.value = await listProjectArchiveSnapshots()
    } catch (e) {
        console.error("Failed to load project archives", e)
    } finally {
        archiveSnapshotsLoading.value = false
    }
}

const exportProjectArchive = async () => {
    if (!archiveProjectName.value.trim()) {
        archiveExportError.value = 'Project name is required'
        return
    }
    archiveExporting.value = true
    archiveExportError.value = ''
    archiveExportTask.value = null
    try {
        const { task_id } = await startProjectArchiveExport({
            project_name: archiveProjectName.value.trim(),
            refresh: true,
        })
        archiveExportTask.value = await waitForProjectArchiveTask(task_id, updateArchiveTask)
        await loadArchiveSnapshots()
    } catch (err: any) {
        archiveExportError.value = err.message || 'Project archive export failed'
    } finally {
        archiveExporting.value = false
    }
}

const previewProjectArchive = async () => {
    const file = archiveFileInput.value?.files?.[0]
    if (!file) {
        archiveImportError.value = 'Choose a project archive first'
        return
    }
    archiveImporting.value = true
    archiveImportError.value = ''
    archiveApplyError.value = ''
    archiveImportTask.value = null
    try {
        const { task_id } = await uploadProjectArchiveImport(file)
        archiveImportTask.value = await waitForProjectArchiveTask(task_id, updateArchiveTask)
    } catch (err: any) {
        archiveImportError.value = err.message || 'Project archive preview failed'
    } finally {
        archiveImporting.value = false
    }
}

const applyArchive = async (mode: 'create_missing' | 'update') => {
    if (!archiveImportTask.value?.id) return
    archiveApplying.value = true
    archiveApplyError.value = ''
    try {
        const { task_id } = await applyProjectArchiveImport(archiveImportTask.value.id, mode)
        archiveImportTask.value = await waitForProjectArchiveTask(task_id, updateArchiveTask)
        await loadArchiveSnapshots()
    } catch (err: any) {
        archiveApplyError.value = err.message || 'Project archive import failed'
    } finally {
        archiveApplying.value = false
    }
}

const archivePreview = () => archiveImportTask.value?.result as ProjectArchivePreview | null
const archiveApplyResult = () => archiveImportTask.value?.result as ProjectArchiveApplyResult | null

onMounted(() => {
    // Load data once we know the real permission of the user
    if (realRole?.value === 'REVIEWER') {
        loadMapping()
        loadTeamGroups()
        loadRoles()
        loadRescoreRules()
        loadAutoGuidance()
        loadArchiveSnapshots()
    }
})

// In case user info loads after the component mounts, reload when role becomes REVIEWER
watch(realRole, (role) => {
    if (role === 'REVIEWER') {
        loadMapping()
        loadTeamGroups()
        loadRoles()
        loadRescoreRules()
        loadAutoGuidance()
        loadArchiveSnapshots()
    }
})

// Reload roles if user role changes or tab becomes active
watch(() => activeTab.value, (newTab) => {
    if (newTab === 'roles' && realRole?.value === 'REVIEWER') {
        loadRoles()
    } else if (newTab === 'team-groups' && realRole?.value === 'REVIEWER') {
        loadMapping()
        loadTeamGroups()
    } else if (newTab === 'rescore' && realRole?.value === 'REVIEWER') {
        loadRescoreRules()
    } else if (newTab === 'config' && realRole?.value === 'REVIEWER') {
        loadAutoGuidance()
    } else if (newTab === 'archives' && realRole?.value === 'REVIEWER') {
        loadArchiveSnapshots()
    } else if (newTab === 'runtime' && realRole?.value === 'REVIEWER') {
        loadRuntimeStatus()
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
    <div class="mb-6 flex flex-wrap border-b border-gray-700">
        <button 
            @click="activeTab = 'mapping'"
            :class="['px-4 py-2 text-sm font-medium border-b-2 transition-colors', activeTab === 'mapping' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-400 hover:text-gray-300']"
        >
            Team Mapping
        </button>
        <button
            v-if="user?.role === 'REVIEWER'"
            @click="activeTab = 'team-groups'"
            :class="['px-4 py-2 text-sm font-medium border-b-2 transition-colors', activeTab === 'team-groups' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-400 hover:text-gray-300']"
        >
            Team Groups
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
        <button
            v-if="user?.role === 'REVIEWER'"
            @click="activeTab = 'config'"
            :class="['px-4 py-2 text-sm font-medium border-b-2 transition-colors', activeTab === 'config' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-400 hover:text-gray-300']"
        >
            Config
        </button>
        <button
            v-if="user?.role === 'REVIEWER'"
            @click="activeTab = 'archives'"
            :class="['px-4 py-2 text-sm font-medium border-b-2 transition-colors inline-flex items-center gap-2', activeTab === 'archives' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-400 hover:text-gray-300']"
        >
            <Archive :size="14" />
            Archives
        </button>
        <button
            v-if="user?.role === 'REVIEWER'"
            @click="activeTab = 'runtime'"
            :class="['px-4 py-2 text-sm font-medium border-b-2 transition-colors', activeTab === 'runtime' ? 'border-cyan-500 text-cyan-300' : 'border-transparent text-gray-400 hover:text-gray-300']"
        >
            Runtime
        </button>
    </div>

    <div
        v-if="activeTab === 'runtime' && user?.role === 'REVIEWER'"
        class="space-y-6 rounded-lg border border-gray-700 bg-gray-800 p-6 shadow-lg"
        data-testid="backend-runtime-panel"
    >
        <div class="flex flex-wrap items-center justify-between gap-3">
            <div>
                <h3 class="text-xl font-bold text-gray-200">Backend Runtime</h3>
                <p class="mt-1 text-xs text-gray-400">
                    Live Python, worker-pool, retained-task, and cache-pressure information for this backend process.
                </p>
            </div>
            <button
                type="button"
                @click="loadRuntimeStatus"
                :disabled="runtimeLoading"
                class="inline-flex items-center gap-2 rounded border border-gray-600 px-3 py-2 text-xs font-bold text-gray-200 hover:bg-gray-700 disabled:opacity-50"
                data-testid="refresh-backend-runtime"
            >
                <RefreshCw :size="14" :class="runtimeLoading ? 'animate-spin' : ''" />
                Refresh
            </button>
        </div>

        <div v-if="runtimeLoading && !runtimeStatus" class="rounded border border-gray-700 bg-gray-900/40 p-4 text-sm text-gray-400">
            Loading backend runtime information…
        </div>
        <div v-if="runtimeError" class="rounded border border-red-800 bg-red-900/30 p-4 text-sm text-red-300">
            {{ runtimeError }}
        </div>

        <template v-if="runtimeStatus">
            <section class="rounded border border-gray-700 bg-gray-900/40 p-4">
                <div class="flex flex-wrap items-start justify-between gap-4">
                    <div>
                        <div class="text-xs font-bold uppercase tracking-wider text-gray-500">Python runtime</div>
                        <div class="mt-1 text-lg font-semibold text-gray-100" data-testid="backend-python-version">
                            {{ runtimeStatus.python.implementation }} {{ runtimeStatus.python.version }}
                        </div>
                    </div>
                    <div
                        :class="[
                            'rounded-full border px-3 py-1 text-xs font-bold',
                            runtimeStatus.python.free_threading_active
                                ? 'border-emerald-600/60 bg-emerald-900/30 text-emerald-300'
                                : 'border-amber-600/60 bg-amber-900/30 text-amber-300',
                        ]"
                        data-testid="backend-gil-state"
                    >
                        {{ runtimeStatus.python.free_threading_active
                            ? 'Free-threaded · GIL disabled'
                            : runtimeStatus.python.gil_enabled
                                ? 'GIL enabled fallback'
                                : 'Free-threading inactive' }}
                    </div>
                </div>
                <dl class="mt-4 grid gap-3 text-xs sm:grid-cols-3">
                    <div class="rounded bg-gray-950/50 p-3">
                        <dt class="text-gray-500">Free-threaded build</dt>
                        <dd class="mt-1 font-semibold text-gray-200">{{ runtimeStatus.python.free_threaded_build ? 'Yes' : 'No' }}</dd>
                    </div>
                    <div class="rounded bg-gray-950/50 p-3">
                        <dt class="text-gray-500">Free threading required</dt>
                        <dd class="mt-1 font-semibold text-gray-200">{{ runtimeStatus.python.free_threading_required ? 'Yes' : 'No' }}</dd>
                    </div>
                    <div class="rounded bg-gray-950/50 p-3">
                        <dt class="text-gray-500">GIL enabled</dt>
                        <dd class="mt-1 font-semibold text-gray-200">{{ runtimeStatus.python.gil_enabled === null ? 'Unknown' : runtimeStatus.python.gil_enabled ? 'Yes' : 'No' }}</dd>
                    </div>
                </dl>
            </section>

            <section>
                <h4 class="mb-3 text-xs font-bold uppercase tracking-wider text-gray-500">Worker capacity</h4>
                <div class="grid gap-3 lg:grid-cols-3">
                    <article
                        v-for="executor in runtimeExecutors"
                        :key="executor.key"
                        class="rounded border border-gray-700 bg-gray-900/40 p-4"
                        :data-testid="`backend-executor-${executor.key}`"
                    >
                        <div class="font-semibold text-gray-200">{{ executor.label }}</div>
                        <div class="mt-3 grid grid-cols-3 gap-2 text-center text-xs">
                            <div class="rounded bg-gray-950/50 p-2">
                                <div class="text-lg font-bold text-cyan-300">{{ executor.status.active }}</div>
                                <div class="text-gray-500">Active</div>
                            </div>
                            <div class="rounded bg-gray-950/50 p-2">
                                <div class="text-lg font-bold text-amber-300">{{ executor.status.queued }}</div>
                                <div class="text-gray-500">Queued</div>
                            </div>
                            <div class="rounded bg-gray-950/50 p-2">
                                <div class="text-lg font-bold text-gray-200">{{ executor.status.capacity }}</div>
                                <div class="text-gray-500">Capacity</div>
                            </div>
                        </div>
                        <div class="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-gray-500">
                            <span>Workers {{ executor.status.workers }}</span>
                            <span>Peak {{ executor.status.max_outstanding }}</span>
                            <span>Failed {{ executor.status.failed_total }}</span>
                            <span v-if="executor.status.rejected_total !== undefined">Rejected {{ executor.status.rejected_total }}</span>
                        </div>
                    </article>
                </div>
            </section>

            <section class="grid gap-3 lg:grid-cols-2">
                <article class="rounded border border-gray-700 bg-gray-900/40 p-4">
                    <h4 class="text-xs font-bold uppercase tracking-wider text-gray-500">Retained grouped tasks</h4>
                    <div class="mt-2 text-3xl font-bold text-gray-100">{{ runtimeStatus.grouped_tasks.total }}</div>
                    <div class="mt-3 flex flex-wrap gap-2 text-xs">
                        <span
                            v-for="(count, status) in runtimeStatus.grouped_tasks.by_status"
                            :key="status"
                            class="rounded-full border border-gray-700 bg-gray-950/50 px-3 py-1 text-gray-300"
                        >
                            {{ status }} {{ count }}
                        </span>
                    </div>
                </article>
                <article class="rounded border border-gray-700 bg-gray-900/40 p-4">
                    <h4 class="text-xs font-bold uppercase tracking-wider text-gray-500">Process cache</h4>
                    <dl class="mt-3 grid grid-cols-2 gap-3 text-xs">
                        <div><dt class="text-gray-500">Memory entries</dt><dd class="font-semibold text-gray-200">{{ runtimeStatus.cache.memory_entries }} / {{ runtimeStatus.cache.memory_entry_limit }}</dd></div>
                        <div><dt class="text-gray-500">Active projects</dt><dd class="font-semibold text-gray-200">{{ runtimeStatus.cache.active_projects }} / {{ runtimeStatus.cache.active_project_limit }}</dd></div>
                        <div><dt class="text-gray-500">Named queries</dt><dd class="font-semibold text-gray-200">{{ runtimeStatus.cache.named_project_queries }} / {{ runtimeStatus.cache.named_project_query_limit }}</dd></div>
                        <div><dt class="text-gray-500">Dirty / errors</dt><dd class="font-semibold text-gray-200">{{ runtimeStatus.cache.dirty_entries }} / {{ runtimeStatus.cache.write_errors }}</dd></div>
                    </dl>
                </article>
            </section>
        </template>
    </div>

    <div v-if="activeTab === 'mapping'" class="bg-gray-800 rounded-lg p-6 border border-gray-700 shadow-lg">
        <h3 class="text-xl font-bold mb-4 text-gray-200">Team Mapping Configuration</h3>
        
        <div class="mb-6">
             <h4 class="text-xs font-bold uppercase text-gray-500 mb-2">Structured Editor</h4>
             <p class="text-gray-400 mb-2 text-xs">
                Configure component mappings using deterministic SBOM selectors: name, group:name, purl::pkg:type/namespace/name for package URLs, cs::name for case-sensitive matches, nogroup::name for known components without a group, and cs,nogroup::name for both. Single-colon keys such as cs:name and nogroup:name are normal group:name selectors. More specific selectors win. Aliases are only used to recognize legacy team tags and are not shown in the vulnerability header.
            </p>
            <div class="space-y-2 mb-4">
                <div v-for="(row, index) in mappingRows" :key="row.id" class="grid gap-2 md:grid-cols-[2fr_1fr_1fr_auto] items-end">
                    <div>
                        <label class="text-xs text-gray-400">Component key</label>
                        <input
                            v-model="row.component"
                            :data-testid="`team-mapping-component-${row.id}`"
                            placeholder="name, group:name, purl::pkg:type/namespace/name"
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

    <div
        v-if="activeTab === 'team-groups' && user?.role === 'REVIEWER'"
        class="bg-gray-800 rounded-lg p-6 border border-gray-700 shadow-lg"
    >
        <h3 class="text-xl font-bold mb-2 text-gray-200">Team Group Configuration</h3>
        <p class="text-gray-400 mb-6 text-xs">
            Build reporting groups from canonical teams in Team Mapping. A group can share a team's name:
            for example, group <code>Core-MUC</code> can contain teams <code>Core-MUC</code> and
            <code>3rd Party</code>. Nested groups are expanded for statistics, and each vulnerability is
            counted only once per group.
        </p>

        <div class="space-y-4 mb-6" data-testid="team-group-editor">
            <div
                v-for="(row, index) in teamGroupRows"
                :key="row.id"
                class="grid gap-3 rounded-lg border border-gray-700 bg-gray-900/40 p-4 lg:grid-cols-[1fr_1.2fr_1.2fr_auto]"
            >
                <div>
                    <label class="mb-1 block text-xs text-gray-400">Group name</label>
                    <input
                        v-model="row.name"
                        :data-testid="`team-group-name-${row.id}`"
                        placeholder="Core-MUC"
                        class="w-full rounded border border-gray-700 bg-gray-900 px-3 py-2 text-xs text-gray-100"
                    />
                </div>
                <div>
                    <label class="mb-1 block text-xs text-gray-400">Direct teams</label>
                    <select
                        v-model="row.teams"
                        multiple
                        :data-testid="`team-group-teams-${row.id}`"
                        class="h-28 w-full rounded border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-100"
                    >
                        <option v-for="team in canonicalTeams" :key="team" :value="team">
                            {{ team }}
                        </option>
                    </select>
                    <p class="mt-1 text-[10px] text-gray-500">Use Ctrl/⌘ to select multiple teams.</p>
                </div>
                <div>
                    <label class="mb-1 block text-xs text-gray-400">Nested groups</label>
                    <select
                        v-model="row.groups"
                        multiple
                        :data-testid="`team-group-groups-${row.id}`"
                        class="h-28 w-full rounded border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-100"
                    >
                        <option
                            v-for="group in nestedGroupOptions(row)"
                            :key="group"
                            :value="group"
                        >
                            {{ group }}
                        </option>
                    </select>
                    <p class="mt-1 text-[10px] text-gray-500">Groups may contain other groups.</p>
                </div>
                <button
                    type="button"
                    @click="removeTeamGroupRow(index)"
                    class="flex h-10 min-w-[2.5rem] items-center justify-center self-start rounded bg-red-600 text-white transition-colors hover:bg-red-700"
                    title="Remove team group"
                >
                    <X :size="14" />
                </button>
            </div>
            <button
                type="button"
                @click="addTeamGroupRow"
                class="rounded bg-blue-600 px-3 py-2 text-xs font-semibold text-white transition-colors hover:bg-blue-700"
            >
                Add team group
            </button>
        </div>

        <h4 class="text-xs font-bold uppercase text-gray-500 mb-2">Raw JSON Editor</h4>
        <p class="text-gray-400 mb-2 text-xs">
            Use explicit <code>teams</code> and <code>groups</code> arrays to distinguish a team from
            a nested group with the same name.
        </p>
        <div class="relative">
            <textarea
                v-model="teamGroupsJson"
                data-testid="team-groups-json"
                class="w-full h-64 bg-gray-900 p-4 rounded border border-gray-700 font-mono text-blue-300 text-xs focus:ring-2 focus:ring-blue-500 focus:outline-none"
                spellcheck="false"
            ></textarea>
            <div class="absolute bottom-4 right-4 flex gap-2">
                <button
                    @click="saveTeamGroups"
                    :disabled="savingTeamGroups || Boolean(teamGroupsRawJsonError)"
                    data-testid="save-team-groups"
                    class="bg-green-600 hover:bg-green-700 text-white font-bold py-1 px-4 rounded text-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
                >
                    {{ savingTeamGroups ? 'Saving...' : 'Save Changes' }}
                </button>
            </div>
        </div>
        <div
            v-if="teamGroupsRawJsonError"
            class="mt-2 p-3 bg-red-900/30 border border-red-800 text-red-400 rounded text-xs"
        >
            {{ teamGroupsRawJsonError }}
        </div>
        <div
            v-if="teamGroupsMessage"
            class="mt-3 p-3 bg-green-900/30 border border-green-800 text-green-400 rounded"
        >
            {{ teamGroupsMessage }}
        </div>
        <div
            v-if="teamGroupsError"
            class="mt-3 p-3 bg-red-900/30 border border-red-800 text-red-400 rounded"
        >
            {{ teamGroupsError }}
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
                Define each version's base, modified, and requirement relationships in <code>metric_rules</code>;
                transition actions are evaluated through those relationships by both individual and bulk rule sync.
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

    <!-- Config Tab -->
    <div v-if="activeTab === 'config' && user?.role === 'REVIEWER'" class="bg-gray-800 rounded-lg p-6 border border-gray-700 shadow-lg">
        <h3 class="text-xl font-bold mb-4 text-gray-200">Configuration</h3>

        <section class="space-y-4">
            <div>
                <h4 class="text-xs font-bold uppercase text-gray-500 mb-2">Code Analysis Guidance</h4>
                <p class="text-gray-400 mb-2 text-xs">
                    Configure static prompt additions for automatic scans and manual vulnerability-card analyses. Use a default entry for all scan targets and component-specific entries under <code>components</code>; component keys use the same name, group:name, and purl:: selectors as team mapping.
                </p>
                <pre class="mb-3 overflow-x-auto rounded border border-gray-700 bg-gray-950 p-3 text-xs text-gray-400">{
  "default": "Always verify runtime reachability against code evidence.",
  "components": {
    "keycloak-extension": {
      "guidance": [
        "This component extends Keycloak.",
        "If the extension is not affected, still consider whether upstream Keycloak itself is vulnerable."
      ]
    }
  }
}</pre>
                <div class="relative">
                    <textarea
                        v-model="autoGuidanceJson"
                        class="w-full h-80 bg-gray-900 p-4 rounded border border-gray-700 font-mono text-blue-300 text-xs focus:ring-2 focus:ring-blue-500 focus:outline-none"
                        spellcheck="false"
                    ></textarea>
                    <div class="absolute bottom-4 right-4 flex gap-2">
                        <button
                            @click="saveAutoGuidance"
                            :disabled="savingAutoGuidance"
                            class="bg-green-600 hover:bg-green-700 text-white font-bold py-1 px-4 rounded text-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
                        >
                            {{ savingAutoGuidance ? 'Saving...' : 'Save Changes' }}
                        </button>
                    </div>
                </div>
            </div>

            <div class="space-y-4 pt-6 border-t border-gray-700">
                <div>
                    <label class="block text-sm font-semibold text-gray-300 mb-2">Or Upload Guidance File (JSON)</label>
                    <input
                        ref="autoGuidanceFileInput"
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
                    @click="handleAutoGuidanceUpload"
                    :disabled="uploadingAutoGuidance"
                    class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                    {{ uploadingAutoGuidance ? 'Uploading...' : 'Upload Guidance' }}
                </button>

                <div v-if="autoGuidanceMessage" class="p-3 bg-green-900/30 border border-green-800 text-green-400 rounded">
                    {{ autoGuidanceMessage }}
                </div>

                <div v-if="autoGuidanceError" class="p-3 bg-red-900/30 border border-red-800 text-red-400 rounded">
                    {{ autoGuidanceError }}
                </div>
            </div>
        </section>
    </div>

    <!-- Project Archives Tab -->
    <div v-if="activeTab === 'archives' && user?.role === 'REVIEWER'" class="bg-gray-800 rounded-lg p-6 border border-gray-700 shadow-lg">
        <h3 class="text-xl font-bold mb-6 text-gray-200">Project Archives</h3>

        <div class="grid gap-6 xl:grid-cols-2">
            <section v-if="canExportArchives" class="space-y-4 rounded border border-gray-700 bg-gray-900/40 p-4">
                <h4 class="text-xs font-bold uppercase text-gray-500">Export</h4>
                <div>
                    <label class="block text-xs font-semibold text-gray-400 mb-2">Project name</label>
                    <input
                        v-model="archiveProjectName"
                        type="text"
                        class="w-full rounded border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100"
                        placeholder="Vulnerable Project"
                    />
                </div>
                <button
                    type="button"
                    @click="exportProjectArchive"
                    :disabled="archiveExporting"
                    class="inline-flex items-center gap-2 rounded bg-blue-600 px-4 py-2 text-sm font-bold text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
                >
                    <Archive :size="16" />
                    {{ archiveExporting ? 'Exporting...' : 'Export Archive' }}
                </button>
                <div v-if="archiveExportTask" class="rounded border border-gray-700 bg-black/20 p-3 text-sm text-gray-300">
                    <div class="flex items-center justify-between gap-3">
                        <span>{{ archiveExportTask.message }}</span>
                        <span class="text-xs font-bold text-blue-300">{{ archiveExportTask.progress }}%</span>
                    </div>
                    <div class="mt-2 h-2 overflow-hidden rounded bg-gray-950">
                        <div class="h-full bg-blue-500 transition-all" :style="{ width: `${archiveExportTask.progress}%` }"></div>
                    </div>
                    <a
                        v-if="archiveExportTask.status === 'completed'"
                        :href="getProjectArchiveTaskDownloadUrl(archiveExportTask.id)"
                        class="mt-3 inline-flex items-center gap-2 rounded bg-green-700 px-3 py-2 text-xs font-bold text-white hover:bg-green-600"
                    >
                        <Download :size="14" />
                        Download
                    </a>
                </div>
                <div v-if="archiveExportError" class="rounded border border-red-800 bg-red-900/30 p-3 text-sm text-red-300">
                    {{ archiveExportError }}
                </div>
            </section>

            <section v-if="canPreviewArchiveImports" class="space-y-4 rounded border border-gray-700 bg-gray-900/40 p-4">
                <h4 class="text-xs font-bold uppercase text-gray-500">Import</h4>
                <input
                    ref="archiveFileInput"
                    type="file"
                    accept=".zip"
                    class="block w-full text-sm text-gray-400
                        file:mr-4 file:rounded-full file:border-0
                        file:bg-blue-900 file:px-4 file:py-2
                        file:text-sm file:font-semibold file:text-blue-200
                        hover:file:bg-blue-800"
                />
                <div class="flex flex-wrap gap-2">
                    <button
                        type="button"
                        @click="previewProjectArchive"
                        :disabled="archiveImporting || archiveApplying"
                        class="inline-flex items-center gap-2 rounded bg-blue-600 px-4 py-2 text-sm font-bold text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                        <Upload :size="16" />
                        {{ archiveImporting ? 'Previewing...' : 'Upload Preview' }}
                    </button>
                    <button
                        v-if="canApplyArchiveImports && archiveImportTask?.status === 'completed' && archiveImportTask.kind === 'import_preview'"
                        type="button"
                        @click="applyArchive('create_missing')"
                        :disabled="archiveApplying"
                        class="rounded bg-green-700 px-4 py-2 text-sm font-bold text-white transition-colors hover:bg-green-600 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                        Create Missing
                    </button>
                    <button
                        v-if="canApplyArchiveImports && archiveImportTask?.status === 'completed' && archiveImportTask.kind === 'import_preview'"
                        type="button"
                        @click="applyArchive('update')"
                        :disabled="archiveApplying"
                        class="rounded bg-amber-600 px-4 py-2 text-sm font-bold text-white transition-colors hover:bg-amber-500 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                        Update Existing
                    </button>
                </div>
                <div v-if="archiveImportTask" class="rounded border border-gray-700 bg-black/20 p-3 text-sm text-gray-300">
                    <div class="flex items-center justify-between gap-3">
                        <span>{{ archiveImportTask.message }}</span>
                        <span class="text-xs font-bold text-blue-300">{{ archiveImportTask.progress }}%</span>
                    </div>
                    <div class="mt-2 h-2 overflow-hidden rounded bg-gray-950">
                        <div class="h-full bg-blue-500 transition-all" :style="{ width: `${archiveImportTask.progress}%` }"></div>
                    </div>
                </div>
                <div v-if="archiveImportTask?.kind === 'import_preview' && archivePreview()" class="overflow-x-auto rounded border border-gray-700">
                    <table class="min-w-full divide-y divide-gray-700 text-left text-xs">
                        <thead class="bg-gray-950/60 text-gray-400">
                            <tr>
                                <th class="px-3 py-2">Version</th>
                                <th class="px-3 py-2">Target</th>
                                <th class="px-3 py-2">Findings</th>
                                <th class="px-3 py-2">Assessments</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-700 text-gray-200">
                            <tr v-for="version in archivePreview()?.versions || []" :key="version.source_uuid">
                                <td class="px-3 py-2 font-semibold">{{ version.version || '(empty)' }}</td>
                                <td class="px-3 py-2">{{ version.target_exists ? 'Exists' : 'Missing' }}</td>
                                <td class="px-3 py-2">{{ version.finding_count }}</td>
                                <td class="px-3 py-2">{{ version.restorable_assessment_count }} / {{ version.assessment_count }}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <div v-if="archiveImportTask?.kind === 'import_apply' && archiveApplyResult()" class="rounded border border-green-800 bg-green-900/20 p-3 text-sm text-green-200">
                    Created {{ archiveApplyResult()?.summary.created }},
                    updated {{ archiveApplyResult()?.summary.updated }},
                    restored {{ archiveApplyResult()?.summary.restored_assessments }} assessments.
                </div>
                <div v-if="archiveImportError || archiveApplyError" class="rounded border border-red-800 bg-red-900/30 p-3 text-sm text-red-300">
                    {{ archiveImportError || archiveApplyError }}
                </div>
            </section>
        </div>

        <section class="mt-6 space-y-4 rounded border border-gray-700 bg-gray-900/40 p-4">
            <div class="flex items-center justify-between gap-3">
                <h4 class="text-xs font-bold uppercase text-gray-500">Stored Archives</h4>
                <button
                    type="button"
                    @click="loadArchiveSnapshots"
                    :disabled="archiveSnapshotsLoading"
                    class="inline-flex items-center gap-2 rounded border border-gray-600 px-3 py-2 text-xs font-bold text-gray-200 hover:bg-gray-700 disabled:opacity-50"
                >
                    <RefreshCw :size="14" />
                    Refresh
                </button>
            </div>
            <div v-if="archiveSnapshots.length === 0" class="text-sm text-gray-500">
                No stored archives found.
            </div>
            <div v-else class="overflow-x-auto rounded border border-gray-700">
                <table class="min-w-full divide-y divide-gray-700 text-left text-xs">
                    <thead class="bg-gray-950/60 text-gray-400">
                        <tr>
                            <th class="px-3 py-2">Project</th>
                            <th class="px-3 py-2">Created</th>
                            <th class="px-3 py-2">Versions</th>
                            <th class="px-3 py-2">Size</th>
                            <th class="px-3 py-2"></th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700 text-gray-200">
                        <tr v-for="snapshot in archiveSnapshots" :key="snapshot.filename">
                            <td class="px-3 py-2 font-semibold">{{ snapshot.project_name || snapshot.filename }}</td>
                            <td class="px-3 py-2">{{ snapshot.created_at || snapshot.modified_at }}</td>
                            <td class="px-3 py-2">{{ snapshot.version_count ?? '-' }}</td>
                            <td class="px-3 py-2">{{ Math.ceil(snapshot.size / 1024) }} KB</td>
                            <td class="px-3 py-2 text-right">
                                <a
                                    :href="getProjectArchiveSnapshotDownloadUrl(snapshot.filename)"
                                    class="inline-flex items-center gap-2 rounded bg-gray-700 px-3 py-1.5 font-bold text-white hover:bg-gray-600"
                                >
                                    <Download :size="13" />
                                    Download
                                </a>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>
    </div>
  </div>
  <div v-else class="text-center py-20">
    <h2 class="text-2xl font-bold text-red-400 mb-4">Access Denied</h2>
    <p class="text-gray-400">You do not have permission to access this page.</p>
    <router-link to="/" class="text-blue-400 hover:text-blue-300 mt-4 inline-block">&larr; Back to Dashboard</router-link>
  </div>
</template>
