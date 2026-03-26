<script setup lang="ts">
import { ref, watch, computed, onMounted, inject, type Ref } from 'vue'
import { getDependencyChains } from '../lib/api'
import DependencyPathList from './DependencyPathList.vue'

const teamMapping = inject<Ref<Record<string, string | string[]>>>('teamMapping', ref({}))

const teamMappedNames = computed(() => {
    const map = new Map<string, string[]>()
    for (const [key, val] of Object.entries(teamMapping.value)) {
        if (key !== '*') {
            map.set(key, Array.isArray(val) ? val : [val])
        }
    }
    return map
})

const props = defineProps<{
    projectUuid: string
    componentUuid: string
    projectName: string
    paths?: string[]
}>()

const emit = defineEmits<{
    (e: 'depth-updated', depth: number | null): void
}>()

const paths = ref<string[]>(props.paths ? [...props.paths] : [])
const loading = ref(false)
const error = ref('')
const loaded = ref(!!props.paths && props.paths.length > 0)

const minimalDepth = computed<number | null>(() => {
    if (!paths.value || paths.value.length === 0) return null
    let min = Number.POSITIVE_INFINITY
    for (const p of paths.value) {
        const depth = p.split(' -> ').length - 1
        if (!Number.isNaN(depth) && depth >= 0) {
            min = Math.min(min, depth)
        }
    }
    return min === Number.POSITIVE_INFINITY ? null : min
})

watch(minimalDepth, (value) => {
    emit('depth-updated', value)
}, { immediate: true })

watch(
    () => props.paths,
    (newPaths) => {
        if (newPaths && newPaths.length > 0) {
            paths.value = [...newPaths]
            loaded.value = true
            loading.value = false
            error.value = ''
        }
    },
    { immediate: true }
)

const loadChains = async () => {
    if (loaded.value) return

    loading.value = true
    error.value = ''
    try {
        const res = await getDependencyChains(props.projectUuid, props.componentUuid)
        paths.value = res || []
        loaded.value = true
    } catch (e: any) {
        error.value = e.message || 'Failed to load chains'
    } finally {
        loading.value = false
    }
}

onMounted(() => {
    if (!loaded.value) loadChains()
})
</script>

<template>
    <div>
        <div v-if="loading" class="text-xs text-gray-500 italic">Loading...</div>
        <div v-else-if="error" class="text-xs text-red-500">{{ error }}</div>
        <div v-else-if="paths.length === 0 && loaded" class="text-xs text-gray-500 italic">No dependency chains found.</div>
        <DependencyPathList v-else :paths="paths" :project-name="projectName" :team-mapped-names="teamMappedNames" />
    </div>
</template>
