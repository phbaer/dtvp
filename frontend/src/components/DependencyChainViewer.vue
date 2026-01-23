<script setup lang="ts">
import { ref } from 'vue'
import { getDependencyChains } from '../lib/api'
import DependencyPathList from './DependencyPathList.vue'

const props = defineProps<{
    projectUuid: string
    componentUuid: string
    projectName: string
}>()

const paths = ref<string[]>([])
const loading = ref(false)
const error = ref('')
const total = ref(0)
const loaded = ref(false)
const expanded = ref(false)

const loadChains = async (reset = false) => {
    if (reset) {
        paths.value = []
        loaded.value = false
    }

    loading.value = true
    error.value = ''
    try {
        const res = await getDependencyChains(props.projectUuid, props.componentUuid)
        paths.value = res
        total.value = res.length
        loaded.value = true
    } catch (e: any) {
        error.value = e.message || 'Failed to load chains'
    } finally {
        loading.value = false
    }
}

const toggle = () => {
    expanded.value = !expanded.value
    if (expanded.value && !loaded.value) {
        loadChains(true)
    }
}



</script>

<template>
    <div class="mt-2">
        <button 
            @click="toggle" 
            class="text-xs font-semibold text-blue-400 hover:text-blue-300 flex items-center gap-1 focus:outline-none"
        >
            <span v-if="expanded">Hide Dependency Chains</span>
            <span v-else>Show Dependency Chains</span>
            <span v-if="total > 0 && !loading" class="text-gray-500">({{ total }})</span>
        </button>

        <div v-if="expanded" class="mt-2">
            <div v-if="loading && paths.length === 0" class="text-xs text-gray-500 italic">Loading dependency chains...</div>
            <div v-else-if="error" class="text-xs text-red-500">{{ error }}</div>
            <div v-else>
                <div v-if="paths.length === 0" class="text-xs text-gray-500 italic">No dependency chains found.</div>
                
                <DependencyPathList :paths="paths" :project-name="projectName" />
            </div>
        </div>
    </div>
</template>
