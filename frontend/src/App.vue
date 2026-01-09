<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { getVersion } from './lib/api'

const version = ref('')
const build = ref('')

onMounted(async () => {
    try {
        const v = await getVersion()
        version.value = v.version
        build.value = v.build
    } catch (e) {
        console.error('Failed to fetch version', e)
    }
})
</script>

<template>
  <div class="min-h-screen bg-gray-900 text-white font-sans w-full flex flex-col">
    <template v-if="$route.path !== '/login'">
        <header class="p-4 border-b border-gray-700 flex justify-between items-center bg-gray-800">
        <h1 class="text-xl font-bold text-blue-400">DTVP</h1>
        <div class="text-sm text-gray-400">Dependency Track Vulnerability Processor</div>
        </header>
        <main class="p-8 max-w-7xl mx-auto w-full flex-grow">
            <router-view></router-view>
        </main>
        <footer class="p-4 border-t border-gray-700 text-center text-xs text-gray-500">
            DTVP v{{ version }} (build {{ build }})
        </footer>
    </template>
    <router-view v-else></router-view>
  </div>
</template>
