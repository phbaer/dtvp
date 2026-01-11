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
        <header class="border-b border-gray-700 bg-gray-800">
            <div class="max-w-7xl mx-auto p-4 flex justify-between items-center w-full">
                <div class="flex items-center gap-6">
                    <h1 class="text-xl font-bold text-blue-400">
                        <router-link to="/">DTVP</router-link>
                    </h1>
                    <nav class="flex gap-4 text-sm font-medium">
                        <router-link to="/" class="hover:text-blue-300 transition-colors" exact-active-class="text-blue-400">Dashboard</router-link>
                        <router-link to="/settings" class="hover:text-blue-300 transition-colors" exact-active-class="text-blue-400">Settings</router-link>
                    </nav>
                </div>
                <div class="text-sm text-gray-400 hidden sm:block">Dependency Track Vulnerability Processor</div>
            </div>
        </header>
        <main class="p-6 sm:p-8 max-w-7xl mx-auto w-full flex-grow">
            <router-view></router-view>
        </main>
        <footer class="border-t border-gray-700 bg-gray-900">
            <div class="max-w-7xl mx-auto p-4 text-center text-xs text-gray-500">
                DTVP v{{ version }} (build {{ build }})
            </div>
        </footer>
    </template>
    <router-view v-else></router-view>
  </div>
</template>
