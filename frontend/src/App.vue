<script setup lang="ts">
import { ref, onMounted, provide, computed } from 'vue'
import { getVersion, getUserInfo, logout, getChangelog } from './lib/api'
import { getRuntimeConfig } from './lib/env'
import ChangelogModal from './components/ChangelogModal.vue'

const version = ref('')
const build = ref('')
const user = ref({ username: '', role: '' })
const realRole = ref('')
const isAnalystView = ref(false)

const projectAuthor = ref('')
const projectEmail = ref('')
const projectUrls = ref({ homepage: '', main: '', github: '', mastodon: '' })

const contextPathRaw = getRuntimeConfig('DTVP_CONTEXT_PATH', '')
const contextPath = contextPathRaw ? (contextPathRaw.startsWith('/') ? contextPathRaw.replace(/\/$/, '') : '/' + contextPathRaw.replace(/\/$/, '')) : ''
const apiBase = `${contextPath || ''}/api`
const sbomUrl = ref(`${apiBase}/sbom`)
const metadataUrl = `${apiBase}/metadata`

const showChangelog = ref(false)
const changelogContent = ref('')

provide('user', computed(() => ({
    ...user.value,
    role: isAnalystView.value ? 'ANALYST' : user.value.role
})))
provide('realRole', realRole)

onMounted(async () => {
    try {
        const v = await getVersion()
        version.value = v.version
        build.value = v.build

        // Check for version update
        const lastSeenVersion = localStorage.getItem('dtvp_last_seen_version')
        if (lastSeenVersion !== v.version && v.version !== '0.0.0') {
            try {
                const res = await getChangelog()
                changelogContent.value = res.content
                showChangelog.value = true
            } catch (e) {
                console.error('Failed to fetch changelog', e)
            }
        }
    } catch (e) {
        console.error('Failed to fetch version', e)
    }

    try {
        const metaRes = await fetch(metadataUrl)
        if (metaRes.ok) {
            const meta = await metaRes.json()
            if (Array.isArray(meta.authors) && meta.authors.length > 0) {
                const author = meta.authors[0]
                const nameMatch = author.match(/^([^<]+)/)
                const emailMatch = author.match(/<([^>]+)>/)
                projectAuthor.value = (nameMatch && nameMatch[1].trim()) || author
                projectEmail.value = (emailMatch && emailMatch[1]) || ''
            }
            if (meta.urls) {
                projectUrls.value = {
                    homepage: meta.urls.Homepage || projectUrls.value.homepage,
                    main: meta.urls['Main repo'] || projectUrls.value.main,
                    github: meta.urls.GitHub || projectUrls.value.github,
                    mastodon: meta.urls.Mastodon || projectUrls.value.mastodon,
                }
            }
        }
    } catch (e) {
        console.error('Failed to fetch metadata', e)
    }

    try {
        const u = await getUserInfo()
        user.value = { 
            username: u.username, 
            role: u.role || 'ANALYST' 
        }
        realRole.value = u.role || 'ANALYST'
    } catch (e) {
        // Not logged in or error
    }
})

const toggleView = () => {
    isAnalystView.value = !isAnalystView.value
}

const acknowledgeChangelog = () => {
    showChangelog.value = false
    localStorage.setItem('dtvp_last_seen_version', version.value)
}
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
                        <router-link to="/statistics" class="hover:text-blue-300 transition-colors" exact-active-class="text-blue-400">Statistics</router-link>
                        <router-link v-if="realRole === 'REVIEWER'" to="/settings" class="hover:text-blue-300 transition-colors" exact-active-class="text-blue-400">Settings</router-link>
                    </nav>
                </div>
                <div class="text-sm text-gray-400 hidden sm:flex items-center gap-6">
                    <div v-if="realRole === 'REVIEWER'" class="flex items-center gap-2 mr-4 bg-gray-700/50 px-3 py-1.5 rounded-full border border-gray-600 shadow-inner">
                        <span :class="['text-[10px] font-bold uppercase tracking-wider transition-colors duration-300', isAnalystView ? 'text-gray-400' : 'text-purple-400']">
                            Reviewer
                        </span>
                        <button 
                            @click="toggleView" 
                            class="relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none bg-gray-600"
                            :class="isAnalystView ? 'bg-blue-600' : 'bg-purple-600'"
                        >
                            <span 
                                class="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out"
                                :class="isAnalystView ? 'translate-x-4' : 'translate-x-0'"
                            ></span>
                        </button>
                        <span :class="['text-[10px] font-bold uppercase tracking-wider transition-colors duration-300', isAnalystView ? 'text-blue-400' : 'text-gray-400']">
                            Analyst
                        </span>
                    </div>

                    <div v-if="user.username" class="flex items-center gap-3">
                        <div class="flex flex-col items-end">
                            <span class="text-blue-300 font-medium leading-none">{{ user.username }}</span>
                            <span class="text-gray-500 text-xs mt-1">({{ isAnalystView ? 'ANALYST View' : user.role }})</span>
                        </div>
                        <button 
                            @click="logout"
                            class="bg-gray-700 hover:bg-gray-600 text-white text-[10px] px-2 py-1 rounded transition-colors cursor-pointer border border-gray-600"
                        >
                            Logout
                        </button>
                    </div>
                    <div v-else>Dependency Track Vulnerability Processor</div>
                </div>
            </div>
        </header>
        <main class="p-6 sm:p-8 max-w-7xl mx-auto w-full flex-grow">
            <router-view></router-view>
        </main>
        <footer class="border-t border-gray-700 bg-gray-900">
            <div class="max-w-7xl mx-auto p-4 text-center text-xs text-gray-500 space-y-1">
                <div>DTVP v{{ version }} (build {{ build }})</div>
                <div>Author: {{ projectAuthor }}</div>
                <div>
                    <a :href="projectUrls.main" target="_blank" rel="noopener noreferrer" class="text-blue-300 hover:text-blue-200">Main repo</a>
                    •
                    <a :href="projectUrls.github" target="_blank" rel="noopener noreferrer" class="text-blue-300 hover:text-blue-200">GitHub</a>
                </div>
                <div>
                    <a :href="sbomUrl + '/backend'" target="_blank" rel="noopener noreferrer" class="text-blue-300 hover:text-blue-200">Download Backend SBOM</a>
                    •
                    <a :href="sbomUrl + '/frontend'" target="_blank" rel="noopener noreferrer" class="text-blue-300 hover:text-blue-200">Download Frontend SBOM</a>
                </div>
                <div>
                    <a :href="sbomUrl" target="_blank" rel="noopener noreferrer" class="text-blue-300 hover:text-blue-200">Download CycloneDX SBOM</a>
                </div>
            </div>
        </footer>

        <ChangelogModal 
            v-if="showChangelog" 
            :changelog="changelogContent" 
            @acknowledge="acknowledgeChangelog"
        />
    </template>
    <router-view v-else></router-view>
  </div>
</template>
