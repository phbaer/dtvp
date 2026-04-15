<script setup lang="ts">
import { ref, onMounted, provide, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { projectHeaderState } from './lib/projectHeaderStore'
import { getVersion, getUserInfo, logout, getChangelog } from './lib/api'
import { getRuntimeConfig } from './lib/env'
import ChangelogModal from './components/ChangelogModal.vue'

const version = ref('')
const build = ref('')
const user = ref({ username: '', role: '' })
const realRole = ref('')
const isAnalystView = ref(false)
const router = useRouter()
const route = useRoute()

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

const goTo = (path: string) => {
    router.push(path)
}

const goToAllProjects = () => {
    projectHeaderState.currentProjectName.value = null
    projectHeaderState.isAllProjects.value = true
    router.push('/')
}

const toggleProjectView = () => {
    if (!projectHeaderState.isAllProjects.value) {
        projectHeaderState.viewMode.value = projectHeaderState.viewMode.value === 'analysis' ? 'statistics' : 'analysis'
    }
}

const headerButtonBase = 'h-8 px-3 inline-flex items-center rounded-full text-[11px] font-semibold uppercase tracking-widest border border-white/10 transition-all whitespace-nowrap'
const headerButtonDefault = 'bg-slate-950/20 text-slate-300 hover:bg-slate-950/30 hover:text-white'
const headerButtonActive = 'bg-white/10 text-white shadow-sm shadow-slate-900/20'
const headerButtonContext = 'bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20'
const headerButtonWarning = 'bg-amber-500/10 text-amber-300 hover:bg-amber-500/20'

const currentProjectName = computed(() => projectHeaderState.currentProjectName.value)
const isAllProjects = computed(() => projectHeaderState.isAllProjects.value)
const showProjectHeaderButtons = computed(
    () => {
        const name = currentProjectName.value
        return !!name && name.trim().length > 0 && !isAllProjects.value
    }
)

const isActive = (path: string) => route.path === path

watch(() => route.path, (path) => {
    if (!path.startsWith('/project/')) {
        projectHeaderState.currentProjectName.value = null
        projectHeaderState.isAllProjects.value = true
    }
}, { immediate: true })

const acknowledgeChangelog = () => {
    showChangelog.value = false
    localStorage.setItem('dtvp_last_seen_version', version.value)
}
</script>

<template>
  <div class="min-h-screen w-full flex flex-col bg-slate-950/70 text-white">
    <template v-if="$route.path !== '/login'">
        <header class="sticky top-0 z-40 border-b border-gray-700/70 bg-gray-800/75 backdrop-blur-2xl">
            <div class="w-full p-3 flex flex-wrap justify-between items-center gap-3">
                <div class="flex flex-wrap items-center gap-3">
                    <router-link
                        to="/"
                        class="text-lg font-black uppercase tracking-[0.3em] text-slate-100 hover:text-white transition-colors"
                    >
                        DTVP
                    </router-link>

                    <template v-if="showProjectHeaderButtons">
                        <span class="inline-flex h-8 overflow-hidden rounded-full border border-white/10">
                            <router-link
                                to="/"
                                @click.prevent="goToAllProjects"
                                :class="[headerButtonBase, headerButtonDefault, 'rounded-r-none rounded-l-full']"
                            >
                                All Projects
                            </router-link>
                            <span class="h-full w-px bg-white/10"></span>
                            <span class="px-4 h-full inline-flex items-center text-[11px] font-semibold uppercase tracking-widest transition-all whitespace-nowrap bg-blue-600 text-white">
                                {{ currentProjectName }}
                            </span>
                        </span>
                    </template>
                    <template v-else>
                        <router-link
                            to="/"
                            @click.prevent="goToAllProjects"
                            :class="[headerButtonBase, route.path === '/' ? headerButtonActive : headerButtonDefault]"
                        >
                            All Projects
                        </router-link>
                    </template>

                    <button
                        type="button"
                        @click="goTo('/statistics')"
                        :class="[headerButtonBase, isActive('/statistics') ? headerButtonActive : headerButtonDefault]"
                    >
                        Statistics
                    </button>
                    <button
                        v-if="realRole === 'REVIEWER'"
                        type="button"
                        @click="goTo('/settings')"
                        :class="[headerButtonBase, isActive('/settings') ? headerButtonActive : headerButtonDefault]"
                    >
                        Settings
                    </button>

                    <template v-if="showProjectHeaderButtons">
                        <span class="h-10 w-px bg-white/10"></span>
                        <button
                            type="button"
                            @click="toggleProjectView"
                            :class="[headerButtonBase, projectHeaderState.viewMode.value === 'analysis' ? headerButtonContext : headerButtonDefault]"
                        >
                            {{ projectHeaderState.viewMode.value === 'analysis' ? 'Project Statistics' : 'Analysis' }}
                        </button>
                        <button
                            v-if="projectHeaderState.isReviewer.value && projectHeaderState.incompleteCount.value > 0"
                            type="button"
                            @click="projectHeaderState.bulkSyncHandler.value?.()"
                            :class="[headerButtonBase, headerButtonWarning]"
                        >
                            Bulk Sync ({{ projectHeaderState.incompleteCount.value }})
                        </button>
                    </template>
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
                            class="bg-gray-700 hover:bg-gray-600 text-white text-[10px] px-2 py-0.5 rounded transition-colors cursor-pointer border border-gray-600"
                        >
                            Logout
                        </button>
                    </div>
                    <div v-else>Dependency Track Vulnerability Processor</div>
                </div>
            </div>
        </header>
        <main class="px-6 sm:px-8 pt-4 sm:pt-6 w-full flex-grow pb-28">
            <router-view v-slot="{ Component, route }">
                <keep-alive>
                    <component
                        :is="Component"
                        :key="route.path"
                        v-if="route.path.startsWith('/project/')"
                    />
                </keep-alive>
                <component
                    :is="Component"
                    :key="route.fullPath"
                    v-if="!route.path.startsWith('/project/')"
                />
            </router-view>
        </main>
        <footer class="fixed bottom-0 left-0 z-40 w-full border-t border-gray-700/70 bg-gray-900/70 backdrop-blur-2xl">
            <div class="w-full p-3 flex flex-col gap-1 text-center text-[11px] text-gray-400 sm:flex-row sm:items-center sm:justify-between sm:px-5 sm:text-left">
                <div class="font-medium text-gray-300">DTVP v{{ version }} (build {{ build }})</div>
                <div>
                    <a :href="projectUrls.main" target="_blank" rel="noopener noreferrer" class="text-blue-300 hover:text-blue-200">Main repo</a>
                    •
                    <a :href="projectUrls.github" target="_blank" rel="noopener noreferrer" class="text-blue-300 hover:text-blue-200">GitHub</a>
                </div>
                <div class="sm:text-right">
                    <a :href="sbomUrl + '/backend'" target="_blank" rel="noopener noreferrer" class="text-blue-300 hover:text-blue-200">Download Backend SBOM</a>
                    •
                    <a :href="sbomUrl + '/frontend'" target="_blank" rel="noopener noreferrer" class="text-blue-300 hover:text-blue-200">Download Frontend SBOM</a>
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
