<script setup lang="ts">
// Opens a short link or saved view (`/v/<code>`, ADR 0015): the project
// review with the stored filters. A view for any project takes the project
// from `?project=`.
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Loader2 } from '@lucide/vue'
import { getSavedView } from '../lib/api'
import { parseFilterQueryString } from '../lib/useProjectVulnFilters'

const route = useRoute()
const router = useRouter()
const message = ref('')

onMounted(async () => {
    const code = String(route.params.code || '')
    try {
        const view = await getSavedView(code)
        const project = view.project || String(route.query.project || '')
        if (!project) {
            message.value = `“${view.name || code}” applies to any project. Open a project and choose it under Views.`
            return
        }
        await router.replace({
            path: `/project/${encodeURIComponent(project)}`,
            query: parseFilterQueryString(view.query),
        })
    } catch (cause: any) {
        message.value = cause?.response?.status === 404
            ? `The link ${code} does not exist.`
            : 'The link could not be opened; try again later.'
    }
})
</script>

<template>
    <div class="mx-auto mt-16 max-w-md rounded-2xl border border-white/10 bg-white/3 p-6 text-sm text-gray-300" data-testid="short-link">
        <p v-if="message" role="alert">{{ message }}</p>
        <p v-else class="inline-flex items-center gap-2"><Loader2 :size="14" class="animate-spin" /> Opening the link…</p>
        <router-link v-if="message" to="/" class="mt-3 inline-block text-blue-300 hover:text-blue-200">Back to the projects</router-link>
    </div>
</template>
