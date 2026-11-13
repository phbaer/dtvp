<script setup lang="ts">
import { computed } from 'vue'
import { marked } from 'marked'

const props = defineProps<{ markdown: string }>()
const rendered = computed(() => {
    const template = document.createElement('template')
    template.innerHTML = marked.parse(props.markdown, { async: false }) as string
    const allowed = new Set(['P', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'UL', 'OL', 'LI', 'TABLE', 'THEAD', 'TBODY', 'TR', 'TH', 'TD', 'STRONG', 'EM', 'CODE', 'PRE', 'BLOCKQUOTE', 'HR', 'BR', 'A', 'DEL'])
    for (const element of Array.from(template.content.querySelectorAll('*'))) {
        if (!allowed.has(element.tagName)) {
            element.remove()
            continue
        }
        const href = element.tagName === 'A' ? element.getAttribute('href') : null
        for (const attribute of Array.from(element.attributes)) element.removeAttribute(attribute.name)
        if (href) {
            try {
                const url = new URL(href)
                if (['http:', 'https:'].includes(url.protocol) && !url.username && !url.password) {
                    element.setAttribute('href', url.href)
                    element.setAttribute('target', '_blank')
                    element.setAttribute('rel', 'noopener noreferrer')
                }
            } catch { /* Unsafe or unsupported links remain plain text. */ }
        }
    }
    return template.innerHTML
})
</script>

<template>
    <section class="mt-3 min-w-0 max-w-full" data-testid="assessment-report">
        <h4 class="mb-2 text-[10px] font-bold uppercase tracking-wide text-gray-400">Full assessment</h4>
        <div class="assessment-report overflow-x-auto break-words text-xs leading-relaxed text-gray-300" v-html="rendered"></div>
    </section>
</template>

<style scoped>
.assessment-report :deep(h1) { font-size: 1rem; font-weight: 700; margin: 0 0 0.75rem; }
.assessment-report :deep(h2), .assessment-report :deep(h3) { font-size: 0.875rem; font-weight: 700; margin: 1.25rem 0 0.5rem; }
.assessment-report :deep(p) { margin: 0.5rem 0; }
.assessment-report :deep(ul) { list-style: disc; padding-left: 1.25rem; margin: 0.5rem 0; }
.assessment-report :deep(ol) { list-style: decimal; padding-left: 1.25rem; margin: 0.5rem 0; }
.assessment-report :deep(table) { border-collapse: collapse; margin: 0.75rem 0; width: 100%; }
.assessment-report :deep(th), .assessment-report :deep(td) { border: 1px solid #374151; padding: 0.4rem; text-align: left; vertical-align: top; }
.assessment-report :deep(a) { color: #67e8f9; text-decoration: underline; }
.assessment-report :deep(pre) { overflow-x: auto; }
</style>
