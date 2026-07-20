import { computed, ref } from 'vue'

export type ProjectHeaderViewMode = 'analysis' | 'statistics'

export const projectHeaderState = {
  currentProjectName: ref<string | null>(null),
  lastProjectName: ref<string | null>(null),
  lastProjectPath: ref<string | null>(null),
  isAllProjects: ref(true),
  viewMode: ref<ProjectHeaderViewMode>('analysis'),
  isReviewer: ref(false),
  bulkWorkflowHandler: ref<(() => void) | null>(null),
}

export const showProjectHeaderButtons = computed(
  () => projectHeaderState.currentProjectName.value !== null && !projectHeaderState.isAllProjects.value
)
