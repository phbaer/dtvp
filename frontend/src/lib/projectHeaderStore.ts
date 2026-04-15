import { computed, ref } from 'vue'

export type ProjectHeaderViewMode = 'analysis' | 'statistics'

export const projectHeaderState = {
  currentProjectName: ref<string | null>(null),
  isAllProjects: ref(true),
  viewMode: ref<ProjectHeaderViewMode>('analysis'),
  incompleteCount: ref(0),
  isReviewer: ref(false),
  bulkSyncHandler: ref<(() => void) | null>(null),
}

export const showProjectHeaderButtons = computed(
  () => projectHeaderState.currentProjectName.value !== null && !projectHeaderState.isAllProjects.value
)
