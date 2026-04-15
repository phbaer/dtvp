import { mount, flushPromises } from '@vue/test-utils'
import ProjectView from '../ProjectView.vue'

export const defaultLifecycleFilters = ['OPEN', 'ASSESSED', 'INCOMPLETE', 'INCONSISTENT']
export const extendedLifecycleFilters = ['OPEN', 'ASSESSED', 'ASSESSED_LEGACY', 'INCOMPLETE', 'INCONSISTENT']
export const defaultAnalysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED']
export const extendedAnalysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED', 'OLD', 'NEW', 'UNKNOWN_STATE']
export const defaultStatusFilters = ['NOT_SET', 'INCOMPLETE', 'INCONSISTENT', 'ASSESSED']
export const extendedStatusFilters = ['NOT_SET', 'INCOMPLETE', 'INCONSISTENT', 'ASSESSED', 'EXPLOITABLE', 'IN_TRIAGE']

export async function mountProjectView(options: {
    routeName?: string
    query?: Record<string, unknown>
    mountOptions?: Record<string, any>
    flush?: boolean
} = {}) {
    const {
        routeName = 'Test',
        query = {},
        mountOptions = {},
        flush = true,
    } = options
    const global = mountOptions.global ?? {}
    const resolvedMountOptions = {
        ...mountOptions,
        global: {
            ...global,
            stubs: {
                RouterLink: true,
                ...global.stubs,
            },
            mocks: {
                $route: {
                    params: routeName === undefined ? {} : { name: routeName },
                    query,
                },
                ...global.mocks,
            },
            provide: {
                user: { value: { role: 'REVIEWER' } },
                ...global.provide,
            },
        },
    }

    const wrapper = mount(ProjectView as any, resolvedMountOptions as any)

    if (flush) {
        await flushPromises()
    }

    return wrapper
}

export async function updateProjectViewState(wrapper: any, state: Record<string, unknown>) {
    Object.assign(wrapper.vm as Record<string, unknown>, state)
    await wrapper.vm.$nextTick()
}