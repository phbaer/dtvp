import { mount, flushPromises, type MountingOptions, type VueWrapper } from '@vue/test-utils'
import { createMemoryHistory, createRouter, type RouteRecordRaw } from 'vue-router'

export async function mountWithRouter<T>(
    component: T,
    options: {
        initialPath: string
        routes: RouteRecordRaw[]
        mountOptions?: MountingOptions<any>
        flush?: boolean
    }
): Promise<{ wrapper: VueWrapper<any>; router: ReturnType<typeof createRouter> }> {
    const { initialPath, routes, mountOptions = {}, flush = true } = options
    const router = createRouter({
        history: createMemoryHistory(),
        routes,
    })

    router.push(initialPath)
    await router.isReady()

    const global = mountOptions.global ?? {}
    const wrapper = mount(component as any, {
        ...mountOptions,
        global: {
            ...global,
            plugins: [...(global.plugins ?? []), router],
        },
    })

    if (flush) {
        await flushPromises()
    }

    return { wrapper, router }
}