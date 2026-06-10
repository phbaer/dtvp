import { createRouter, createWebHistory } from 'vue-router'

import { getUserInfo } from './lib/api'
import { getRuntimeConfig } from './lib/env'

const routes = [
    { path: '/login', component: () => import('./pages/Login.vue') },
    { path: '/', component: () => import('./pages/Dashboard.vue') },
    { path: '/settings', component: () => import('./pages/Settings.vue'), meta: { role: 'REVIEWER' } },
    { path: '/project/:name', component: () => import('./pages/ProjectView.vue') },
    { path: '/project/:name/vscorer', component: () => import('./pages/TMRescore.vue'), meta: { role: 'REVIEWER' } },
    { path: '/project/:name/tmrescore', component: () => import('./pages/TMRescore.vue'), meta: { role: 'REVIEWER' } },
    { path: '/statistics', component: () => import('./pages/Statistics.vue') },
]

export const router = createRouter({
    history: createWebHistory(getRuntimeConfig('DTVP_CONTEXT_PATH', '/')),
    routes,
})

let sessionChecked = false;
let userRole: string | undefined = undefined;

router.beforeEach(async (to, _from) => {
    // If going to login, allow it
    if (to.path === '/login') {
        return;
    }

    if (!sessionChecked) {
        try {
            const user = await getUserInfo();
            userRole = user.role;
            sessionChecked = true;
        } catch {
            sessionChecked = true;
            return '/login';
        }
    }

    // Role check for routes with meta.role
    if (to.meta.role && to.meta.role !== userRole) {
        return '/';
    }
});
