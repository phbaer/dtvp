import { createRouter, createWebHistory } from 'vue-router'
import Login from './pages/Login.vue'
import Dashboard from './pages/Dashboard.vue'
import ProjectView from './pages/ProjectView.vue'
import Settings from './pages/Settings.vue'
import Statistics from './pages/Statistics.vue'
import TMRescore from './pages/TMRescore.vue'

import { getUserInfo } from './lib/api'
import { getRuntimeConfig } from './lib/env'

const routes = [
    { path: '/login', component: Login },
    { path: '/', component: Dashboard },
    { path: '/settings', component: Settings, meta: { role: 'REVIEWER' } },
    { path: '/project/:name', component: ProjectView },
    { path: '/project/:name/tmrescore', component: TMRescore },
    { path: '/statistics', component: Statistics },
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
