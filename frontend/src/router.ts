import { createRouter, createWebHistory } from 'vue-router'
import Login from './pages/Login.vue'
import Dashboard from './pages/Dashboard.vue'
import ProjectView from './pages/ProjectView.vue'
import Settings from './pages/Settings.vue'

import { login, checkSession } from './lib/api'
import { getRuntimeConfig } from './lib/env'

const routes = [
    { path: '/login', component: Login },
    { path: '/', component: Dashboard },
    { path: '/settings', component: Settings },
    { path: '/project/:name', component: ProjectView },
]

export const router = createRouter({
    history: createWebHistory(getRuntimeConfig('DTVP_CONTEXT_PATH', '/')),
    routes,
})

let sessionChecked = false;

router.beforeEach(async (to, _from, next) => {
    // If going to login, allow it
    if (to.path === '/login') {
        next();
        return;
    }

    if (!sessionChecked) {
        const isAuthenticated = await checkSession();
        sessionChecked = true;

        if (!isAuthenticated) {
            login(); // Redirects to OIDC
            return;
        }
    }
    next();
});
