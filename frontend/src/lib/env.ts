export type RuntimeConfigKey =
    | 'DTVP_CONTEXT_PATH'
    | 'DTVP_FRONTEND_URL'
    | 'DTVP_API_URL'
    | 'DTVP_DEV_DISABLE_AUTH'
    | 'DTVP_DEFAULT_PROJECT_FILTER';

export const getRuntimeConfig = (key: RuntimeConfigKey, defaultValue: string): string => {
    // Primary source: server-side injected config via index.html (window.__env__)
    const val = (typeof window !== 'undefined' ? (window as any).__env__?.[key] : undefined);
    if (typeof val === 'string' && val && !val.startsWith('${')) {
        return val;
    }

    // Fallback: Vite-provided env variables (prefixed with VITE_). Useful in development
    // or build environments where we don't inject window.__env__.
    const viteKey = `VITE_${key}`;
    const viteVal = (import.meta.env as any)[viteKey];
    if (typeof viteVal === 'string' && viteVal) {
        return viteVal;
    }

    // Additional fallback for Node environments (e.g., tests or SSR builds).
    const nodeVal = (typeof process !== 'undefined' ? (process.env as any)[key] || (process.env as any)[viteKey] : undefined);
    if (typeof nodeVal === 'string' && nodeVal) {
        return nodeVal;
    }

    return defaultValue;
};
