export const getRuntimeConfig = (key: 'DTVP_CONTEXT_PATH' | 'DTVP_FRONTEND_URL' | 'DTVP_DEV_DISABLE_AUTH', defaultValue: string): string => {
    const val = window.__env__?.[key];
    if (val && !val.startsWith('${')) {
        return val;
    }
    return defaultValue;
};
