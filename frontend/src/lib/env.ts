export const getRuntimeConfig = (key: 'DTVP_CONTEXT_PATH' | 'DTVP_API_URL', defaultValue: string): string => {
    const val = window.__env__?.[key];
    if (val && !val.startsWith('${')) {
        return val;
    }
    return defaultValue;
};
