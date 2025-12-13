export { };

declare global {
    interface Window {
        __env__: {
            DTVP_CONTEXT_PATH: string;
            DTVP_API_URL: string;
        };
    }
}
