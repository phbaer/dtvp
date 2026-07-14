export { };

declare global {
    interface Window {
        __env__: {
            DTVP_CONTEXT_PATH: string;
            DTVP_FRONTEND_URL: string;
            DTVP_DEV_DISABLE_AUTH: string;
            DTVP_DEFAULT_PROJECT_FILTER: string;
            DTVP_ATTRIBUTION_AGE_FILTER_DAYS: string;
            DTVP_JIRA_CREATE_URL: string;
        };
    }
}
