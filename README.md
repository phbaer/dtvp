# Dependency Track Vulnerability Processor

This is an opinionated, currently completely auto-generated (by Antigravity) tool for processing Dependency Track vulnerabilities. It will read all project versions of a specific project from Dependency Track. Vulnerabilities will be grouped by Common Vulnerability ID (CVE). A user can then assess it accross all versions of the project and update the analysis state of the vulnerability.

## Environment variables:

* DTVP_API_KEY=<Dependency Track API key>
* DTVP_API_URL=<Dependency Track Base URL>
* DTVP_OIDC_AUTHORITY=<OIDC Authority>
* DTVP_CONTEXT_PATH=<Context path (optional, default: /)>
* DTVP_FRONTEND_URL=<Frontend URL (optional, default: http://localhost:8000)>
* DTVP_OIDC_REDIRECT_URI=<Redirect URI (optional, default: http://localhost:8000/auth/callback)>
* DTVP_SESSION_SECRET_KEY=<Session secret key>
* DTVP_OIDC_CLIENT_ID=<OIDC Client ID>
* DTVP_OIDC_CLIENT_SECRET=<OIDC Client Secret>
