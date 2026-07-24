# Runtime secrets

Do not commit credentials in this directory. The optional archive Git profile
reads only `dtvp_archive_deploy_key` and `known_hosts` from here by default; it
does not receive the directory or any application credentials. Override the
host paths with `DTVP_ARCHIVE_GIT_SSH_KEY_HOST_FILE` and
`DTVP_ARCHIVE_GIT_KNOWN_HOSTS_HOST_FILE` when needed.

The hardened Compose overlay creates application secret mounts directly from
values in the local `.env` file, so those values do not appear in container
environment metadata. Backend credentials use vendor-neutral
`DTVP_VULNERABILITY_BACKEND_*` names. Demo-only backend infrastructure and its
database credentials live under `demo/`, outside the DTVP deployment.
