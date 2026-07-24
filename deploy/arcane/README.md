# Arcane deployment

This directory is a self-contained Arcane Compose project for DTVP. It uses
published images rather than repository build contexts, exposes DTVP directly
on port 8000, and separates non-secret service settings from Arcane's project
environment. Dependency-Track or any other vulnerability backend remains an
independently operated external system.

- `dtvp.env` contains non-secret DTVP runtime settings.
- `agentyzer.env` contains non-secret Agentyzer runtime settings.
- Arcane's project `.env`, initialized from `.env.dist`, contains image/port
  selectors and secrets only.

The project has two named volumes:

- `dtvp-data` is durable DTVP-owned state and must be backed up.
- `agentyzer-repos` contains cloned repositories, worktrees, and local job
  state. It is disposable and must not be included in DTVP backups.

## Manual Arcane project

1. Open **Projects**, choose **Create Project**, and name it `dtvp`.
2. Paste `compose.yml` into the Compose editor.
3. Enable **Workspace** and create `dtvp.env`, `agentyzer.env`, and
   `repos.yaml` from the files in this directory. Adjust the non-secret runtime
   settings and add repository mappings without credentials or authenticated
   clone URLs.
4. Open **Environment Configuration (.env)**, copy `.env.dist`, and replace
   every required secret. Generate independent session/service/admin secrets
   with `openssl rand -hex 32`; do not reuse values across roles.
5. Add the DTVP image registry to Arcane first if it requires authentication,
   then create the project.

The default port binding is `127.0.0.1:8000`. Keep it when a reverse proxy runs
on the Docker host. Set `DTVP_HTTP_BIND_ADDRESS=0.0.0.0` only for intentional
direct network exposure.

## Git-managed Arcane project

1. Add this repository under **Customize → Git Repositories**.
2. Create a project **From Git Repo** and select the desired branch.
3. Set the Compose file path to `deploy/arcane/compose.yml`. Arcane's
   directory-aware sync copies both service env files and `repos.yaml` from the
   same directory.
4. Enable Auto Sync if desired. Arcane redeploys a changed sync only while the
   project is already running.
5. Maintain non-secret deployment settings in `dtvp.env` and `agentyzer.env`
   on the deployment branch. Edit the project `.env` in Arcane and copy the
   secret values from `.env.dist`. Arcane keeps this file editable and outside
   the read-only Git workspace, so secrets do not need to be committed.

For reproducible Git-managed releases, replace the default `:latest` image
references in `compose.yml` with versioned tags or digests, or set immutable
`DTVP_IMAGE` and `AGENTYZER_IMAGE` values in the project environment.
The currently published DTVP and Agentyzer images target `linux/amd64`.

The Compose file intentionally does not pass the complete project `.env` into
either container. Each service loads only its own non-secret env file.
Credentials are explicitly overridden with Compose secret files, so DTVP
credentials are not exposed to Agentyzer and LLM credentials are not exposed
to DTVP.

## Backup and restore

Use Arcane's **Volumes** view to back up the project-generated `dtvp-data`
volume. Stop the project first so DTVP cannot write during the archive, then
start it again after the backup completes. Store Arcane's `/backups` directory
on durable encrypted or off-host storage.

Do not back up `agentyzer-repos`; Agentyzer recreates it. The selected
vulnerability backend is also outside this project and remains the
responsibility of its operator. Arcane volume backups do not update DTVP's
`backup_status.json`, so this configuration leaves
`DTVP_BACKUP_MAX_AGE_SECONDS=0` unless separate backup automation maintains
that marker.
