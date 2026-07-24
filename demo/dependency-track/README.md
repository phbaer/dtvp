# Dependency-Track demo backend

This directory provides an optional demonstration environment for exercising
the Dependency-Track adapter. Dependency-Track, its frontend, and PostgreSQL
are not DTVP services and are not included in the default Compose deployment.
The demo is intentionally configured for local evaluation with DTVP
authentication disabled; do not use it as a production deployment.

For a source-based development stack using the lightweight mock backend, run
this from the repository root after installing the Python and frontend
dependencies:

```sh
pm2 start demo/dependency-track/ecosystem.config.js --update-env
```

From the repository root:

```sh
cp .env.dist .env
cp demo/dependency-track/.env.dist demo/dependency-track/.env
# Set a random DTVP_DEMO_DEPENDENCY_TRACK_DATABASE_PASSWORD in the demo env file.
docker compose \
  --env-file .env \
  --env-file demo/dependency-track/.env \
  -f compose.yml \
  -f demo/dependency-track/compose.yml \
  up -d
```

Open `http://localhost/` for Dependency-Track and
`http://localhost/dtvp/` for DTVP. After Dependency-Track's initial setup,
create a least-privilege service-team API key, place it in
`DTVP_DEMO_DEPENDENCY_TRACK_API_KEY`, and recreate the `dtvp` service.

To keep credentials out of container metadata, add the secret overlays:

```sh
docker compose \
  --env-file .env \
  --env-file demo/dependency-track/.env \
  -f compose.yml \
  -f demo/dependency-track/compose.yml \
  -f compose.secrets.yml \
  -f demo/dependency-track/compose.secrets.yml \
  up -d
```

Demo state has its own volumes and is deliberately excluded from DTVP backup
and restore procedures. Manage or discard it independently.
