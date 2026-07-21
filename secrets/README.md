# Runtime secrets

Do not commit credentials in this directory. It is reserved for the optional
archive Git deploy key and `known_hosts` file. The hardened Compose overlay
creates application secret mounts directly from values in the local `.env`
file, so those values do not appear in container environment metadata.
