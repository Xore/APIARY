# Dockge-managed Keycloak

The `honeypot-keycloak` Dockge stack is defined by
[`docker-compose.keycloak.yml`](../docker-compose.keycloak.yml). Keycloak and
PostgreSQL run on the homeserver; VPS Traefik forwards `auth.example.invalid` over
WireGuard to `${HP_BIND}:${KEYCLOAK_PORT}`. PostgreSQL and port 9000 are never
published.

The stack pulls pinned upstream images and performs no Compose image build.
`Xore/auth-backend` supplies only the custom-theme assets mounted from
`KEYCLOAK_THEME_DIR`. Realm policy, runtime deployment, and database durability
belong here in APIARY.

## Bootstrap

Before the first Dockge start:

1. Review the stack `.env`, initially copied from `keycloak.env.example`.
   Set `KEYCLOAK_PUBLIC_DOMAIN` to the private deployment value; the container
   renders the secret-free realm template locally before its first import.
2. Create `KEYCLOAK_SECRETS_DIR`, owned by `root:root`, with mode `0750`.
3. Create `postgres-password`, `bootstrap-admin-password`, and
   `restic-password` with independent random values, owned by `root:root` and
   mode `0440`. Keycloak runs as a non-root user in group 0, while PostgreSQL's
   entrypoint reads its password file before dropping privileges.
4. Confirm `KEYCLOAK_THEME_DIR` points at the stack-local theme synchronized
   from the reviewed `Xore/auth-backend` repository by the home deploy job.
5. Start in Dockge, then create and test a named MFA-enabled administrator.
6. Delete `bootstrap-admin-password` and restart in Dockge. Bootstrap
   credentials are read only while that file exists.

The canonical, secret-free realm baseline is
[`realm/apiary-realm.json`](realm/apiary-realm.json). Validate it with
`./keycloak/realm/validate.sh`. Client secrets and users are deliberately never
stored in the export.

The VPS route must target the WireGuard endpoint, preserve the original host,
set reviewed `X-Forwarded-*` headers, and never expose port 9000.

The administrator console uses `https://keycloak-admin.example.invalid`, not the
public issuer hostname. VPS Traefik applies a tighter rate limit, while Keycloak
requires a realm-administrator account and MFA. Do not add HTTP Basic in front
of the console: its SPA uses the `Authorization` header for Bearer API calls.

## Backup and restore

`backup.sh` streams a PostgreSQL custom dump into the encrypted Restic
repository on `/mnt-2`, retaining seven daily and four weekly snapshots.
`RESTIC_REPOSITORY` remains configurable in Dockge's `.env`.

```bash
./keycloak/backup.sh
KEYCLOAK_RESTORE_CONFIRM=restore-keycloak-database \
  ./keycloak/restore.sh latest
```

Test restores against a disposable stack first. A failed restore leaves
Keycloak stopped, preventing operation against partial database state.
