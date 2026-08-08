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
2. Create `KEYCLOAK_SECRETS_DIR` with mode `0700`.
3. Create `postgres-password`, `bootstrap-admin-password`, and
   `restic-password` with independent random values and mode `0600`.
4. Set `KEYCLOAK_THEME_DIR` to the reviewed auth-backend
   `themes/apiary` directory.
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
public issuer hostname. VPS Traefik applies file-backed bcrypt BasicAuth and a
tighter rate limit to the entire admin hostname before forwarding to Keycloak.
Keycloak then independently requires an administrator account and MFA. Create
the outer credential interactively on the VPS as documented in
`vps/.env.example`; never commit the htpasswd file or reuse a Keycloak password.

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
