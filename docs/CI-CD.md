# CI/CD and repository automation

The workflows in `.github/workflows` keep public contributions safe without
placing production credentials in GitHub or in this repository.

## Checks

Every push to `main` and every pull request runs:

- the public-repository leak and forbidden-artifact scanner;
- Go formatting and tests for every Go module;
- TypeScript checks and a reproducible Tailwind frontend build;
- Python and shell syntax checks plus high-severity ShellCheck findings;
- Docker Compose validation for the home and VPS stacks;
- CodeQL for Go, JavaScript/TypeScript, and Python;
- dependency review on pull requests.

Container images are built for pull requests. A push to `main` or a version tag
publishes the custom images to the repository's GitHub Container Registry.

## Dependabot

Dependabot checks GitHub Actions, Go modules, npm dependencies, and Docker base
images every week. Patch and minor Dependabot pull requests are approved and
placed into GitHub's auto-merge queue. They still wait for branch protection
and all required checks; major upgrades always require manual review.

The repository setting **Allow auto-merge** and the Actions permission
**Allow GitHub Actions to create and approve pull requests** must remain
enabled for this workflow.

## Home deployment

Home deployment uses a dedicated self-hosted runner with these labels:

```text
self-hosted, linux, x64, honeypot-home
```

Attach the runner to the protected `production-home` environment. Its service
account needs write access to `/opt/stacks/honeypot-stack` and permission to
run Docker Compose. The workflow preserves the server's `.env` and runtime
state, synchronizes the repository, writes Dockge's authoritative
`compose.yml`, validates it, and recreates changed services.

Require a manual reviewer on `production-home`; never accept pull-request code
on this production runner.

### How files reach the homeserver

The home job runs **on the homeserver itself**. GitHub does not open an inbound
SSH connection to the home network:

1. The permanently installed Actions runner polls GitHub for an approved job.
2. `actions/checkout` downloads the selected repository commit into the
   runner's temporary work directory.
3. Local `rsync` copies that checkout into `/opt/stacks/honeypot-stack`.
4. The workflow copies `docker-compose.yml` to `compose.yml`, which is the
   filename Dockge manages.
5. `docker compose config --quiet` validates the deployed configuration.
6. `docker compose up -d --build` builds local images and reconciles the
   running stack.

The runner therefore needs outbound HTTPS access to GitHub, local filesystem
access to the Dockge stack, and access to the Docker socket. It does not need a
publicly reachable SSH port.

The synchronization uses `--delete-delay`, so repository-controlled files
removed from Git are removed from the destination near the end of a successful
transfer. These host-owned paths are explicitly preserved:

| Preserved path | Reason |
|---|---|
| `.env` | production addresses, credentials, and local settings |
| `logs/` | sensor and imported VPS logs |
| `state/`, `dashboard-state/` | application checkpoints and state |
| `analysis/geoip/*.mmdb` | locally downloaded licensed databases |
| `sandbox/results/` | runtime malware-analysis output |
| `.git/`, `.github/` | not needed by the deployed stack |

The runner's service account, rather than the workflow YAML, determines the
effective host permissions. Register it only on the trusted homeserver and do
not give the `production-home` environment to pull-request workflows.

### honeypot-init

`docker-compose.init.yml` runs as a second, separate Dockge stack at
`/opt/stacks/honeypot-init`, not as part of `honeypot-stack`. It holds the
one-shot bootstrap jobs (log directory ownership, persona seeding,
Elasticsearch/Kibana/Arkime first-run setup) that used to live in the main
compose file; see that file's header for the full reasoning (#111). The same
`home` job deploys it right after `honeypot-stack`, from the same checkout.

Its `.env` is created once by hand on the homeserver and is never touched by
this workflow — `ARKIME_ADMIN_PASSWORD` and `ARKIME_PASSWORD_SECRET` in it
must be kept identical to the same two values in `honeypot-stack`'s `.env`,
and an automated sync has no safe way to verify that a value it did not set
is still correct.

## VPS deployment

Create a protected `production-vps` environment with a required reviewer and
these environment secrets:

| Secret | Purpose |
|---|---|
| `VPS_SSH_KEY` | dedicated deployment private key |
| `VPS_HOST` | VPS hostname or address |
| `VPS_USER` | deployment user, normally `root` |
| `VPS_PORT` | SSH port, normally `2222` |

The workflow preserves `/root/vps/.env`, synchronizes `vps/`, validates
`docker-compose.yml`, and recreates changed services with plain Docker Compose.
Use a dedicated key restricted to the deployment host and rotate it if workflow
logs or repository access are ever compromised.

### How files reach the VPS

The VPS job runs on a short-lived GitHub-hosted Ubuntu runner:

1. `actions/checkout` downloads the selected repository commit.
2. The protected `VPS_SSH_KEY` secret is written to a temporary file with mode
   `0600`.
3. The job constructs SSH options from `VPS_HOST`, `VPS_USER`, and `VPS_PORT`.
   The user defaults to `root` and the port defaults to `2222`.
4. The job snapshots the environment-specific files on the VPS into
   `/root/vps-backups/pre-deploy-<timestamp>.tar.gz`, keeping the ten most
   recent archives.
5. `rsync` sends only the repository's `vps/` directory over SSH to
   `/root/vps/`.
6. A second SSH command runs on the VPS, validates
   `/root/vps/docker-compose.yml`, and executes
   `docker compose up -d --build`.
7. A verification step fails the job if the certificates or `dynamic.yml` are
   missing, empty, unparseable, or still carry placeholder domains.
8. GitHub destroys the hosted runner, including its temporary key file, after
   the job.

### Files the VPS owns, not the repository

`--delete-delay` removes destination files that no longer exist under the
repository's `vps/` directory, and overwrites the ones that do. Three paths are
therefore excluded from synchronization because the VPS copy is authoritative:

| Path | Why it is excluded |
|---|---|
| `.env` | Secrets and host-specific values. |
| `traefik/certs/` | Issued TLS certificates. They do not exist in the repository, so an unexcluded `--delete-delay` deletes them, and the workflow cannot reissue them. |
| `traefik/dynamic.yml` | Carries the deployment's real domain. The committed copy is a `honeypot.example` placeholder, so copying it over the live file leaves every router matching a domain that no requests use. |

All three were lost or overwritten in a single `target: both` run before these
exclusions existed: the certificates were deleted and Traefik fell back to
self-signed, and every router silently stopped matching. Persistent VPS data
must live in named volumes, bind mounts outside `/root/vps`, or one of the
excluded paths above.

When a routing change does need to reach production, edit
`/root/vps/traefik/dynamic.yml` on the VPS directly — Traefik's file provider
watches it and reloads without a restart.

The SSH key is the direct production credential in this path. Restrict it to
the intended VPS, keep it in the protected environment rather than repository
secrets where possible, and require environment approval before the job can
read it.

## Diagnostics

`diagnostics.yml` is the read-only counterpart to `deploy.yml`, and it is
`workflow_dispatch` only. It mirrors the deployment topology: the home job runs
on the `[self-hosted, linux, x64, honeypot-home]` runner, and the VPS job runs
on a GitHub-hosted runner over the same SSH deployment key. Neither changes
anything — they report container state, recent logs, and disk and volume usage.

It exists because the alternative to a scoped read-only workflow is an operator
opening an interactive shell on production to answer a question, and that is
how a diagnosis turns into an accidental change. Keep it read-only. It must
never gain a step that restarts a service, prunes a volume, or writes a file —
if a finding calls for action, the action goes through `deploy.yml` and its
environment approval.

The workflow reads `HP_BIND` and deliberately never prints it: it is an
internal WireGuard address, and the job's output is visible to anyone who can
read the Actions log.

## Delivery paths at a glance

```text
Home:
GitHub -> outbound-polling self-hosted runner on homeserver
       -> local rsync /opt/stacks/honeypot-stack
       -> Dockge compose.yml -> docker compose up

VPS:
GitHub-hosted runner -> rsync + SSH over VPS_PORT
                     -> /root/vps
                     -> docker compose up on VPS
```

Selecting `both` creates both jobs from the same workflow run. They share the
`honeypot-production` concurrency group, but the home and VPS jobs are
otherwise independent: one can fail while the other succeeds. Always inspect
both job results before calling a two-target deployment complete.

## Running a deployment

Open **Actions → Deploy → Run workflow**, select `home`, `vps`, or `both`, then
approve the relevant protected environment. Deployments are intentionally
manual; a push to a public repository never changes production by itself.

The workflow deploys the commit selected in the **Run workflow** dialog,
normally the current `main`. Merging a pull request starts checks and container
publishing, but does not invoke `Deploy`; an operator must dispatch it
separately.

For each target, verify the run after Compose finishes:

- the deployment job used the expected commit SHA;
- `docker compose ps` shows the intended services running and healthy;
- Dashboard, EveBox, Kibana, and Arkime respond where applicable;
- Filebeat and Elasticsearch report no output errors;
- source timestamps and indexed document counts continue advancing.

If the home runner is offline, the home job remains queued. If an environment
approval is missing, the job waits before gaining access to that environment's
secrets or runner. A VPS authentication failure stops before the remote Compose
command; a Compose validation failure stops before services are reconciled.
