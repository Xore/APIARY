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

## Running a deployment

Open **Actions → Deploy → Run workflow**, select `home`, `vps`, or `both`, then
approve the relevant protected environment. Deployments are intentionally
manual; a push to a public repository never changes production by itself.
