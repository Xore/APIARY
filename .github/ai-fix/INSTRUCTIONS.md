# AI Fix Instructions — honeypot-stack

Generated: 2026-07-26

This folder contains context and instructions for an AI agent to resolve all open Dependabot pull requests and any security alerts in this repository.

---

## Open Pull Requests (7 total — all from Dependabot)

All PRs are dependency bumps with no conflicts. They target the `main` branch and were all opened on 2026-07-26.

### Actions: GitHub Actions upgrades

| PR | Title | Branch | Safe to merge? |
|----|-------|--------|----------------|
| [#2](https://github.com/Xore/honeypot-stack/pull/2) | Bump `actions/checkout` from 6 → 7 | `dependabot/github_actions/actions/checkout-7` | ✅ Yes — security fix, blocks unsafe fork PR checkout |
| [#3](https://github.com/Xore/honeypot-stack/pull/3) | Bump `dependabot/fetch-metadata` from 2.3.0 → 3.1.0 | `dependabot/github_actions/dependabot/fetch-metadata-3.1.0` | ✅ Yes — Node 24 runtime upgrade |
| [#4](https://github.com/Xore/honeypot-stack/pull/4) | Bump `docker/login-action` from 3 → 4 | `dependabot/github_actions/docker/login-action-4` | ✅ Yes — Node 24 runtime, minor security patches |
| [#6](https://github.com/Xore/honeypot-stack/pull/6) | Bump `actions/setup-go` from 6 → 7 | `dependabot/github_actions/actions/setup-go-7` | ✅ Yes — ESM migration, Node 24 |
| [#7](https://github.com/Xore/honeypot-stack/pull/7) | Bump `actions/dependency-review-action` from 4 → 5 | `dependabot/github_actions/actions/dependency-review-action-5` | ✅ Yes — Node 24 runtime, security findings resolved |

### npm: Frontend dependency upgrade

| PR | Title | Branch | Notes |
|----|-------|--------|-------|
| [#5](https://github.com/Xore/honeypot-stack/pull/5) | Bump `typescript` from 5.9.3 → 7.0.2 in `/dashboard/frontend` | `dependabot/npm_and_yarn/dashboard/frontend/typescript-7.0.2` | ⚠️ Major version jump (5→7). Review breaking changes in TS 6.0 and 7.0 before merging. Check `tsconfig.json` and any deprecated compiler options. |

### Docker: Base image upgrade

| PR | Title | Branch | Notes |
|----|-------|--------|-------|
| [#9](https://github.com/Xore/honeypot-stack/pull/9) | Bump `alpine` in `/dashboard` from 3.20 → 3.24 | `dependabot/docker/dashboard/docker-37a3415c43` | ✅ Yes — patch/minor Alpine update, safe for Docker base image |

---

## Instructions for AI Agent

### Step 1 — Safe merges (GitHub Actions + Docker)

Merge the following PRs directly using squash or merge commit. No code changes needed:

```bash
# Via GitHub CLI
gh pr merge 2 --squash --repo Xore/honeypot-stack
gh pr merge 3 --squash --repo Xore/honeypot-stack
gh pr merge 4 --squash --repo Xore/honeypot-stack
gh pr merge 6 --squash --repo Xore/honeypot-stack
gh pr merge 7 --squash --repo Xore/honeypot-stack
gh pr merge 9 --squash --repo Xore/honeypot-stack
```

Or trigger via Dependabot comment on each PR:
```
@dependabot merge
```

### Step 2 — TypeScript major version bump (PR #5)

This is a **breaking change** (TypeScript 5 → 7). Before merging:

1. Check out the branch:
   ```bash
   git fetch origin dependabot/npm_and_yarn/dashboard/frontend/typescript-7.0.2
   git checkout dependabot/npm_and_yarn/dashboard/frontend/typescript-7.0.2
   ```

2. Run the TypeScript compiler in the frontend directory:
   ```bash
   cd dashboard/frontend
   npx tsc --noEmit
   ```

3. Fix any type errors surfaced by the stricter TypeScript 6/7 rules (especially around `noImplicitAny`, ESM module resolution, and removed legacy options).

4. Commit fixes to the branch and push, then merge.

### Step 3 — Security Alerts

GitHub Dependabot security alerts are not accessible via the public REST API without admin token scopes. To check:

1. Visit: https://github.com/Xore/honeypot-stack/security/dependabot
2. For each alert, check if the relevant dependency upgrade above already resolves it.
3. If additional alerts exist outside of the current PRs, create new fix branches targeting the vulnerable `package.json`, `Dockerfile`, or workflow files.

Known security-relevant upgrades already covered by open PRs:
- `actions/dependency-review-action` v5 resolves upstream security findings (PR #7)
- `docker/login-action` v4 patches `@actions/core`, `js-yaml`, and `brace-expansion` (PR #4)
- `actions/checkout` v7 blocks unsafe fork PR checkout vulnerability (PR #2)

---

## Repository Context

- **Stack**: Docker Compose honeypot stack (Conpot, Suricata, Arkime, etc.)
- **Dashboard**: Vue/TypeScript frontend in `/dashboard/frontend`
- **CI/CD**: GitHub Actions workflows in `.github/workflows/`
- **Base images**: Alpine Linux
- **Default branch**: `main`

## Priority Order

1. 🔴 Security-related GitHub Actions upgrades (PRs #2, #4, #7) — merge immediately
2. 🟡 Runtime/tooling upgrades (PRs #3, #6) — merge after CI passes
3. 🟡 Docker base image (PR #9) — merge after local test
4. 🟠 TypeScript major bump (PR #5) — requires manual review and potential code fixes
