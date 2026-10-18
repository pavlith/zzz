# Git workflow

We maintain exactly two long-lived branches:

- `main` — stable releases and production-ready revisions.
- `dev` — all ongoing development. Commit directly to this branch; do not create feature branches.

When a release is ready, run tests and security checks, then merge `dev` into `main` (prefer a reviewed PR `dev -> main`). Never force-push either branch.

Local setup:

```bash
git fetch origin
git switch -c dev --track origin/dev  # first time only
git pull --ff-only
```

Normal development:

```bash
git switch dev
git add .
git commit -m 'feat: description'
git push origin dev
```

Release: create a pull request from `dev` to `main`, review and merge after CI succeeds. Both branches are retained. Remove obsolete feature branches after confirming their commits are reachable from `dev`.
