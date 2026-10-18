# Implementation plan

**Canonical task tracker:** [Backend + Web Roadmap](roadmap-backend-web.md). This file is an execution overview, not an independent stale backlog.

## Confirmed current baseline
Backend API and tests exist for workspaces, vault ACL, items/revisions, sync, device trust, envelopes, staged rotation, signed acknowledgements, commitments and an experimental hash-chain transparency export. Experimental Go E2EE envelope library exists in `pkgs/e2ee`. There is **no Svelte web client**, no complete production login, no reviewed interoperable E2EE protocol and **no active key-epoch rotation**.

## Milestone progression
M0 contracts/threat model → M1 backend hardening and database migrations → M2 production identity/devices → M3 reviewed Go+Web crypto → M4 durable sync/rotation/transparency → M5 Svelte 5 web end-to-end features → M6 security audit, deployment and release.

Work can overlap except for strict security dependencies: don't connect the web app to live credentials until M2/M3 gates pass; don't implement actual activation until M3/M4 reviewed conditions pass.

## Workflow
Every issue/task should refer to an ID from the canonical roadmap (M0-01 etc), identify acceptance criteria and test coverage, update docs/OpenAPI and pass CI. Work directly on `dev`, do not change `main` during development. Release only after separate review.
