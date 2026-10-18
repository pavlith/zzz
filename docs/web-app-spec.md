# Web application implementation specification — Svelte 5

**Status: NOT IMPLEMENTED.** Target: SvelteKit + Svelte 5 runes, TypeScript strict, shadcn-svelte, pnpm, responsive UI and an audited WebCrypto integration. Backend current development auth is **not safe** for live credentials.

## Proposed structure
```
web/
  src/
    routes/               # SvelteKit authenticated layouts and pages
    lib/
      api/                # generated OpenAPI client and errors
      crypto/             # browser crypto adapter and test vectors
      auth/               # session, unlock, trusted device state
      sync/               # IndexedDB encrypted cache and queue
      components/ui/      # shadcn-svelte primitives
      features/           # vaults, items, devices, members, rotation, audit
      stores/             # typed Svelte 5 state
    app.html
  tests/unit/
  tests/e2e/
```

## Product journeys and acceptance
1. **Onboard/login/unlock:** account creation/login only after audited backend authentication; trusted device pairing and recovery. Secrets never pass through SSR load functions, analytics or server-side rendering.
2. **Vault dashboard:** workspace/vault navigation, members, invite/revoke/permissions, clear separation between ACL Read and cryptographic access.
3. **Items:** create/edit/delete/reveal/copy, password generator, encrypted revisions, client-side search, tags/folders and activity states; app always encrypts locally before sending bytes.
4. **Sync:** explicit online/offline status, encrypted local cache, retry/idempotency, conflict dialog, tombstone retention, epoch-change resync.
5. **Security center:** manage devices, revoke sessions, enrollment verification, signed commitments, compare checkpoints, rotation/preflight/status/history and recovery.
6. **Accessibility/i18n:** keyboard navigation, screen readers, ru/en, small mobile browser and desktop widths, reduced motion, secure clipboard policies.

## Browser security rules
- Prefer HttpOnly Secure SameSite session cookies with CSRF protections; never persist dev bearer credentials to localStorage.
- Generate/derive secrets using reviewed WebCrypto and strong CSPRNG; document extractable/nonextractable key trade-offs, XSS hazards and impossibility of reliable JS memory zeroization.
- Encrypt sensitive IndexedDB data. Never cache plaintext in service workers, SSR, URL, logs, errors or telemetry.
- CSP, dependency audit, secure headers, anti-clickjacking and DOM XSS prevention; shadcn-svelte components are not an automatic security control.
- Never market browser-based key handling as equivalent to hardware-backed mobile secure enclave without evidence.
- App build must fail on TypeScript, lint, unit/integration/browser E2E, Go-Web crypto vector and API contract errors.

## Deployment decision
SvelteKit deployment mode (static vs server) remains an ADR. Secrets must stay in browser execution context regardless. HTTPS and secure origins mandatory. No PWA offline plaintext storage by default; enable only after threat review.

## Milestones
M5-01 scaffold; M5-02 UX system; M5-03 auth/devices; M5-04 crypto/keyring; M5-05 vault management; M5-06 items; M5-07 sync; M5-08 rotation/recovery; M5-09 a11y/hardening; M5-10 Playwright. Refer to [canonical roadmap](roadmap-backend-web.md).
