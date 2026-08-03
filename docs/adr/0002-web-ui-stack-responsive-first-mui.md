# 0002. Web UI stack: React + Vite + TypeScript, responsive‑first on MUI

Date: 2026-08-03 · Status: accepted

## Context

The platform ships a single web app for the read models, dependency graph and blast‑radius views.
On‑call engineers must be able to triage blast radius from a **phone** as well as a desktop, so the
UI has to be first‑class on both form factors — not a desktop app with a cramped mobile fallback.

The repo is built by a **team of Copilot coding agents**, each owning a lane and landing reviewable
PRs. The UI layer therefore has to optimise for **cross‑agent consistency, accessibility as a
Definition‑of‑Done gate (WCAG AA), and type‑checked reviewability**, in addition to a good end‑user
experience on mobile and desktop. `ARCHITECTURE.md` already fixes the base stack as
**React + Vite + TypeScript**; the open question was the layout/component system.

## Decision

- Keep **React + Vite + TypeScript** as the base and build **responsive‑first**: one SPA serves
  phone → desktop (no separate mobile build), with Vite code‑splitting + lazy routes to keep the
  mobile bundle small.
- Adopt **MUI (Material UI)** as the **default component library**:
  - semantic, **typed** components (`<Button>`, `<DataGrid>`, `<Drawer>`) keep independently‑authored
    modules visually and structurally consistent, and wrong props fail `tsc` / review rather than
    drifting silently;
  - ARIA/roles and focus handling are built in, so the **WCAG AA** DoD is met with far less manual
    `aria-*` wiring by agents;
  - `Grid` + `useMediaQuery` + breakpoints provide responsive layout out of the box; a single central
    theme enforces `meta viewport`, ≥44 px touch targets, no hover‑only actions and mobile nav
    (drawer / bottom bar).
- Ship as an installable **PWA** (`vite-plugin-pwa`) with an offline read cache of the last
  assessment; reach for **Capacitor** only if an app‑store presence is later required.
- Client stays **in‑boundary & keyless**: users sign in with **Entra ID (MSAL)** (no secrets in the
  browser); the FastAPI core continues to use **Managed Identity** for all Azure calls; no PHI/PII
  persists locally beyond the ephemeral, opt‑in read cache.
- **Tailwind + shadcn/ui** is the **sanctioned alternative** where a lighter, fully‑custom look is
  needed, accepting the trade‑offs below.

## Consequences

- **+** Consistent, accessible UI across many agents with minimal per‑PR review friction.
- **+** One responsive codebase covers mobile and desktop; on‑call triage works from a handset.
- **+** Typed components + central theme make UI changes reviewable and hard to drift.
- **+** In‑boundary/keyless posture holds on the client (Entra ID in, Managed Identity at the core).
- **−** Heavier bundle and a more opinionated visual language than utility‑first CSS.
- **−** Escaping MUI's design language for bespoke visuals means dropping to the Tailwind + shadcn/ui
  alternative, i.e. a second styling idiom to maintain.
