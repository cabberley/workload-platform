# 0015. Citrix (and connector) dependency-edge merge is deferred; connectors contribute node annotations only

Date: 2026-08-07 · Status: accepted

## Context

Issue #48 delivers a read-only, keyless, fail-closed **Citrix control-plane connector** for the
Dependency & Blast Radius module (`dependency_graph`). It is built on the shared connector framework
(ADR 0004) as a defensive twin of the Discovery *Kuiper* connector (#47), and — like Kuiper — it is
inert until a human wires an APPROVED https endpoint.

Citrix naturally produces two kinds of signal:

1. **Host/session health** (`host-health`) — a bounded, closed-vocabulary health token for a
   Citrix-managed host that ALREADY exists in the estate as a `ResourceNode`.
2. **Session/host dependency** (`session-dependency`) — a directed "A depends on B" relationship
   between two estate resources, i.e. a candidate `DependencyEdge`.

The obvious next step — feeding (2) into the workload graph as new edges — is **unsafe today**, for
a structural reason that is independent of Citrix and applies to every connector:

> **Graph-replace hazard.** The `dependency_graph` module computes the authoritative `graph`
> (nodes + auto edges derived from network topology + pack-resolved edges) and hands it to the state
> writer, which **UPSERT-REPLACES the entire `WorkloadGraph` for the workload** (`shared.state`
> `_write_graph` / the Azure commit path). The persisted graph is whatever the module returns from a
> run — there is no additive edge-merge semantics at the persistence layer.

Consequently, if a connector emitted its own edges into the returned graph, those edges would be
persisted **in place of** — not alongside — the authoritative auto/pack edges only if the module
merged them into its single returned graph; and any code path that returned a connector-derived
graph *instead of* the module's would **wipe** the authoritative edge set. A naive connector→edge
integration is therefore a data-loss foot-gun. This is exactly why the Kuiper connector (#47)
deferred edge integration and contributed supplemental **node** annotations only.

## Decision

**1. Connectors contribute supplemental NODE annotations only; they never mutate the edge set.**
The Citrix connector applies its `host-health` signals as bounded, fixed-vocabulary **tags on an
existing estate node**, matched by **exact node id** (`apply_supplemental`):

- `aegis:source` — the connector-provenance marker, treated as a sorted, comma-joined **set** of
  contributing connectors so Citrix is unioned in additively (e.g. `citrix,kuiper`) and never
  clobbers another connector's provenance, and
- `aegis:citrix-health = <one of {healthy, degraded, unreachable, maintenance}>` (closed
  vocabulary).

A signal whose `resourceId` does not match an existing node id is **dropped** (no node is ever
created, renamed, retyped, or removed). This is non-destructive by construction: the node/edge
*sets* are unchanged; only additive tags on already-authoritative nodes are added. Health tags do
not participate in the graph-replace hazard because they do not alter which nodes or edges exist.

**2. Dependency edges are parsed but NOT persisted — deferred behind a `TODO(human)` + this ADR.**
`session-dependency` signals are validated and mapped to a **pure, in-memory** list of
`DependencyEdge` objects by `connectors.citrix.dependency_edges(...)` (origin `connector:citrix`,
provenance `SourceReference` of kind `citrix`). This function is a **pure mapping returned for
future use** — it is deliberately **never merged into the returned graph** and never reaches the
state writer. The non-destructive merge (union connector edges with authoritative auto/pack edges,
de-dupe, preserve authoritative origins, and only then persist) is owned by the `dependency_graph`
module and is left as a documented `TODO(human)`.

**3. The module hook is strictly additive, default-off, and fail-closed.** `dependency_graph`
consumes the connector only if an operator injects it under the well-known client key `citrix`
(`ModuleContext.clients["citrix"]`). When it is absent — the default — the module runs **exactly as
before** (byte-for-byte identical graph). When present, the hook:

- runs **after** node resolution and **before** graph assembly, applying only health annotations;
- treats ANY connector failure (fail-closed `available=False`, exceptions, empty/unusable signals)
  as "estate-only graph" and continues — a Citrix problem can never break the module;
- surfaces a bounded, PII-free human-readable note (error **class name only**, never a body/token).

## Consequences

- **+** No data-loss risk: the authoritative auto/pack edge set is untouched; connectors can only
  *add tags to nodes that already exist*. The module's persisted graph is identical to today unless
  a matching health signal is present, in which case it differs only by additive node tags.
- **+** Off-by-default and fail-closed: absent/disabled/misconfigured Citrix leaves the module's
  behaviour unchanged; the connector stays inert until a human wires an APPROVED endpoint.
- **+** The edge-mapping logic is written, tested, and ready (`dependency_edges`), so the future
  non-destructive merge is a small, well-scoped change rather than new ground-up work.
- **−** Citrix (and Kuiper) dependency edges are **not yet reflected** in the blast-radius graph;
  their value is realised only once the module implements the additive merge. Until then the
  connectors are health-annotation sources.
- **−** Introducing the merge later requires the module (not the connector) to own union/de-dupe
  semantics and to decide precedence between connector-derived and authoritative edges — an
  intentional, reviewable change captured by the `TODO(human)` and this ADR.

## TODO(human)

- **Non-destructive edge merge (owner: `dependency_graph` module).** Implement an additive merge of
  `connectors.citrix.dependency_edges(...)` (and the equivalent Kuiper hints) into the workload
  graph that unions with, never replaces, the authoritative auto/pack edges, de-dupes, preserves
  authoritative origins, and only then persists. Update this ADR when done.
- **Real Citrix contract (owner: product team).** The concrete Citrix endpoint, request path,
  response envelope, payload/hint schema, and auth scheme are an external dependency. The connector
  currently uses clearly-labelled synthetic placeholders and a mock `TokenProvider`; confirm and
  replace them (with a follow-up ADR revision) once the Citrix contract arrives.
