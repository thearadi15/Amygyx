# Initial architecture decisions

## ADR-001: Monorepo for the MVP

**Decision:** Keep the React frontend and FastAPI backend in one repository.

**Reason:** A solo developer can change and review API contracts, UI behavior, tests, and documentation in one pull request. Split repositories only if ownership or release requirements later justify it.

## ADR-002: Modular monolith first

**Decision:** Begin with one API application and clear internal module boundaries.

**Reason:** Avoid distributed-system overhead before real ingestion volume and deployment needs are known.

## ADR-003: Localhost-first development

**Decision:** Bind development servers to 127.0.0.1 by default and use explicit local CORS origins.

**Reason:** Reduce accidental network exposure during early development. Production hosting requires a separate deployment and security review.

## ADR-004: Explainable detectors before custom AI

**Decision:** Begin with deterministic parsers and rules; evaluate ML models against documented datasets before production use.

**Reason:** Findings need evidence and measurable quality, not just an opaque model score.

## Dependency locking

Lockfiles are intentionally generated with the package managers on a network-enabled development machine. Commit both `services/api/uv.lock` and `apps/web/package-lock.json`; CI uses locked installation and fails if lockfiles are missing or out of sync. Do not hand-author lockfiles.
