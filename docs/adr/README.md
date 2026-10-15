# Architecture Decision Records

Significant design decisions are recorded here, one file per decision,
numbered in order: `NNNN-short-title.md`. A record is never rewritten after
it is accepted; a later record supersedes it.

Write a record when a change alters a trust boundary, a cryptographic
suite, a wire or storage format, the disclosure gate, a public API, or a
dependency that handles plaintext or keys.

## Template

```markdown
# NNNN. Title

* Status: Proposed | Accepted | Superseded by NNNN
* Date: YYYY-MM-DD

## Context

The problem and the forces at play.

## Decision

What we will do.

## Consequences

What becomes easier or harder, and what must now be true.
```

## Records

* [0001. Hybrid post-quantum cryptographic suites](0001-hybrid-post-quantum-suites.md)
* [0002. Refuse grouping sets and positional subsets in the disclosure gate](0002-refuse-grouping-sets-and-positional-subsets.md)
* [0003. Connector data as versioned snapshots](0003-connector-data-as-versioned-snapshots.md)
* [0005. Query and deployment topology](0005-query-topology.md)
