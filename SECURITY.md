# Security policy

## Reporting

Email **security@group-space.com** with enough detail to reproduce. We would
rather receive a duplicate, a false alarm, or a doc nitpick than not receive a
real one. Reports that the documentation claims more than the code delivers
are in scope and welcome.

Please do not open a public issue for anything you believe is exploitable
before we have had a chance to respond. We aim to acknowledge within 72 hours.

## Scope

- The protocol and its implementation in this repository (`src/`, `sw/`).
- The published npm artifacts and their provenance chain.
- The claims made in `docs/`. An overclaim is a vulnerability in the
  documentation.

Out of scope here (report to the same address, different tracker): the Group
Space application, its servers, and its deployments.

## Supported versions

Format v1 is the only wire format and is frozen (see `docs/protocol.md` §8).
Security fixes land on the latest minor release; there are no long-term
support branches. A fix that cannot be made without breaking the wire format
would be handled as a coordinated migration, not a patch.

## What we will not do

Silently change sealed formats, weaken parameters for compatibility, or
describe an unfixed issue as fixed. If a report forces a trade-off, the
trade-off gets written down where users can read it.
