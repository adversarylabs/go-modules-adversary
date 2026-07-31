# Go Modules adversary

Go Modules reviews dependency metadata for reproducibility, upgrade safety, and maintainable ownership.

The initial review covers local replacements, mutable branch replacements, and exclusions that preserve undocumented compatibility constraints.

## Fixtures and calibration

Five graded module fixtures own expected review snapshots. The 61-repository corpus calibrates module graph and reproducibility decisions.

## Automatic detection

`adversary auto` selects Go Modules when `go.mod`, `go.sum`, `go.work`, workspace sums, or vendor module metadata changes.

## Development

Run `npm test`, `adversary validate .`, and `adversary pack --check .`.

## Issue catalog

What this adversary targets (P0 / P1 / LLM-only priorities, detection notes, and public pattern references) is documented in [docs/issue-catalog.md](docs/issue-catalog.md).
