# Go Modules adversary

Reviews Go module metadata for reproducibility, upgrade safety, and maintainable dependency ownership.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It evaluates Go module metadata for reproducibility, checksum protection, vulnerable versions, replacement directives, and dependency graph integrity.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It owns only this Go specialty. Other Go concerns remain with the corresponding `go/*` adversaries, and it does not execute or modify the target repository.
