# go/modules — issue catalog

This document is the **issue catalog** for this adversary: the classes of defects we aim to find, how we detect them (static vs LLM), public pattern references, and staff priority (P0 / P1 / LLM-only / Cut).

It is documentation and roadmap for contributors — not a runtime contract. Implemented detectors live in `src/` with fixtures under `fixtures/`; the **Review verdicts** section records what ships first.

Public examples cited below illustrate bad patterns only. Do not scrape secrets from them or copy copyrighted code into fixtures.

**Catalog id:** `go/modules`  
**Status:** public OSS documentation of the issue classes this adversary targets  
**Goal:** trusted, high-precision detections. Prefer missing a weak signal over a false positive.

## Mission
Reproducible, secure Go module graphs: tidy sums, safe replaces, toolchain pins, vulnerability awareness.

## LLM strategy (required for world-class)
**Enhance:** explain upgrade/replace risk.
**Discover:** typosquats and retract gaps (low confidence).

### Division of labor
Static = precise facts. LLM = enhancement + evidence-gated discovery. When unsure, omit.

## Review verdicts (staff pass)

- **P0 implement:** `replace.local`, `sum.missing`, `cve.known`, `checksum.database-off`
- **P1:** `replace.fork-stale`, `exclude.abuse`, `toolchain.missing`, `go-version.too-old`, `tidy.drift`, `pseudo-version`, `retract.ignored`, `path.major-suffix`, `workspace.committed`, `vendor.drift`, `toolchain.local`, `version.incompatible`, `tools.undeclared`
- **LLM-only:** none — module analysis is deterministic; keep it that way.
- **Cut:** `retract.missing` — author-side concern needing a vuln DB; the consuming side is covered by `retract.ignored`. `indirect.direct-needed` — absorbed into `tidy.drift`. `license.unknown` — separate product domain; defer to license tooling. `goprivate.missing` — no reliable way to know a host is private. `retract.minors` — upgrade-process advice, not a repo defect. `cyber.typosquat` — one FP against a legitimate package is product-killing; revisit only with curated data. `retract.main-package` — style opinion.
- **Renamed:** `sum.outdated` → `tidy.drift`; `retract.wrong-module` → `path.major-suffix`; `retract.ambiguous-tags` → `version.incompatible`; `retract.unused-tools` → `tools.undeclared` (the `retract.*` prefixes were wrong).

## Issue catalog

---
### 1. `go-mod.replace.local` — replace directives left in module for publish

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** replace => ../local breaks consumers.

**Static detection.** Detect replace to relative paths.

**LLM role.** Allow go.work for local.

**False-positive guards.** Intentional forks documented.

**Public examples of the bad pattern:**
  - https://go.dev/ref/mod#go-mod-file-replace
  - https://go.dev/doc/modules/managing-dependencies
  - https://github.com/golang/go/wiki/Modules

---
### 2. `go-mod.replace.fork-stale` — replace to stale forks

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Security lag on replaced modules.

**Static detection.** Detect replace to random forks.

**LLM role.** LLM risk.

**False-positive guards.** Maintained mirrors.

**Public examples of the bad pattern:**
  - https://go.dev/ref/mod#go-mod-file-replace
  - https://go.dev/blog/vuln
  - https://github.com/golang/go/wiki/Modules

---
### 3. `go-mod.exclude.abuse` — exclude hides security updates

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** exclude of patched versions.

**Static detection.** Detect exclude blocks.

**LLM role.** LLM why.

**False-positive guards.** Breakage workarounds documented.

**Public examples of the bad pattern:**
  - https://go.dev/ref/mod#go-mod-file-exclude
  - https://go.dev/doc/modules/managing-dependencies
  - https://github.com/golang/vuln

---
### 4. `go-mod.toolchain.missing` — No toolchain directive for reproducibility

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | medium |

**What it is.** Builds differ by developer Go version.

**Static detection.** Detect missing toolchain in go.mod go1.21+.

**LLM role.** Recommend pin.

**False-positive guards.** Libs defer to consumers.

**Public examples of the bad pattern:**
  - https://go.dev/doc/toolchain
  - https://go.dev/ref/mod#go-mod-file-toolchain
  - https://github.com/golang/go/issues/57001

---
### 5. `go-mod.go-version.too-old` — go directive far behind

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Misses language/security fixes.

**Static detection.** Parse go directive; flag only when older than the oldest supported Go release (two majors back), scaling severity with distance — anything newer is noise.

**LLM role.** Soft finding.

**False-positive guards.** Frozen maintenance branches.

**Public examples of the bad pattern:**
  - https://go.dev/doc/devel/release
  - https://go.dev/ref/mod#go-mod-file-go
  - https://github.com/golang/go

---
### 6. `go-mod.sum.missing` — Committed go.mod without go.sum

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** Integrity missing.

**Static detection.** File existence.

**LLM role.** Require sum for apps.

**False-positive guards.** Non-module mode rare.

**Public examples of the bad pattern:**
  - https://go.dev/ref/mod#go-sum-files
  - https://go.dev/doc/modules/managing-dependencies
  - https://github.com/golang/go/wiki/Modules

---
### 7. `go-mod.tidy.drift` — go.mod/go.sum not tidy (tidy drift)

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Extra/missing sums, unused requires, and used-but-indirect deps (absorbs former `go-mod.indirect.direct-needed`) — one rule: the module graph does not match the source.

**Static detection.** Run `go mod tidy -diff` (Go 1.23+) in check mode and report the diff as evidence.

**LLM role.** CI suggestion.

**False-positive guards.** Generated noise.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/cmd/go#hdr-Add_missing_and_remove_unused_modules
  - https://go.dev/ref/mod#go-sum-files
  - https://github.com/golang/go/wiki/Modules

---
### 8. `go-mod.pseudo-version` — Many pseudo-versions of important deps

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | medium |

**What it is.** Supply-chain churn.

**Static detection.** Detect pseudo-version strings for direct deps.

**LLM role.** Prefer tagged releases.

**False-positive guards.** Actively developed monorepos.

**Public examples of the bad pattern:**
  - https://go.dev/ref/mod#pseudo-versions
  - https://go.dev/doc/modules/version-numbers
  - https://github.com/golang/go/wiki/Modules

---
### 9. `go-mod.retract.ignored` — Consuming retracted versions

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** require retracted version.

**Static detection.** Parse retract directives of dependencies — requires module proxy access or a vendored retraction snapshot; mark as check-mode rule.

**LLM role.** Upgrade.

**False-positive guards.** None.

**Public examples of the bad pattern:**
  - https://go.dev/ref/mod#go-mod-file-retract
  - https://go.dev/blog/vuln
  - https://pkg.go.dev

---
### 10. `go-mod.cve.known` — Known vulnerable module versions

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** govulncheck integration.

**Static detection.** Plan: invoke vuln DB offline data.

**LLM role.** Must be precise.

**False-positive guards.** Vuln not reachable — still note.

**Public examples of the bad pattern:**
  - https://github.com/golang/vuln
  - https://go.dev/blog/vuln
  - https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck

---
### 11. `go-mod.path.major-suffix` — Module path mismatch with import path

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** Major version suffix issues.

**Static detection.** Detect v2+ without /v2 path.

**LLM role.** Hard go rules.

**False-positive guards.** Exceptions rare.

**Public examples of the bad pattern:**
  - https://go.dev/blog/v2-go-modules
  - https://go.dev/ref/mod#major-version-suffixes
  - https://github.com/golang/go/wiki/Modules#semantic-import-versioning

---
### 12. `go-mod.workspace.committed` — go.work committed accidentally

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | high |

**What it is.** Breaks consumers/CI.

**Static detection.** Detect go.work in git without go.work.sum policy.

**LLM role.** Recommend gitignore.

**False-positive guards.** Monorepo intentional with docs.

**Public examples of the bad pattern:**
  - https://go.dev/ref/mod#workspaces
  - https://github.com/github/gitignore
  - https://go.dev/blog/get-familiar-with-workspaces

---
### 13. `go-mod.vendor.drift` — vendor/ out of sync

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** When vendor present.

**Static detection.** Need go mod vendor check plan.

**LLM role.** CI.

**False-positive guards.** No vendor.

**Public examples of the bad pattern:**
  - https://go.dev/ref/mod#vendoring
  - https://pkg.go.dev/cmd/go#hdr-Make_vendored_copy_of_dependencies
  - https://github.com/golang/go/wiki/Modules

---
### 14. `go-mod.toolchain.local` — toolchain local hides version

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Non-reproducible.

**Static detection.** Detect toolchain local.

**LLM role.** Pin version.

**False-positive guards.** Dev only.

**Public examples of the bad pattern:**
  - https://go.dev/doc/toolchain
  - https://go.dev/ref/mod#go-mod-file-toolchain
  - https://github.com/golang/go

---
### 15. `go-mod.version.incompatible` — +incompatible versions

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Legacy path issues.

**Static detection.** Detect +incompatible.

**LLM role.** Modernize.

**False-positive guards.** Unavoidable legacy.

**Public examples of the bad pattern:**
  - https://go.dev/ref/mod#incompatible-versions
  - https://go.dev/blog/v2-go-modules
  - https://github.com/golang/go/wiki/Modules

---
### 16. `go-mod.tools.undeclared` — tool directive / tools.go pattern missing for generators

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | low |

**What it is.** Reproducible codegen.

**Static detection.** Detect //go:generate without tool deps.

**LLM role.** go 1.24 tool directive.

**False-positive guards.** Global tools intentional.

**Public examples of the bad pattern:**
  - https://go.dev/doc/modules/managing-dependencies
  - https://github.com/golang/go/issues/48429
  - https://pkg.go.dev/cmd/go

---
### 17. `go-mod.checksum.database-off` — GOSUMDB off in project docs/scripts

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** Integrity disabled.

**Static detection.** Detect GOSUMDB=off, GONOSUMDB/GONOSUMCHECK, GOINSECURE, and GOPRIVATE=* in scripts, CI, Dockerfiles, and Makefiles.

**LLM role.** Hard warn.

**False-positive guards.** Private airgap with alternative verification.

**Public examples of the bad pattern:**
  - https://go.dev/ref/mod#checksum-database
  - https://go.dev/blog/module-mirror-launch
  - https://github.com/golang/go/wiki/Modules

---

## Implementation roadmap (after approval)
P0 static rules + fixtures → LLM enhancement → discovery → precision bake-off on public repos.

**P0 priorities:** relative replace, missing go.sum, known vulns (govulncheck), GOSUMDB/GOINSECURE disabled.
