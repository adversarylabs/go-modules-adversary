# Checks — what go/modules detects

This file is the **public audit list** of detectors. If a rule id appears here, it is part of the product surface: it should fire on a vulnerable pattern, stay quiet on the documented clean case, and produce file:line evidence where applicable.

Runtime source of truth: [`src/domain.ts`](src/domain.ts).
Regression entry: graded module fixtures under `test/`.

**Scope:** `go.mod`, `go.sum`, `go.work`, `go.env`, and related env/CI files that affect module verification.

---

## Critical

### `go-modules.cve-known`

| | |
| --- | --- |
| **What** | Required module version is known-vulnerable |
| **Why** | Published vulns remain exploitable until upgraded |
| **Looks for** | require pins listed in offline vuln table |
| **Stays quiet when** | Fixed version of the module |
| **Fixture** | `fixtures/` |
| **Remediation** | Upgrade and `go mod tidy` |

## High

### `go-modules.local-replace`

| | |
| --- | --- |
| **What** | Local replace outside published graph |
| **Why** | Consumers cannot reproduce the graph |
| **Looks for** | `replace` → filesystem path |
| **Stays quiet when** | Published version or private go.work only |
| **Remediation** | Do not commit machine-local replaces |

### `go-modules.sum-missing`

| | |
| --- | --- |
| **What** | go.mod with requires but no go.sum |
| **Why** | No cryptographic pin of module contents |
| **Looks for** | Versioned requires without go.sum |
| **Stays quiet when** | Committed go.sum beside go.mod |
| **Remediation** | Run `go mod tidy` and commit go.sum |

### `go-modules.checksum-database-off`

| | |
| --- | --- |
| **What** | Go checksum database disabled |
| **Why** | Removes independent hash attestation |
| **Looks for** | `GOSUMDB=off` or broad GONOSUMDB/GOINSECURE |
| **Stays quiet when** | sum.golang.org enabled; GOPRIVATE for private hosts |
| **Remediation** | Do not disable GOSUMDB globally |

## Medium

### `go-modules.branch-replace`

| | |
| --- | --- |
| **What** | Replacement tracks mutable branch state |
| **Why** | Two installs can resolve different code |
| **Looks for** | replace to branch-like revisions |
| **Stays quiet when** | Tagged version or pseudo-version + sum |
| **Remediation** | Pin immutable revisions |

### `go-modules.same-module-replace`

| | |
| --- | --- |
| **What** | Unversioned same-module replacement overrides a required module |
| **Why** | The replacement applies to every selected version, including later upgrades |
| **Looks for** | `require M vCurrent` with `replace M => M vTarget` |
| **Stays quiet when** | Local replacements, forks, version-specific replacements, or no matching require |
| **Remediation** | Require the target version directly, or document the deliberate global override |

### `go-modules.exclude`

| | |
| --- | --- |
| **What** | exclude hides compatibility constraint |
| **Why** | Future upgrades fail without context |
| **Looks for** | `exclude` directives without ownership trail |
| **Stays quiet when** | Documented incompatibility + removal condition |
| **Remediation** | Document why exclude exists |
