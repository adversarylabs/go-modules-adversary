# go/modules

**go/modules** reviews Go module metadata for **reproducibility, upgrade safety, and supply-chain integrity**: replacements, excludes, go.sum, checksum database configuration, and known-vulnerable pins.

It is a **module graph reviewer**, not a general dependency updater. It prefers silence when the graph is immutable and verifiable.

## What it does

1. **Discovers** `go.mod` / `go.sum` / `go.work` / `go.env`, plus related Makefile/CI/env files that disable checksum verification.
2. **Runs deterministic detectors** over module directives and offline vuln pins.
3. **Synthesizes a review** of graph integrity.
4. Optionally **enhances** with a model when provided.

It never executes the scanned project as the product under review, never installs dependencies into it, and never needs network access to the target repository.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)** — the audit surface for “what does this adversary look for?”

Highlights:

| Area | Examples |
| --- | --- |
| Reproducibility | Local `replace`; branch-like mutable replacements |
| Integrity | Missing `go.sum`; `GOSUMDB=off` / broad `GONOSUMDB` |
| Compatibility | Undocumented `exclude` directives |
| Vulnerabilities | Required versions in the offline known-vuln table |

### Ownership boundaries

Other official adversaries own adjacent classes so findings stay non-duplicative:

| Concern | Owned by |
| --- | --- |
| Language-level security in application Go code | [`go/security`](https://github.com/adversarylabs/go-security-adversary) |
| Committed cloud/provider secrets in any file | [`security/secrets`](https://github.com/adversarylabs/secrets-adversary) |
| CI supply-chain pin of actions | [`ci/github-actions`](https://github.com/adversarylabs/githubactions-adversary) |

## Precision stance

- **High confidence** only for deterministic, evidence-backed patterns.
- Clean fixtures must stay quiet; vulnerable fixtures must fire where graded fixtures exist.
- Prefer missing a weak signal over a false positive on normal production code.
