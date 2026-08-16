# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `go-modules.branch-replace` | Medium | Replacement tracks mutable branch state |
| `go-modules.checksum-database-off` | High | Go checksum database disabled |
| `go-modules.cve-known` | Critical | Required module version is known-vulnerable |
| `go-modules.exclude` | Medium | exclude hides compatibility constraint |
| `go-modules.local-replace` | High | Local replace outside published graph |
| `go-modules.same-module-replace` | Medium | Unversioned same-module replacement overrides a required module |
| `go-modules.sum-missing` | High | go.mod with requires but no go.sum |
| `go-modules.tidy-orphan-require` | Medium | A `require` documented as serving a non-Go consumer has no retaining import in the same module and may be removed by `go mod tidy` |
