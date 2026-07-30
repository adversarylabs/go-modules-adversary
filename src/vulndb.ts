/**
 * Offline vulnerability table for go-modules.cve-known.
 *
 * This is intentionally small and fixture-oriented so detection is
 * deterministic and network-free. Production deployments can expand the
 * table (or replace the lookup) with a fuller OSV/govulncheck snapshot.
 *
 * Matching is exact module path + version string as written in go.mod require
 * lines. Entries below use synthetic module paths reserved for fixtures.
 */

export interface VulnEntry {
  /** Module path as it appears in go.mod (e.g. example.com/vuln/old). */
  module: string;
  /** Exact version string including the leading "v" when present. */
  version: string;
  /** Advisory / CVE-style identifier. */
  id: string;
  /** Short human-readable description of the vulnerability. */
  summary: string;
}

/** Curated offline DB. Expand for production; keep fixtures on these keys. */
export const OFFLINE_VULN_DB: readonly VulnEntry[] = [
  {
    module: "example.com/vuln/old",
    version: "v1.0.0",
    id: "GO-FIXTURE-0001",
    summary: "Known vulnerable fixture module version (offline test entry).",
  },
  {
    module: "example.com/vuln/crypto",
    version: "v0.2.0",
    id: "GO-FIXTURE-0002",
    summary: "Historical fixture crypto weakness at v0.2.0 (offline test entry).",
  },
  {
    module: "example.com/vuln/http",
    version: "v1.3.1",
    id: "GO-FIXTURE-0003",
    summary: "Historical fixture HTTP request smuggling risk (offline test entry).",
  },
];

const byKey = new Map(
  OFFLINE_VULN_DB.map((entry) => [`${entry.module}@${entry.version}`, entry] as const),
);

export function lookupVuln(module: string, version: string): VulnEntry | undefined {
  return byKey.get(`${module}@${version}`);
}
