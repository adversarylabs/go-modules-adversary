import assert from "node:assert/strict";
import { cp, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createApp } from "../src/index.ts";
import { OFFLINE_VULN_DB } from "../src/vulndb.ts";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));

async function isolatedFixture(fixture: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "go-modules-p0-"));
  await cp(fixture, root, { recursive: true });
  return root;
}

const review = async (rel: string) => {
  const root = await isolatedFixture(join(projectRoot, "fixtures", rel));
  return createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
};

test("P0 catalog rules detect vulnerable fixtures and stay quiet on clean", async () => {
  const cases = [
    { dir: "p0-local-replace", id: "go-modules.local-replace" },
    { dir: "p0-sum-missing", id: "go-modules.sum-missing" },
    { dir: "p0-cve-known", id: "go-modules.cve-known" },
    { dir: "p0-checksum-database-off", id: "go-modules.checksum-database-off" },
  ] as const;

  for (const c of cases) {
    const bad = await review(`${c.dir}/vulnerable`);
    assert.equal(
      bad.findings.some((f) => f.ruleId === c.id),
      true,
      `${c.id} missed; got ${bad.findings.map((f) => f.ruleId).join(",") || "(none)"}`,
    );
    const good = await review(`${c.dir}/clean`);
    assert.equal(
      good.findings.some((f) => f.ruleId === c.id),
      false,
      `${c.id} flagged clean; got ${good.findings.map((f) => f.ruleId).join(",") || "(none)"}`,
    );
  }
});

test("cve-known offline DB is fixture-driven and matchable", () => {
  assert.ok(OFFLINE_VULN_DB.length >= 2);
  for (const entry of OFFLINE_VULN_DB) {
    assert.match(entry.module, /^example\.com\/vuln\//);
    assert.match(entry.version, /^v\d/);
    assert.ok(entry.id.length > 0);
    assert.ok(entry.summary.length > 0);
  }
});

test("cve-known evidence cites offline vuln ids for fixture modules", async () => {
  const bad = await review("p0-cve-known/vulnerable");
  const finding = bad.findings.find((f) => f.ruleId === "go-modules.cve-known");
  assert.ok(finding !== undefined);
  const messages = finding.evidence.map((e) => e.message ?? "").join("\n");
  assert.match(messages, /GO-FIXTURE-0001/);
  assert.match(messages, /GO-FIXTURE-0002/);
  assert.doesNotMatch(messages, /example\.com\/safe\/lib/);
});

test("sum-missing points at go.mod require evidence without inventing go.sum", async () => {
  const bad = await review("p0-sum-missing/vulnerable");
  const finding = bad.findings.find((f) => f.ruleId === "go-modules.sum-missing");
  assert.ok(finding !== undefined);
  assert.equal(finding.evidence[0]?.location?.file, "go.mod");
  assert.ok((finding.evidence[0]?.location?.line ?? 0) >= 1);
});

test("checksum-database-off detects GOSUMDB=off in Makefile", async () => {
  const bad = await review("p0-checksum-database-off/vulnerable");
  const finding = bad.findings.find((f) => f.ruleId === "go-modules.checksum-database-off");
  assert.ok(finding !== undefined);
  assert.equal(finding.evidence[0]?.location?.file, "Makefile");
  assert.match(finding.evidence[0]?.snippet ?? "", /GOSUMDB\s*=\s*off/i);
});
