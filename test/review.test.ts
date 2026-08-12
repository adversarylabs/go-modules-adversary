import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { cp, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { type ReviewResult } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const execute = promisify(execFile);

async function review(root: string): Promise<ReviewResult> {
  return createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
}

function snapshot(output: ReviewResult) {
  return {
    risk: output.assessment?.risk,
    findings: output.findings.map((finding) => ({
      ruleId: finding.ruleId,
      severity: finding.severity,
      evidenceCount: finding.evidence.length,
    })),
    positiveKeys: output.positives.map((item) => item.key),
    ship: output.opinion?.ship,
  };
}

for (const grade of ["excellent", "good", "average", "poor", "terrible"]) {
  test(`${grade} fixture matches its expected review snapshot`, async () => {
    const fixture = join(projectRoot, "fixtures", grade);
    const root = await isolatedFixture(fixture);
    const expected = JSON.parse(await readFile(join(fixture, "expected.review.json"), "utf8"));
    assert.deepEqual(snapshot(await review(root)), expected);
  });
}

test("review output is deterministic", async () => {
  const root = await isolatedFixture(join(projectRoot, "fixtures", "terrible"));
  assert.deepEqual(await review(root), await review(root));
});

test("an unrelated go.mod edit does not surface a legacy same-module replacement", async () => {
  const root = await gitRepository({
    "go.mod": `module example.com/service

go 1.24

require example.com/dependency v1.0.0
replace example.com/dependency => example.com/dependency v1.1.0
`,
    "go.sum": "",
  });
  await writeFile(
    join(root, "go.mod"),
    `module example.com/service

go 1.25

require example.com/dependency v1.0.0
replace example.com/dependency => example.com/dependency v1.1.0
`,
  );

  const output = await createApp().run({
    input: {
      source: { path: root },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: ["go.mod"],
      },
    },
    includeRawObservations: true,
  });
  assert.equal(output.findings.some((finding) => finding.ruleId === "go-modules.same-module-replace"), false);
});

test("a newly added go.mod still reports a same-module replacement", async () => {
  const root = await gitRepository({ "README.md": "# service\n" });
  await writeFile(
    join(root, "go.mod"),
    `module example.com/service

go 1.25

require example.com/dependency v1.0.0
replace example.com/dependency => example.com/dependency v1.1.0
`,
  );

  const output = await createApp().run({
    input: {
      source: { path: root },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: ["go.mod"],
      },
    },
    includeRawObservations: true,
  });
  assert.equal(output.findings.some((finding) => finding.ruleId === "go-modules.same-module-replace"), true);
});

async function isolatedFixture(fixture: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "go-domain-fixture-"));
  await cp(fixture, root, { recursive: true });
  return root;
}

async function gitRepository(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "go-modules-git-"));
  await execute("git", ["init", "--quiet", root]);
  await execute("git", ["-C", root, "config", "user.email", "tests@example.com"]);
  await execute("git", ["-C", root, "config", "user.name", "Tests"]);
  for (const [path, content] of Object.entries(files)) {
    await writeFile(join(root, path), content);
  }
  await execute("git", ["-C", root, "add", "."]);
  await execute("git", ["-C", root, "commit", "--quiet", "-m", "baseline"]);
  return root;
}
