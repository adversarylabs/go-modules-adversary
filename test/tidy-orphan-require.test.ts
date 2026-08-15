import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createApp } from "../src/index.ts";

const ruleId = "go-modules.tidy-orphan-require";

async function review(files: Record<string, string>) {
  const root = await mkdtemp(join(tmpdir(), "go-modules-tidy-"));
  await mkdir(root, { recursive: true });
  for (const [name, source] of Object.entries(files)) {
    const path = join(root, name);
    await mkdir(join(path, ".."), { recursive: true });
    await writeFile(path, source);
  }
  return createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
}

test("flags a Hugo theme require that no Go file imports", async () => {
  const output = await review({
    "go.mod": `module example.com/site

go 1.24

require gopkg.in/yaml.v2 v2.4.0
require github.com/google/docsy/theme v0.16.0 // indirect
`,
    "main.go": `package site

import "gopkg.in/yaml.v2"

func load() { _ = yaml.Marshal }
`,
  });
  const finding = output.findings.find((item) => item.ruleId === ruleId);
  assert.ok(finding, JSON.stringify(output.findings, null, 2));
  assert.match(finding.evidence[0]!.message ?? "", /github.com\/google\/docsy\/theme/);
});

test("stays quiet when tools.go blank-imports the required module", async () => {
  const output = await review({
    "go.mod": `module example.com/site

go 1.24

require github.com/google/docsy/theme v0.16.0
`,
    "tools.go": `//go:build tools

package site

import _ "github.com/google/docsy/theme"
`,
  });
  assert.equal(
    output.findings.some((item) => item.ruleId === ruleId),
    false,
    JSON.stringify(output.findings, null, 2),
  );
});

test("stays quiet when a comment documents that tidy must not run", async () => {
  const output = await review({
    "go.mod": `module example.com/site

go 1.24

// Do NOT run go mod tidy in this directory — Hugo theme, not a Go import.
require github.com/google/docsy/theme v0.16.0
`,
    "main.go": "package site\n",
  });
  assert.equal(
    output.findings.some((item) => item.ruleId === ruleId),
    false,
    JSON.stringify(output.findings, null, 2),
  );
});

test("stays quiet when there is no Go file beside go.mod", async () => {
  const output = await review({
    "go.mod": `module example.com/site

go 1.24

require github.com/google/docsy/theme v0.16.0
`,
  });
  assert.equal(
    output.findings.some((item) => item.ruleId === ruleId),
    false,
    JSON.stringify(output.findings, null, 2),
  );
});
