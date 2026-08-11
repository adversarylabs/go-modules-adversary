import assert from "node:assert/strict";
import test from "node:test";
import { sameModuleReplaceSignals } from "../src/domain.ts";
import { type SourceRevision } from "../src/types.ts";

function analyze(
  current: string,
  status: SourceRevision["status"] = "repository",
  changedLines = new Set<number>(),
) {
  const source: SourceRevision = {
    path: "go.mod",
    current,
    changedLines,
    status,
  };
  return sameModuleReplaceSignals(source);
}

test("detects an unversioned same-module replacement for a required module", () => {
  const signals = analyze(`
module example.com/service

require tags.cncf.io/container-device-interface v1.1.0

replace tags.cncf.io/container-device-interface => tags.cncf.io/container-device-interface v1.1.1-0.20260625135320-7a214f294075
`);

  assert.equal(signals.length, 1);
  assert.equal(signals[0]?.ruleId, "go-modules.same-module-replace");
  assert.equal(signals[0]?.line, 6);
  assert.deepEqual(signals[0]?.data, {
    module: "tags.cncf.io/container-device-interface",
    requiredVersion: "v1.1.0",
    replacementVersion: "v1.1.1-0.20260625135320-7a214f294075",
    scope: "all-versions",
  });
});

test("detects same-module replacements in require and replace blocks", () => {
  const signals = analyze(`
module example.com/service

require (
  example.com/dependency v0.9.1
)

replace (
  example.com/dependency => example.com/dependency v0.9.2 // temporary override
)
`);

  assert.equal(signals.length, 1);
  assert.equal(signals[0]?.line, 9);
});

test("stays quiet for replacements with different scope or intent", () => {
  const cleanCases = [
    `require example.com/dependency v1.0.0\nreplace example.com/dependency => ../dependency`,
    `require example.com/dependency v1.0.0\nreplace example.com/dependency => example.net/fork v1.0.1`,
    `require example.com/dependency v1.0.0\nreplace example.com/dependency v1.0.0 => example.com/dependency v1.0.1`,
    `replace example.com/dependency => example.com/dependency v1.0.1`,
  ];

  for (const source of cleanCases) {
    assert.deepEqual(analyze(source), []);
  }
});

test("detects a changed require whose existing replacement still overrides it", () => {
  const source = `module example.com/service

require example.com/dependency v1.1.1-0.20260720132747-49ac08dcf160

replace example.com/dependency => example.com/dependency v1.1.0-0.20260625135320-7a214f294075
`;

  const signals = analyze(source, "modified", new Set([3]));
  assert.equal(signals.length, 1);
  assert.equal(signals[0]?.line, 3);
  assert.match(signals[0]?.snippet ?? "", /^require /);
});

test("stays quiet when an unrelated go.mod line changes around an existing pair", () => {
  const source = `module example.com/service

go 1.26

require example.com/dependency v1.0.0

replace example.com/dependency => example.com/dependency v1.0.1
`;

  assert.deepEqual(analyze(source, "modified", new Set([3])), []);
});
