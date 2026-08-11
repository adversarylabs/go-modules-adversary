import { lineSignals, positive } from "./signals.js";
import { type DomainDefinition, type Signal, type SourceRevision } from "./types.js";
import { lookupVuln } from "./vulndb.js";

/** Paths reviewed for Go module graph integrity and related env/CI config. */
export function includePath(path: string): boolean {
  if (/(^|\/)(go\.(?:mod|sum|work|env)|modules\.txt)$/.test(path)) return true;
  if (/(^|\/)\.env(?:$|\.)/.test(path)) return true;
  if (/(^|\/)(?:[Mm]akefile|GNUmakefile)$/.test(path)) return true;
  if (/\.(?:ya?ml|sh)$/.test(path)) return true;
  return false;
}

export const domain: DomainDefinition = {
  name: "go-modules",
  displayName: "Go Modules",
  observationKey: "go-modules.analysis",
  sourceDescription: "Go module",
  includePath,
  rules: [
    {
      id: "go-modules.local-replace",
      title: "A local replacement makes the module unreproducible",
      concern: "unreproducible module replacements",
      category: "dependencies",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} replace directive${count === 1 ? "" : "s"} point outside the published module graph.`,
      whyItMatters: "Local replacements resolve only in the author's filesystem and are not carried by a module release.",
      impact: "Consumers and CI cannot reproduce the dependency graph represented by this checkout.",
      recommendation: "Publish and require a real module version, or keep the replacement only in an uncommitted developer go.work file.",
    },
    {
      id: "go-modules.branch-replace",
      title: "A replacement tracks mutable dependency state",
      concern: "mutable branch replacements",
      category: "dependencies",
      severity: "medium",
      confidence: "high",
      summary: (count) => `${count} replacement${count === 1 ? "" : "s"} reference a branch-like revision.`,
      whyItMatters: "Mutable dependency references do not identify one immutable source state.",
      impact: "Two installs can resolve different code while the repository metadata is unchanged.",
      recommendation: "Resolve and commit a tagged version or Go pseudo-version with its checksum.",
    },
    {
      id: "go-modules.same-module-replace",
      title: "An unversioned replacement pins every version of a module",
      concern: "unconditional same-module replacements",
      category: "dependencies",
      severity: "medium",
      confidence: "high",
      summary: (count) =>
        `${count} same-module replacement${count === 1 ? "" : "s"} override every selected version of a required module.`,
      whyItMatters: "An unversioned replace directive applies to every selected version of its module, including later direct and transitive upgrades.",
      impact: "The dependency graph can remain pinned to the replacement target even after another requirement selects a newer version.",
      recommendation: "For an ordinary upgrade, remove the replacement and require the target version directly; otherwise document why the global override is intentional and when it can be removed.",
    },
    {
      id: "go-modules.exclude",
      title: "An excluded module version hides a compatibility constraint",
      concern: "module exclude directives",
      category: "dependencies",
      severity: "medium",
      confidence: "medium",
      summary: (count) => `${count} exclude directive${count === 1 ? "" : "s"} require an undocumented graph exception.`,
      whyItMatters: "Exclusions can be valid, but they often preserve a compatibility workaround that future upgrades cannot infer.",
      impact: "Dependency updates may reintroduce the underlying issue or fail without an ownership trail.",
      recommendation: "Document the incompatibility and removal condition next to the exclusion or in dependency policy.",
    },
    {
      id: "go-modules.sum-missing",
      title: "go.mod declares dependencies without a go.sum",
      concern: "missing module sum integrity file",
      category: "dependencies",
      severity: "high",
      confidence: "high",
      summary: (count) =>
        count === 1
          ? "A go.mod with versioned requires has no companion go.sum."
          : `${count} go.mod files with versioned requires lack a companion go.sum.`,
      whyItMatters: "go.sum records cryptographic hashes that pin dependency contents for reproducible, verifiable builds.",
      impact: "Installs can pull different module contents than the author reviewed, and checksum-database verification has no local baseline.",
      recommendation: "Run `go mod tidy` (or `go get` for each require) and commit the generated go.sum next to go.mod.",
    },
    {
      id: "go-modules.cve-known",
      title: "A required module version is known-vulnerable",
      concern: "known vulnerable module versions",
      category: "security",
      severity: "critical",
      confidence: "high",
      summary: (count) =>
        `${count} require${count === 1 ? "" : "s"} pin module versions listed in the offline vulnerability table.`,
      whyItMatters: "Known-vulnerable dependency versions remain exploitable until upgraded or replaced.",
      impact: "Applications and tools built from this module graph inherit published security defects.",
      recommendation: "Upgrade the required module to a fixed version and re-run `go mod tidy`. Expand the offline vuln table or use govulncheck for production coverage.",
    },
    {
      id: "go-modules.checksum-database-off",
      title: "The Go checksum database is disabled",
      concern: "disabled Go checksum database",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) =>
        `${count} configuration site${count === 1 ? "" : "s"} disable or broadly bypass the Go checksum database.`,
      whyItMatters: "sum.golang.org attests module hashes independently of the module proxy; turning it off removes a core supply-chain check.",
      impact: "Tampered or substituted modules can install without checksum-database rejection.",
      recommendation: "Remove GOSUMDB=off and overly broad GONOSUMDB/GOINSECURE=* settings; use GOPRIVATE for private hosts instead of disabling verification globally.",
    },
  ],
  noRiskSummary: "The reviewed module metadata resolves an immutable, reproducible dependency graph.",
  approvalSummary: "I would approve the reviewed Go module and toolchain changes.",
  analyze(file) {
    return {
      signals: [
        ...lineSignals(file, "go-modules.local-replace", /^\s*replace\b.*=>\s*(?:\.\.?\/|\/)/, () => "This replacement resolves through a local filesystem path."),
        ...lineSignals(file, "go-modules.branch-replace", /^\s*replace\b.*=>\s*\S+\s+(?:main|master|latest|HEAD)\s*$/, () => "This replacement names mutable dependency state."),
        ...sameModuleReplaceSignals(file),
        ...lineSignals(file, "go-modules.exclude", /^\s*exclude\s+\S+\s+\S+/, () => "This module version is excluded without a machine-readable removal condition."),
        ...cveKnownSignals(file),
        ...checksumDatabaseOffSignals(file),
      ],
      positives: [
        ...positive(file, "go-modules.toolchain-pinned", /^\s*toolchain\s+go\d+\.\d+\.\d+\s*$/, "The exact Go toolchain patch version is declared."),
      ],
    };
  },
};

/** Cross-file: go.mod with versioned requires but no sibling go.sum in discovery. */
export function missingSumSignals(files: SourceRevision[]): Signal[] {
  const paths = new Set(files.map((file) => file.path));
  const signals: Signal[] = [];

  for (const file of files) {
    if (!file.path.endsWith("go.mod") && !/(^|\/)go\.mod$/.test(file.path)) continue;
    const requires = versionedRequires(file.current);
    if (requires.length === 0) continue;

    const sumPath = file.path.replace(/go\.mod$/, "go.sum");
    if (paths.has(sumPath)) continue;

    const first = requires[0]!;
    signals.push({
      ruleId: "go-modules.sum-missing",
      path: file.path,
      line: first.line,
      message: `go.mod requires ${requires.length} versioned module${requires.length === 1 ? "" : "s"} but ${sumPath} is not present in the repository.`,
      snippet: first.snippet,
      data: {
        goMod: file.path,
        expectedSum: sumPath,
        requireCount: requires.length,
      },
    });
  }

  return signals;
}

interface RequireLine {
  module: string;
  version: string;
  line: number;
  snippet: string;
}

function versionedRequires(source: string): RequireLine[] {
  const results: RequireLine[] = [];
  let inRequireBlock = false;

  source.split("\n").forEach((raw, index) => {
    const line = raw.trim();
    if (/^require\s*\(\s*$/.test(line)) {
      inRequireBlock = true;
      return;
    }
    if (inRequireBlock) {
      if (line === ")") {
        inRequireBlock = false;
        return;
      }
      const block = parseRequireLine(line);
      if (block !== undefined) {
        results.push({ ...block, line: index + 1, snippet: raw.trim().slice(0, 300) });
      }
      return;
    }
    const single = /^require\s+(\S+)\s+(\S+)/.exec(line);
    if (single !== null) {
      const module = single[1]!;
      const version = single[2]!;
      if (isVersionedRequire(module, version)) {
        results.push({
          module,
          version,
          line: index + 1,
          snippet: raw.trim().slice(0, 300),
        });
      }
    }
  });

  return results;
}

function parseRequireLine(line: string): { module: string; version: string } | undefined {
  // Strip trailing // comments (e.g. // indirect)
  const withoutComment = line.replace(/\s*\/\/.*$/, "").trim();
  if (withoutComment === "" || withoutComment.startsWith("//")) return undefined;
  const match = /^(\S+)\s+(\S+)\s*$/.exec(withoutComment);
  if (match === null) return undefined;
  const module = match[1]!;
  const version = match[2]!;
  if (!isVersionedRequire(module, version)) return undefined;
  return { module, version };
}

function isVersionedRequire(module: string, version: string): boolean {
  if (module === "" || version === "") return false;
  // go.mod versions start with "v" or are "none" in exclude-like forms; require uses semver tags.
  return /^v\d/.test(version) || /^\d+\.\d+/.test(version);
}

interface ReplacementLine {
  oldModule: string;
  oldVersion: string | undefined;
  newModule: string;
  newVersion: string | undefined;
  line: number;
  snippet: string;
}

/** Same-module, unversioned replacements that globally override a direct requirement. */
export function sameModuleReplaceSignals(file: SourceRevision): Signal[] {
  if (!/(^|\/)go\.mod$/.test(file.path)) return [];

  const requirements = new Map(versionedRequires(file.current).map((requirement) => [requirement.module, requirement]));
  const signals: Signal[] = [];

  for (const replacement of replacementLines(file.current)) {
    const requirement = requirements.get(replacement.oldModule);
    if (requirement === undefined) continue;
    if (replacement.oldVersion !== undefined) continue;
    if (replacement.oldModule !== replacement.newModule) continue;
    if (replacement.newVersion === undefined || !isVersionedRequire(replacement.newModule, replacement.newVersion)) continue;

    signals.push({
      ruleId: "go-modules.same-module-replace",
      path: file.path,
      line: replacement.line,
      message: `${replacement.oldModule} is required at ${requirement.version}, but this unversioned replacement forces every selected version to ${replacement.newVersion}.`,
      snippet: replacement.snippet,
      data: {
        module: replacement.oldModule,
        requiredVersion: requirement.version,
        replacementVersion: replacement.newVersion,
        scope: "all-versions",
      },
    });
  }

  return signals;
}

function replacementLines(source: string): ReplacementLine[] {
  const results: ReplacementLine[] = [];
  let inReplaceBlock = false;

  source.split("\n").forEach((raw, index) => {
    const line = raw.trim();
    if (/^replace\s*\(\s*$/.test(line)) {
      inReplaceBlock = true;
      return;
    }
    if (inReplaceBlock && line === ")") {
      inReplaceBlock = false;
      return;
    }

    const directive = inReplaceBlock ? line : line.replace(/^replace\s+/, "");
    if (!inReplaceBlock && directive === line) return;
    const parsed = parseReplacementLine(directive);
    if (parsed !== undefined) {
      results.push({ ...parsed, line: index + 1, snippet: raw.trim().slice(0, 300) });
    }
  });

  return results;
}

function parseReplacementLine(line: string): Omit<ReplacementLine, "line" | "snippet"> | undefined {
  const withoutComment = line.replace(/\s*\/\/.*$/, "").trim();
  if (withoutComment === "" || withoutComment.startsWith("//")) return undefined;

  const sides = withoutComment.split(/\s+=>\s+/);
  if (sides.length !== 2) return undefined;
  const oldFields = sides[0]!.trim().split(/\s+/);
  const newFields = sides[1]!.trim().split(/\s+/);
  if (oldFields.length < 1 || oldFields.length > 2 || newFields.length < 1 || newFields.length > 2) return undefined;

  return {
    oldModule: oldFields[0]!,
    oldVersion: oldFields[1],
    newModule: newFields[0]!,
    newVersion: newFields[1],
  };
}

function cveKnownSignals(file: SourceRevision): Signal[] {
  if (!/(^|\/)go\.mod$/.test(file.path)) return [];
  const signals: Signal[] = [];
  for (const req of versionedRequires(file.current)) {
    const entry = lookupVuln(req.module, req.version);
    if (entry === undefined) continue;
    signals.push({
      ruleId: "go-modules.cve-known",
      path: file.path,
      line: req.line,
      message: `${entry.id}: ${req.module}@${req.version} is listed as known-vulnerable (${entry.summary})`,
      snippet: req.snippet,
      data: {
        module: req.module,
        version: req.version,
        vulnId: entry.id,
        summary: entry.summary,
      },
    });
  }
  return signals;
}

/** High-precision checksum-database disable / bypass patterns. */
const CHECKSUM_OFF_PATTERNS: Array<{
  pattern: RegExp;
  message: (match: RegExpMatchArray) => string;
  data: (match: RegExpMatchArray) => Record<string, unknown>;
}> = [
  {
    pattern: /(?:^|[\s"'`;])(?:export\s+)?GOSUMDB\s*=\s*["']?off["']?(?=[\s"'`;]|$)/i,
    message: () => "GOSUMDB=off disables the Go checksum database for module downloads.",
    data: () => ({ setting: "GOSUMDB", value: "off" }),
  },
  {
    pattern: /(?:^|[\s"'`;])(?:export\s+)?GONOSUMDB\s*=\s*["']?\*["']?(?=[\s"'`;]|$)/i,
    message: () => "GONOSUMDB=* exempts every module host from checksum-database checks.",
    data: () => ({ setting: "GONOSUMDB", value: "*" }),
  },
  {
    pattern: /(?:^|[\s"'`;])(?:export\s+)?GOINSECURE\s*=\s*["']?\*["']?(?=[\s"'`;]|$)/i,
    message: () => "GOINSECURE=* allows insecure module fetches for every host.",
    data: () => ({ setting: "GOINSECURE", value: "*" }),
  },
];

function checksumDatabaseOffSignals(file: SourceRevision): Signal[] {
  // Only scan text files we intentionally discover for env/CI signals.
  if (
    !/(^|\/)(go\.(?:mod|env)|[Mm]akefile|GNUmakefile)$/.test(file.path) &&
    !/(^|\/)\.env(?:$|\.)/.test(file.path) &&
    !/\.(?:ya?ml|sh)$/.test(file.path)
  ) {
    return [];
  }

  const signals: Signal[] = [];
  file.current.split("\n").forEach((line, index) => {
    // Skip pure comment lines in shell/make that are documentation only? Still flag —
    // documented instructions to disable the checksum DB are the risk surface.
    for (const rule of CHECKSUM_OFF_PATTERNS) {
      const match = line.match(rule.pattern);
      if (match === null) continue;
      signals.push({
        ruleId: "go-modules.checksum-database-off",
        path: file.path,
        line: index + 1,
        message: rule.message(match),
        snippet: line.trim().slice(0, 300),
        data: rule.data(match),
      });
      break;
    }
  });
  return signals;
}
