import { lineSignals, positive } from "./signals.js";
import { type DomainDefinition } from "./types.js";

export const domain: DomainDefinition = {
  name: "go-modules",
  displayName: "Go Modules",
  observationKey: "go-modules.analysis",
  sourceDescription: "Go module",
  includePath: (path) => /(^|\/)(go\.(?:mod|sum|work)|modules\.txt)$/.test(path),
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
  ],
  noRiskSummary: "The reviewed module metadata resolves an immutable, reproducible dependency graph.",
  approvalSummary: "I would approve the reviewed Go module and toolchain changes.",
  analyze(file) {
    return {
      signals: [
        ...lineSignals(file, "go-modules.local-replace", /^\s*replace\b.*=>\s*(?:\.\.?\/|\/)/, () => "This replacement resolves through a local filesystem path."),
        ...lineSignals(file, "go-modules.branch-replace", /^\s*replace\b.*=>\s*\S+\s+(?:main|master|latest|HEAD)\s*$/, () => "This replacement names mutable dependency state."),
        ...lineSignals(file, "go-modules.exclude", /^\s*exclude\s+\S+\s+\S+/, () => "This module version is excluded without a machine-readable removal condition."),
      ],
      positives: [
        ...positive(file, "go-modules.toolchain-pinned", /^\s*toolchain\s+go\d+\.\d+\.\d+\s*$/, "The exact Go toolchain patch version is declared."),
      ],
    };
  },
};
