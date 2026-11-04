# Huginn — Documentation

Huginn validates secrets reported by [gitleaks](https://github.com/gitleaks/gitleaks)
by replaying them against the real upstream API they belong to, so a scan's
output can be triaged by "confirmed valid" vs. "needs a manual look" instead
of by regex match alone.

This folder holds the project's specification documents:

| Document | Covers |
|---|---|
| [architecture.md](architecture.md) | How the pieces fit together: `main.go` → `runner.go` → `validator.go`, the `Secret`/`Validator` types, control flow, and the input/output JSON contract. |
| [cli-usage.md](cli-usage.md) | Building and running the `huginn` binary, its flags, exit behavior, and the Docker image. |
| [validators.md](validators.md) | The full specification of every supported gitleaks `RuleID`: which Go function validates it, which upstream endpoint/header scheme it uses, and the categories of secret the project cannot validate on purpose, with the reasoning. |
| [rules-sync.md](rules-sync.md) | How `updatereadme/rules.toml` mirrors gitleaks' own rule set, and how the `updatereadme` tool keeps the README's `## keys` checklist in sync with `validator.go`. |
| [testing.md](testing.md) | What the test suite covers, what it deliberately does not (live third-party network calls), and how to run and extend it. |
| [contributing.md](contributing.md) | Step-by-step guide for adding a validator for a new gitleaks rule. |

## Project layout

```
main.go                     CLI entry point (flag parsing, exit codes)
runner.go                   Reads the gitleaks JSON report, runs validation, writes output.json
validator.go                Secret/Validator types + one function per supported RuleID
runner_test.go              Runner-level tests (happy path + error paths)
validator_test.go           Unit tests for validator helpers and bug regressions
test/test.json              Sample gitleaks report used by the tests
updatereadme/                Standalone tool + mirrored copy of gitleaks' rules.toml
  rules.toml                 Snapshot of gitleaks' rule definitions (id, regex, keywords)
  readme.go                  Regenerates README.md's "## keys" checklist from rules.toml + validator.go
docs/                        You are here
Dockerfile                   Multi-stage build producing a minimal runtime image
.github/workflows/           CI: release build, version bump
```
