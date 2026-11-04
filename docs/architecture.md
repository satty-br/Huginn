# Architecture

## Overview

Huginn is a small, single-binary Go CLI. It takes a gitleaks JSON report and
a path to the scanned project, and produces a copy of that report where every
secret has an added `Valid` boolean — `true` only if Huginn could reproduce
a successful authenticated call to that secret's own service using the leaked
value itself.

```
                 ┌────────────┐
 results.json ──▶│   main.go  │  parses -file / -project flags, checks the
                 └─────┬──────┘  input file exists, calls Runner()
                       │
                       ▼
                 ┌────────────┐
                 │  runner.go │  reads + unmarshals the JSON report,
                 └─────┬──────┘  builds a Validator, loops over every Secret
                       │
                       ▼
                 ┌─────────────┐
                 │ validator.go│  Validate(secret) looks up secret.RuleID in
                 └─────┬───────┘  a map of ~162 RuleIDs → validator functions
                       │
              ┌────────┴─────────┐
              ▼                  ▼
      upstream API call     FileSearch(secret, regex)
      (Bearer/Basic/custom      — reads secret.File looking for context
       header, per service)       the validator needs: a self-hosted
              │                   service's domain, a companion secret's
              ▼                   app ID, an email, etc.
      true/false  ───────────▶ out[i].Valid
                       │
                       ▼
                 output.json  (same shape as the input, plus "valid")
```

## Core types (`validator.go`)

```go
type Secret struct {
    Description, Match, Secret, File, SymlinkFile, Commit string
    StartLine, EndLine, StartColumn, EndColumn             int
    Entropy                                                float64
    Author, Email, Date, Message                           string
    Tags                                                   []string
    RuleID, Fingerprint                                     string
    Valid                                                   bool
}
```

This mirrors gitleaks' own JSON report schema field for field, so a report
produced by `gitleaks detect --report-format json` can be fed to Huginn
unchanged, and Huginn's `output.json` can be diffed against the original
report with nothing but the new `valid` field standing out.

```go
type Validator struct {
    Project string   // the scanned project's root — passed through, used
                      // by validators that need to look at *other* files
                      // than the one the secret itself was found in
    Secrets []Secret  // every secret from the current report, so a
                      // validator can look up a *different* secret
                      // (same file, different RuleID) to reconstruct a
                      // pair gitleaks reports as two separate findings
}
```

## Control flow (`runner.go`)

`Runner(file, project string) error`:

1. Reads `file` and unmarshals it into `[]Secret`. Both the read and the
   unmarshal return early with a wrapped error on failure — the caller
   decides what to do (the CLI prints it and exits non‑zero; a test can
   assert on it).
2. Builds a single `Validator{Project: project, Secrets: secrets}` shared
   across the whole run, so every validator call has access to every other
   secret found in the same report (see "Pairing" below).
3. For each `Secret`, calls `validator.Validate(secret)`. If it returns
   `true`, prints a green confirmation line and sets `secret.Valid = true`
   on the copy going into the output slice.
4. Marshals the output slice back to indented JSON and writes it to
   `output.json` in the current working directory (not `project` — the
   `project` argument is only ever used to let a validator search *other*
   project files for context, it is not where output goes).

## Dispatch (`validator.go`'s `Validate`)

`Validate(secret Secret) bool` holds a `map[string]func(Secret) bool`
keyed by gitleaks `RuleID` (e.g. `"github-pat"`, `"stripe-access-token"`).
Several RuleIDs that represent the same underlying credential format (e.g.
GitHub's `github-pat`, `github-oauth`, `github-fine-grained-pat`, and
`github-refresh-token` are all bearer tokens checked the same way against
`GET /user`) point at the same Go function. A `RuleID` with no entry in the
map — anything gitleaks can detect that Huginn has no validator for —
returns `false` without making any network call.

See [validators.md](validators.md) for the full table and the categories of
secret this project does not attempt to validate, with reasoning.

## Validation patterns

Every validator is a method on `*Validator` with the signature
`func(Secret) bool`. A handful of reusable HTTP helpers back almost all of
them:

- `Get` / `GetAuth` — GET with arbitrary headers and/or HTTP Basic auth.
- `Post` / `PostJSON` / `PostForm` / `PostBasicAuth` / `PostFormBasicAuth` —
  POST variants for APIs that need a JSON body (mostly GraphQL), a
  form-urlencoded body (mostly OAuth2 `client_credentials`), or no body at
  all.
- `GenericAuth` / `DefaultBearer` / `DefaultBasic` — build an
  `Authorization` header with a given scheme.
- `IsResponseSuccessful` — the single success predicate used everywhere:
  `response != nil && response.StatusCode < 401`. Centralizing the nil
  check here matters: every HTTP helper above returns `nil` on a network
  error, a timeout, or a malformed request, which given Huginn calls out to
  dozens of independent third-party APIs is a routine occurrence, not an
  edge case.

Beyond that baseline, four more specific patterns show up repeatedly:

1. **Domain discovery (`FileSearch`).** Self-hosted services (GitLab,
   Vault, Grafana, Okta, Mattermost, Octopus Deploy, Looker, JFrog, Zendesk,
   Shopify, …) don't have one fixed API host. `FileSearch(secret, regex)`
   re-reads `secret.File` line by line and returns the first line matching
   `regex`, which a validator then parses as a URL to recover the scheme and
   host, falling back to a sane default (e.g. `https://gitlab.com`) when no
   such hint exists in the file.

2. **Pairing (`FindSecretInFile`).** Some credentials are only useful
   together, and gitleaks reports each half as a *separate* finding with its
   own `RuleID` (`bitbucket-client-id` / `bitbucket-client-secret`,
   `sumologic-access-id` / `sumologic-access-token`, `looker-client-id` /
   `looker-client-secret`, …). Because the `Validator` holds every `Secret`
   from the current report, `FindSecretInFile(file, ruleID)` can look up the
   sibling value reported for the *same file* and reconstruct the pair
   before calling the upstream API. Both RuleIDs in a pair map to the same
   Go function, which branches on `secret.RuleID` to know which half it was
   handed and which half it still needs to look up.

3. **GraphQL via a fixed introspection field.** A few APIs (Linear,
   Sourcegraph, Fly.io, Infracost) only expose a GraphQL endpoint, with no
   plain REST/GET alternative. Rather than guess at each one's actual schema
   (and risk a wrong field name producing a GraphQL error that looks
   identical to an auth failure), each sends the smallest valid query for
   that API — `{ __typename }` for Infracost works against *any* GraphQL
   schema since it's a spec-level meta field, while Linear/Sourcegraph/Fly.io
   use a minimal, well-documented query (`viewer`/`currentUser`) confirmed
   against their own API docs.

4. **Request signing (AWS SigV4).** `aws-access-token` is the one credential
   requiring more than headers: `AWSTokenTest` looks for a companion
   `generic-api-key` secret in the same file (gitleaks' generic rule is what
   catches the *secret* half of an AWS key pair) and an `AWS_REGION=`
   assignment nearby, then signs a real `GET https://sts.amazonaws.com/`
   request with `AWS4-HMAC-SHA256`, built from `hmacSHA256`/`hash` in the
   same file.

## Why `output.json` lands in the working directory

This matches the original design intent described in the top-level
`README.md`: `--project` tells Huginn where to go looking for the *context*
a validator needs (a self-hosted domain, a paired secret's file) — it does
not relocate where the result is written. Anyone running Huginn from a
script should `cd` to wherever they want `output.json` to land, or move it
afterwards.
