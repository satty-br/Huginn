# Testing

## Running the suite

```sh
go build ./...
go vet ./...
go test ./...
```

`go test` currently takes a couple of seconds: `TestRunner` runs the real
`Runner()` end to end against `test/test.json`, which includes real
`github-pat`-shaped secrets, so it does make live HTTP calls to
`api.github.com` (they're expected to fail with 401/404, since the sample
tokens are fake — the test only asserts that `Runner` completes and writes
a non-empty `output.json`, not that any particular secret validates true).
Every other test is hermetic: no network access, temp files cleaned up via
`t.TempDir()`/`t.Cleanup()`.

## What's covered

- **`runner_test.go`** — `Runner()`'s three outcomes: success writing
  `output.json`, a missing input file, and a malformed JSON input file. Both
  error paths exercise the `error`-returning signature (see
  [contributing.md](contributing.md#error-handling) for why that matters).
- **`validator_test.go`** — the shared helpers every validator is built on
  (`FileSearch`, `FindSecretInFile`, `GenericAuth`/`DefaultBearer`/
  `DefaultBasic`, `IsResponseSuccessful`), plus two **regression tests** for
  bugs this project found and fixed (kept so they can never silently come
  back):
  - `TestIsResponseSuccessful_NilResponse` — every `Get`/`Post`/`GetAuth`
    variant returns `nil` on a network error or timeout. `IsResponseSuccessful`
    used to dereference `response.StatusCode` unconditionally, which panicked
    the whole run on the very first flaky request out of the dozens of
    third-party calls a real scan makes. It must return `false` for `nil`
    now, and this test pins that.
  - `TestFindAWSRegion` / `TestAWSTokenTest_RequiresPairedKeyAndRegion` —
    `FindAWSRegion` used a regex with a lookbehind assertion
    (`(?<=AWS_REGIOn=)`), which Go's RE2-based `regexp` package does not
    support at all; `regexp.MustCompile` panicked on it unconditionally,
    meaning the program crashed the instant it processed *any*
    `aws-access-token` secret. `AWSTokenTest` also had its "do I have a
    paired key?" check inverted (`if len(keys) > 0 { return false }`,
    i.e. it bailed out only when a pair *was* found). Both are fixed and
    pinned here.

## What's intentionally not covered

**Individual validator functions are not unit tested against the real
third-party API they target.** Every one of the ~112 validator functions in
`validator.go` hits a live, external, independently-owned service
(GitHub, Stripe, Cloudflare, …). Testing them properly would mean either:

- making real calls with real secrets in CI (not something to do with
  live credentials in a public repo's test suite), or
- refactoring every validator to take an injectable base URL/HTTP client
  so a `httptest.Server` could stand in for each of 100+ different APIs's
  specific auth scheme and response shape — a large, invasive change that
  would touch nearly every function in the file for a benefit that's
  mostly "did I spell the header name right," which code review and the
  specification in [validators.md](validators.md) (sourced from the actual
  code) already cover.

If you want to actually exercise a specific new validator end to end, the
pragmatic approach is: get a real (even if low-privilege/disposable) secret
for that service, run `./huginn -file <a one-secret gitleaks JSON> -project .`
once by hand, and confirm the banner prints the green "is valid!" line —
then let it go back to being covered only by the dispatch-table and
helper-function tests.

## Adding tests for a new validator

Unless your validator introduces a new *helper* pattern (a new auth scheme
helper, a new way of discovering context), it does not need its own test —
rely on the generic `TestValidate_UnknownRuleIDReturnsFalse`-style coverage
and the shared helper tests. If it does add a new pattern, follow the
regression-test style above: name the test after the behavior it locks in,
and make the test fail against the old code before your fix (then pass
after), so it would actually have caught the bug.
