# Contributing a new validator

This walks through adding support for a gitleaks rule Huginn doesn't
validate yet, end to end.

## 1. Confirm the rule exists in `rules.toml`

```sh
grep -A4 'id = "the-rule-id"' updatereadme/rules.toml
```

If it's missing, gitleaks added it after the last sync — see
[rules-sync.md](rules-sync.md) first and pull it in before writing a
validator for it.

## 2. Find the real API endpoint and auth scheme — from the provider's own docs

This is the part worth taking slowly. A wrong guess is worse than no
validator at all:

- **A false negative** (reporting a real, exploitable credential as
  invalid) is the primary risk and defeats the whole point of the tool —
  double-check the exact header name/scheme/required extra headers against
  the provider's current official documentation, not a blog post, SDK
  comment, or memory. Several existing validators needed a
  provider-specific version header alongside the token (`Duffel-Version`,
  `GoCardless-Version`) that a plausible-looking Bearer-only guess would
  have silently gotten wrong.
- **A false positive** is worse and has caused a validator to be skipped
  outright in this project: if a wrong request parameter (e.g. a missing or
  invalid OAuth `scope`) can make the API return something *other* than
  `401`/`403` for a genuinely invalid credential, `IsResponseSuccessful`'s
  `< 401` check will misreport it as valid. If you can't find an endpoint
  that reliably fails closed on bad credentials, don't add one — note it in
  [validators.md](validators.md#deliberately-not-implemented) instead.
- Prefer an endpoint that needs **no side effects** (a `GET /me`,
  `/whoami`, `/validate`, `/account` style read) over one that creates or
  modifies something, even in a sandbox/test environment.

## 3. Write the function in `validator.go`

Match the existing shape: a method on `*Validator` taking a `Secret` and
returning `bool`, using the shared helpers wherever they fit
(`DefaultBearer`, `GenericAuth`, `GetAuth` for Basic auth, `PostJSON` for a
JSON/GraphQL body, `PostForm`/`PostFormBasicAuth` for OAuth2
`client_credentials`). Always return through `v.IsResponseSuccessful(response)`
rather than touching `response.StatusCode` directly — it's the one place
that's nil-safe.

```go
func (v *Validator) ExampleAPIToken(secret Secret) bool {
	url := "https://api.example.com/v1/me"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}
```

If the API needs a **self-hosted domain** you can't hardcode, use
`FileSearch` to recover it from the same file the secret was found in, with
a sane fallback (see `OktaAccessToken` or `MattermostAccessToken` for the
pattern).

If gitleaks reports this credential as **two separate RuleIDs that only work
as a pair** (a client id + secret, an access id + token), use
`FindSecretInFile` to look up the sibling value in the same file, branching
on `secret.RuleID` to know which half you were handed (see
`BitbucketOAuth` or `SendbirdAPIToken` for the pattern). Map **both**
RuleIDs to the same function in `Validate()`.

## 4. Register it in `Validate()`'s map

```go
"the-rule-id": v.ExampleAPIToken,
```

Keep the map alphabetically-adjacent entries loosely grouped the way the
existing ones are (new-ish additions are appended near the bottom in
batches) — exact ordering doesn't matter functionally, `gofmt` will align
the `:` column for you.

## 5. Format, vet, build, test

```sh
gofmt -w validator.go
go build ./...
go vet ./...
go test ./...
```

## 6. Regenerate the README checklist

```sh
cd updatereadme && go run .
```

This flips the new rule's checkbox to `[X]` automatically — see
[rules-sync.md](rules-sync.md).

## 7. Regenerate `docs/validators.md`

That table is generated from `validator.go`, not written by hand. Re-derive
it the same way it was first built — extract `Validate()`'s map and, for
each function, the first `https?://` literal found in its body — and
replace the `## Supported RuleIDs` table with the refreshed one. (There is
no standing script for this yet; treat it as a short one-off extraction
until/unless it's worth turning into a `go generate` step.)

## 8. If you decide *not* to implement one

Document why in
[validators.md](validators.md#deliberately-not-implemented) under
whichever of the five categories fits, rather than leaving it silently
unchecked with no explanation — that section exists specifically so the
next contributor doesn't re-research the same dead end.
