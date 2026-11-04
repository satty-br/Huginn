# Keeping rules.toml and the README in sync with gitleaks

Huginn only validates a secret it already knows the *shape* of — it never
runs gitleaks itself, it only validates a report gitleaks already produced.
So `updatereadme/rules.toml` is a **mirrored snapshot** of gitleaks'
upstream `config/gitleaks.toml`, kept in the repo so the top-level
`README.md`'s `## keys` checklist can be regenerated from it without a
network call, and so it's obvious in a diff exactly which rule IDs exist and
what each one's regex/entropy/keywords are.

## When to update it

Whenever gitleaks adds, renames, or removes a rule upstream. There is no
automation for this yet — it's a manual pull:

1. Fetch the current upstream rule file:
   ```sh
   curl -sL https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml -o /tmp/gitleaks.toml
   ```
2. Diff its rule IDs against `updatereadme/rules.toml`'s:
   ```sh
   grep -oP '^id = "\K[^"]+' /tmp/gitleaks.toml | sort > /tmp/upstream.txt
   grep -oP '^\s*id\s*=\s*"\K[^"]+' updatereadme/rules.toml | sort > /tmp/local.txt
   comm -23 /tmp/upstream.txt /tmp/local.txt   # new upstream rules
   comm -13 /tmp/upstream.txt /tmp/local.txt   # rules removed/renamed upstream
   ```
3. For each new ID, copy its whole `[[rules]]` block (id, description,
   regex, entropy, keywords — *not* any shared `[rules.allowlist]` block,
   those are global and already present once at the top of the file) from
   the upstream file into `updatereadme/rules.toml`.
4. For a renamed rule (e.g. gitleaks renaming `"age secret key"` to
   `"age-secret-key"`, or splitting one `facebook` rule into
   `facebook-access-token`/`facebook-page-access-token`/`facebook-secret`),
   update or replace the existing block rather than leaving the old id
   alongside the new one.
5. Validate the file still parses and has no duplicate IDs:
   ```sh
   python3 -c "
   import tomllib
   with open('updatereadme/rules.toml','rb') as f:
       data = tomllib.load(f)
   ids = [r['id'] for r in data['rules']]
   assert len(ids) == len(set(ids)), 'duplicate rule id!'
   print(len(ids), 'rules, no duplicates')
   "
   ```

## Regenerating the README checklist

Once `rules.toml` is current, regenerate `README.md`'s `## keys` section —
one checkbox per rule ID, checked (`[X]`) if and only if that exact string
appears anywhere in `validator.go` (which in practice means it's used as a
map key in `Validate()`, but the check is a plain substring search, so it
would also "pass" if the ID merely appeared in a comment — keep that in
mind if you ever see a checkbox that looks wrong):

```sh
cd updatereadme
go run .
```

`readme.go` (`package main`) reads `rules.toml` and `../validator.go`
(both relative to the `updatereadme/` directory it's run from), builds the
checklist, and splices it into `../README.md` after the literal `## keys`
marker — replacing everything that follows it, so nothing should be added
below that heading in `README.md` by hand.

## Adding a validator moves a checkbox automatically

There's nothing extra to do in `rules.toml` or `README.md` when you
implement a validator for an existing rule ID — write the Go function, wire
it into `Validate()`'s map (see [contributing.md](contributing.md)), then
re-run `go run .` from `updatereadme/` and that rule's checkbox flips to
`[X]` on its own.
