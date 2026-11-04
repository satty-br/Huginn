# Validators

This is a generated specification of every gitleaks `RuleID` Huginn can
validate, and — just as important — the categories of secret it
deliberately does *not* try to validate, with the reasoning for each. The
table was produced straight from `validator.go`'s `Validate()` dispatch map
and each function's body, so it stays accurate to the code; see
[contributing.md](contributing.md) for how to regenerate it after adding a
new validator.

"Endpoint" shows the literal URL embedded in the function where one exists.
`*(resolved at runtime — see notes)*` means the validator builds the URL
from context it discovers first — most often a self-hosted service's own
domain via `FileSearch`, as explained in
[architecture.md](architecture.md#validation-patterns).

## Supported RuleIDs

| gitleaks RuleID(s) | Validator function | Endpoint | Auth scheme | Notes |
|---|---|---|---|---|
| `zendesk-secret-key` | `Zendesk` | `*(resolved at runtime — see notes)*` | Bearer | discovers domain/context via FileSearch |
| `github-app-token` | `GithubAppToken` | `https://api.github.com/repos/` | Bearer |  |
| `github-fine-grained-pat`, `github-oauth`, `github-pat`, `github-token`, `github-refresh-token` | `GithubToken` | `https://api.github.com/user` | custom |  |
| `gitlab-pat`, `gitlab-pat-routable` | `GitlabAPIToken` | `*(resolved at runtime — see notes)*` | custom |  |
| `gitlab-ptt` | `GitLabPipelineToken` | `*(resolved at runtime — see notes)*` | PRIVATE-TOKEN header |  |
| `gitlab-rrt`, `gitlab-runner-authentication-token`, `gitlab-runner-authentication-token-routable` | `GitLabRunnerToken` | `*(resolved at runtime — see notes)*` | PRIVATE-TOKEN header |  |
| `yandex-aws-access-token` | `YandexAWSAccessToken` | `https://iam.api.cloud.yandex.net/iam/v1/roles` | Bearer |  |
| `yandex-access-token`, `yandex-api-key` | `YandexAPIKey` | `https://cloud-api.yandex.net/v1/disk/resources/public` | OAuth \<token\> header |  |
| `typeform-api-token` | `TypeformAPIKey` | `https://api.typeform.com/me` | Bearer |  |
| `droneci-access-token` | `DroneCIAccessToken` | `https://cloud.drone.io/api/user` | Bearer |  |
| `easypost-test-api-token`, `easypost-api-token` | `EasyPostAPIToken` | `https://api.easypost.com/v2/addresses` | Basic (secret as token) |  |
| `gcp-api-key` | `GCPAPIKey` | `https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s` | token as query param |  |
| `grafana-api-key`, `grafana-service-account-token` | `GrafanaAPIKey` | `https://grafana.com` | Basic (secret as token) | discovers domain/context via FileSearch |
| `grafana-cloud-api-token` | `GrafanaCloudAPIKey` | `http://www.grafana.com/api/v1/accesspolicies` | Basic (secret as token) |  |
| `hashicorp-vault-token`, `vault-batch-token`, `vault-service-token` | `HashicorpVaultToken` | `*(resolved at runtime — see notes)*` | custom |  |
| `hashicorp-tf-password` | `HashicorpVaultPassword` | `*(resolved at runtime — see notes)*` | Form POST, password field (tries common usernames) |  |
| `hashicorp-tf-api-token` | `HashicorpTFAPIToken` | `https://app.terraform.io/api/v2/account/details` | Bearer |  |
| `heroku-api-key`, `heroku-api-key-v2` | `HerokuAPIKey` | `https://api.heroku.com/account` | Bearer |  |
| `jfrog-api-key`, `jfrog-identity-token`, `artifactory-api-key`, `artifactory-reference-token` | `JFrogAPIKey` | `https://artifactory` | Bearer | discovers domain/context via FileSearch |
| `aws-access-token` | `AWSTokenTest` | `https://sts.amazonaws.com/` | AWS SigV4 request signing |  |
| `slack-api-token`, `slack-user-token`, `slack-app-token`, `slack-bot-token`, `slack-config-access-token`, `slack-config-refresh-token`, `slack-legacy-bot-token`, `slack-legacy-token`, `slack-legacy-workspace-token` | `SlackAPIToken` | `https://slack.com/api/auth.test?token=%s&pretty=1` | custom |  |
| `slack-webhook-url` | `SlackWebhookURL` | `*(resolved at runtime — see notes)*` | POST to the webhook URL itself |  |
| `openai-api-key` | `OpenAIAPIKey` | `https://api.openai.com/v1/models` | Bearer |  |
| `asana-client-secret` | `Asana` | `*(resolved at runtime — see notes)*` | Bearer | discovers domain/context via FileSearch |
| `atlassian-api-token` | `AtlassianAPIToken` | `*(resolved at runtime — see notes)*` | Bearer | discovers domain/context via FileSearch |
| `twitter-api-token`, `twitter-bearer-token`, `twitter-access-token`, `twitter-access-secret` | `TwitterAPIToken` | `https://api.twitter.com/1.1/statuses/user_timeline.json` | Bearer |  |
| `twitch-api-token` | `TwitchAPIToken` | `https://api.twitch.tv/helix/users` | Bearer |  |
| `sendgrid-api-token` | `SendgridAPIToken` | `https://api.sendgrid.com/v3/marketing/contacts` | Bearer |  |
| `postman-api-token` | `PostmanAPIToken` | `https://api.getpostman.com/me` | X-Api-Key header |  |
| `pypi-upload-token` | `PyPIUploadToken` | `https://upload.pypi.org/legacy/` | Basic (secret as token) |  |
| `npm-access-token` | `NPMAccessToken` | `https://registry.npmjs.org/-/npm/v1/user` | Bearer |  |
| `new-relic-user-api-key`, `new-relic-browser-api-token` | `NewRelicUserAPIKey` | `https://api.newrelic.com/v2/applications.json` | X-Api-Key header |  |
| `microsoft-teams-webhook` | `MicrosoftTeamsWebhook` | `*(resolved at runtime — see notes)*` | custom |  |
| `discord-client-secret` | `DiscordClientSecret` | `https://discord.com/api/v8/users/@me` | Bearer |  |
| `dynatrace-api-token` | `DynatraceAPIToken` | `https://api.dynatrace.com/api/v1/deployment/installer/agent/connectioninfo` | Api-Token <token> header |  |
| `netlify-access-token` | `NetlifyAccessToken` | `https://api.netlify.com/api/v1/sites` | Bearer |  |
| `confluent-access-token`, `confluent-secret-key` | `ConfluentAccessToken` | `https://api.confluent.cloud/v1/organizations` | Bearer |  |
| `databricks-api-token` | `DatabricksAPIToken` | `https://api.cloud.databricks.com/api/2.0/clusters/list` | Bearer |  |
| `stripe-access-token` | `StripeAccessToken` | `https://api.stripe.com/v1/charges` | HTTP Basic (secret as username or password) |  |
| `travisci-access-token` | `TravisCIAccessToken` | `https://api.travis-ci.com/user` | token <token> header |  |
| `telegram-bot-api-token` | `TelegramBotAPIToken` | `https://api.telegram.org/bot%s/getMe` | token embedded in the URL path |  |
| `airtable-api-key`, `airtable-personnal-access-token` | `AirtableAPIKey` | `https://api.airtable.com/v0/meta/bases` | Bearer |  |
| `coinbase-access-token` | `CoinbaseAccessToken` | `https://api.coinbase.com/v2/user` | Bearer |  |
| `digitalocean-access-token`, `digitalocean-pat`, `digitalocean-refresh-token` | `DigitalOceanAccessToken` | `https://api.digitalocean.com/v2/account` | Bearer |  |
| `discord-api-token` | `DiscordAPIToken` | `https://discord.com/api/v10/users/@me` | Bot <token> header |  |
| `dropbox-api-token`, `dropbox-long-lived-api-token`, `dropbox-short-lived-api-token` | `DropboxAPIToken` | `https://api.dropboxapi.com/2/users/get_current_account` | Bearer |  |
| `fastly-api-token` | `FastlyAPIToken` | `https://api.fastly.com/current_user` | Fastly-Key header |  |
| `freshbooks-access-token` | `FreshbooksAccessToken` | `https://api.freshbooks.com/auth/api/v1/users/me` | Bearer |  |
| `hubspot-api-key` | `HubspotAPIKey` | `https://api.hubapi.com/integrations/v1/me?hapikey=%s` | token as query param |  |
| `huggingface-access-token`, `huggingface-organization-api-token` | `HuggingFaceAccessToken` | `https://huggingface.co/api/whoami-v2` | Bearer |  |
| `intercom-api-key` | `IntercomAPIKey` | `https://api.intercom.io/me` | Bearer |  |
| `launchdarkly-access-token` | `LaunchDarklyAccessToken` | `https://app.launchdarkly.com/api/v2/account` | Authorization header |  |
| `lob-api-key`, `lob-pub-api-key` | `LobAPIKey` | `https://api.lob.com/v1/addresses` | HTTP Basic (secret as username or password) |  |
| `mailchimp-api-key` | `MailchimpAPIKey` | `https://%s.api.mailchimp.com/3.0/` | HTTP Basic (arbitrary username, key as password) |  |
| `mailgun-private-api-token` | `MailgunAPIToken` | `https://api.mailgun.net/v3/domains` | HTTP Basic (username `api`, key as password) |  |
| `mapbox-api-token` | `MapboxAPIToken` | `https://api.mapbox.com/tokens/v2?access_token=%s` | token as query param |  |
| `messagebird-api-token` | `MessageBirdAPIToken` | `https://rest.messagebird.com/balance` | AccessKey <token> header |  |
| `nytimes-access-token` | `NYTimesAccessToken` | `https://api.nytimes.com/svc/search/v2/articlesearch.json?api-key=%s&q=test` | token as query param |  |
| `okta-access-token` | `OktaAccessToken` | `*(resolved at runtime — see notes)*` | SSWS <token> header | discovers domain/context via FileSearch |
| `planetscale-api-token`, `planetscale-oauth-token` | `PlanetScaleAPIToken` | `https://api.planetscale.com/v1/organizations` | Bearer |  |
| `pulumi-api-token` | `PulumiAPIToken` | `https://api.pulumi.com/api/user` | token <token> header |  |
| `readme-api-token` | `ReadmeAPIToken` | `https://dash.readme.com/api/v1` | HTTP Basic (secret as username or password) |  |
| `rubygems-api-token` | `RubygemsAPIToken` | `https://rubygems.org/api/v1/profile/me.json` | Authorization header |  |
| `sendinblue-api-token` | `SendinblueAPIToken` | `https://api.sendinblue.com/v3/account` | api-key header |  |
| `sentry-access-token`, `sentry-org-token`, `sentry-user-token` | `SentryAccessToken` | `https://sentry.io/api/0/organizations/` | Bearer |  |
| `shippo-api-token` | `ShippoAPIToken` | `https://api.goshippo.com/addresses/` | ShippoToken <token> header |  |
| `shopify-access-token`, `shopify-custom-access-token`, `shopify-private-app-access-token` | `ShopifyAccessToken` | `https://%s/admin/api/2023-10/shop.json` | X-Shopify-Access-Token header | discovers domain/context via FileSearch |
| `snyk-api-token` | `SnykAPIToken` | `https://api.snyk.io/rest/self?version=2024-10-15` | token <token> header |  |
| `square-access-token` | `SquareAccessToken` | `https://connect.squareup.com/v2/locations` | Bearer |  |
| `notion-api-token` | `NotionAPIToken` | `https://api.notion.com/v1/users/me` | Bearer |  |
| `cohere-api-token` | `CohereAPIToken` | `https://api.cohere.ai/v1/models` | Bearer |  |
| `anthropic-api-key`, `anthropic-admin-api-key` | `AnthropicAPIKey` | `https://api.anthropic.com/v1/models` | X-Api-Key header |  |
| `sonar-api-token` | `SonarAPIToken` | `https://sonarcloud.io/api/authentication/validate` | HTTP Basic (secret as username or password) |  |
| `cloudflare-api-key` | `CloudflareAPIKey` | `https://api.cloudflare.com/client/v4/user/tokens/verify` | Bearer |  |
| `datadog-access-token` | `DatadogAccessToken` | `https://api.datadoghq.com/api/v1/validate` | DD-API-KEY header |  |
| `finnhub-access-token` | `FinnhubAccessToken` | `https://finnhub.io/api/v1/quote?symbol=AAPL&token=%s` | token as query param |  |
| `frameio-api-token` | `FrameioAPIToken` | `https://api.frame.io/v2/me` | Bearer |  |
| `gitter-access-token` | `GitterAccessToken` | `https://api.gitter.im/v1/user` | Bearer |  |
| `flutterwave-secret-key` | `FlutterwaveSecretKey` | `https://api.flutterwave.com/v3/transactions` | Bearer |  |
| `contentful-delivery-api-token` | `ContentfulDeliveryAPIToken` | `https://cdn.contentful.com/spaces/%s/environments/master/entries?access_token=%s` | token as query param | discovers domain/context via FileSearch |
| `mattermost-access-token` | `MattermostAccessToken` | `*(resolved at runtime — see notes)*` | Bearer | discovers domain/context via FileSearch |
| `octopus-deploy-api-key` | `OctopusDeployAPIKey` | `*(resolved at runtime — see notes)*` | X-Octopus-ApiKey header | discovers domain/context via FileSearch |
| `duffel-api-token` | `DuffelAPIToken` | `https://api.duffel.com/air/airlines` | Bearer |  |
| `gocardless-api-token` | `GoCardlessAPIToken` | `https://api.gocardless.com/creditors` | Bearer |  |
| `doppler-api-token` | `DopplerAPIToken` | `https://api.doppler.com/v3/me` | Bearer |  |
| `scalingo-api-token` | `ScalingoAPIToken` | `https://auth.scalingo.com/v1/tokens/exchange` | HTTP Basic (empty username, token as password) |  |
| `sidekiq-sensitive-url` | `SidekiqSensitiveURL` | `*(resolved at runtime — see notes)*` | credentials embedded in the leaked URL itself |  |
| `squarespace-access-token` | `SquarespaceAccessToken` | `https://api.squarespace.com/1.0/commerce/orders` | Bearer |  |
| `cisco-meraki-api-key` | `MerakiAPIKey` | `https://api.meraki.com/api/v1/organizations` | Bearer |  |
| `cloudflare-origin-ca-key` | `CloudflareOriginCAKey` | `https://api.cloudflare.com/client/v4/certificates` | X-Auth-User-Service-Key header |  |
| `facebook-access-token`, `facebook-page-access-token` | `FacebookAccessToken` | `https://graph.facebook.com/me?access_token=%s` | token as query param |  |
| `gitlab-cicd-job-token` | `GitlabCICDJobToken` | `*(resolved at runtime — see notes)*` | JOB-TOKEN header |  |
| `gitlab-session-cookie` | `GitlabSessionCookie` | `*(resolved at runtime — see notes)*` | Cookie header |  |
| `linear-api-key` | `LinearAPIKey` | `https://api.linear.app/graphql` | GraphQL (POST + JSON body) |  |
| `sourcegraph-access-token` | `SourcegraphAccessToken` | `https://sourcegraph.com/.api/graphql` | GraphQL (POST + JSON body) |  |
| `flyio-access-token` | `FlyioAccessToken` | `https://api.fly.io/graphql` | Bearer |  |
| `beamer-api-token` | `BeamerAPIToken` | `https://api.getbeamer.com/v0/ping` | Beamer-Api-Key header |  |
| `etsy-access-token` | `EtsyAccessToken` | `https://openapi.etsy.com/v3/application/openapi-ping` | X-Api-Key header |  |
| `prefect-api-token` | `PrefectAPIToken` | `https://api.prefect.cloud/api/me/` | Bearer |  |
| `perplexity-api-key` | `PerplexityAPIKey` | `https://api.perplexity.ai/router/v1/models` | Bearer |  |
| `bitbucket-client-id`, `bitbucket-client-secret` | `BitbucketOAuth` | `https://bitbucket.org/site/oauth2/access_token` | Form POST (OAuth2 client_credentials) | cross-references a paired secret in the same file |
| `linkedin-client-id`, `linkedin-client-secret` | `LinkedInOAuth` | `https://www.linkedin.com/oauth/v2/accessToken` | Form POST (OAuth2 client_credentials) | cross-references a paired secret in the same file |
| `twitter-api-key`, `twitter-api-secret` | `TwitterAppOnly` | `https://api.twitter.com/oauth2/token` | Form POST (OAuth2 client_credentials) | cross-references a paired secret in the same file |
| `sendbird-access-id`, `sendbird-access-token` | `SendbirdAPIToken` | `https://api-%s.sendbird.com/v3/applications/settings/auto_event_message` | Api-Token header | cross-references a paired secret in the same file |
| `sumologic-access-id`, `sumologic-access-token` | `SumoLogicAPIToken` | `https://api.sumologic.com/api/v1/collectors` | HTTP Basic (access id / access key) | cross-references a paired secret in the same file |
| `plaid-client-id`, `plaid-secret-key` | `PlaidClientPair` | `https://production.plaid.com/institutions/get` | JSON POST body | cross-references a paired secret in the same file |
| `gitlab-feed-token` | `GitlabFeedToken` | `*(resolved at runtime — see notes)*` | `feed_token` query param |  |
| `infracost-api-token` | `InfracostAPIToken` | `https://dashboard.api.infracost.io/graphql` | X-Api-Key header |  |
| `adafruit-api-key` | `AdafruitAPIKey` | `https://io.adafruit.com/api/v2/%s/feeds` | X-AIO-Key header | discovers domain/context via FileSearch |
| `looker-client-id`, `looker-client-secret` | `LookerOAuth` | `*(resolved at runtime — see notes)*` | Form POST (OAuth2 client_credentials) | discovers domain/context via FileSearch; cross-references a paired secret in the same file |
| `cloudflare-global-api-key` | `CloudflareGlobalAPIKey` | `https://api.cloudflare.com/client/v4/user` | X-Auth-Email + X-Auth-Key headers | discovers domain/context via FileSearch |
| `algolia-api-key` | `AlgoliaAPIKey` | `https://%s-dsn.algolia.net/1/keys/%s` | X-Algolia-Application-Id + X-Algolia-API-Key headers | discovers domain/context via FileSearch |

## Deliberately not implemented

Roughly a third of the `RuleID`s gitleaks can detect have no entry in
`Validate()`'s map, and `Validate()` returns `false` for them without making
any network call. These fall into four categories:

### 1. Needs a second value gitleaks never captures

Some credentials only work as a pair, but gitleaks' own rule set only ever
captures *one* half as a distinct, matchable string — there is no second
`RuleID` to cross-reference with `FindSecretInFile`. Examples: `twilio-api-key`
(needs the Account SID), `finicity-api-token`/`finicity-client-secret` (needs
a numeric Partner ID that has no rule of its own), `clickhouse-cloud-api-secret-key`
(needs a Key ID), `maxmind-license-key` (needs an Account ID),
`new-relic-insert-key` (needs an Account ID baked into the URL path),
`clojars-api-token` / `adafruit-api-key` without a recoverable username.

### 2. Needs a domain/application ID Huginn cannot discover generically

A handful of pairs (`gitlab-oauth-app-secret`, `settlemint-*`,
`harness-api-key`, `openshift-user-token`, `gitlab-scim-token`,
`gitlab-feature-flag-client-token`, `gitlab-kubernetes-agent-token`) need
either an application/project/cluster identifier with no fixed format to
search for, or a per-customer instance domain with no public, shared
endpoint to fall back to (unlike, say, Okta or Mattermost, where a
`FileSearch` for `*.okta.com`/`*.mattermost.*` reliably recovers it).

### 3. Confirmed by the provider's own docs to be unreliable or unsafe to check this way

- `gitlab-deploy-token` — GitLab's own documentation states deploy tokens
  cannot be used against the public API at all, only against specific
  git/registry/package endpoints that need a project reference Huginn
  doesn't have.
- `adobe-client-id`/`adobe-client-secret` — Adobe IMS's `client_credentials`
  grant requires a product-specific `scope` parameter. Guessing it wrong
  returns `400 invalid_scope` for a *valid* credential too, which would read
  as "successful" under this project's `< 401` success check — a false
  positive, not just a missed validation. Skipped rather than risk that.
- `rapidapi-access-token` — RapidAPI's docs confirm a request without the
  per-API `X-RapidAPI-Host` header fails regardless of key validity.
- `nuget-config-password` — the one GET-able endpoint
  (`/api/v2/verifykey/{id}/{version}`) returns the *same* `403` both for an
  invalid key and for a valid key that simply isn't authorized for the
  probe package Huginn would have to pick — an ambiguous signal either way.

### 4. Not an API-callable credential at all

`jwt`, `jwt-base64`, `private-key`, `pkcs12-file`, `kubernetes-secret-yaml`,
`curl-auth-header`, `curl-auth-user`, `age-secret-key`, `1password-secret-key` —
these are raw artifacts, config fragments, or keys used entirely offline
(e.g. 1Password's local secret key, combined with the account password and
2FA, never alone against an API). There is no "endpoint" to call them
against in the first place.

### 5. Signature-based exchange APIs without a usable key pair

`kraken-access-token`, `kucoin-access-token`/`kucoin-secret-key`,
`bittrex-access-key`/`bittrex-secret-key` need HMAC request signing *and*
either a missing third value (KuCoin's passphrase) or — for Kraken/Bittrex —
gitleaks' own rules don't reliably distinguish which captured string is the
public key vs. the private signing secret, since both rules share the exact
same regex shape.
