# Huginn

![huginn logo](https://github.com/satty-br/huginn/blob/main/huginn.png?raw=true)

### Huginn is a project that validates the secrets found by gitleaks, a tool that detects leaked credentials in git repositories.

### put the project folder in the same directory or set the variable --project

[![Go Reference](https://pkg.go.dev/badge/golang.org/x/example.svg)](https://pkg.go.dev/golang.org/x/example)

Installation
Clone the project repository to your local machine
Install the project dependencies with the command:
````
$ git clone https://github.com/satty-br/huginn
$ cd huginn
$ cd huginn
$ go build

````
Usage

Run the main.py file with the gitleaks results file in JSON format as an argument and set the project folder because I need to search for information within the files:

````
$ ./huginn -help
$ ./huginn --project ./project ./results.json
````

Hugin will read the JSON file and show the details of the secrets on the screen

Hugin will also return a new file output.json with the same format as the gitleaks file, but with an additional property called valid, which can be true or false
If valid is true, it means that Hugin validated the secret and confirmed that it is a valid credential
If valid is false, it means that the secret can be an invalid credential or a false positive, in that case, you need to do a double check

## keys
- [X] adafruit-api-key
- [ ] adobe-client-id
- [ ] adobe-client-secret
- [ ] age-secret-key
- [X] airtable-api-key
- [X] algolia-api-key
- [ ] alibaba-access-key-id
- [ ] alibaba-secret-key
- [ ] asana-client-id
- [X] asana-client-secret
- [X] atlassian-api-token
- [ ] authress-service-client-access-key
- [X] aws-access-token
- [X] beamer-api-token
- [X] bitbucket-client-id
- [X] bitbucket-client-secret
- [ ] bittrex-access-key
- [ ] bittrex-secret-key
- [ ] clojars-api-token
- [ ] codecov-access-token
- [X] coinbase-access-token
- [X] confluent-access-token
- [X] confluent-secret-key
- [X] contentful-delivery-api-token
- [X] databricks-api-token
- [X] datadog-access-token
- [ ] defined-networking-api-token
- [X] digitalocean-access-token
- [X] digitalocean-pat
- [X] digitalocean-refresh-token
- [X] discord-api-token
- [ ] discord-client-id
- [X] discord-client-secret
- [X] doppler-api-token
- [X] droneci-access-token
- [X] dropbox-api-token
- [X] dropbox-long-lived-api-token
- [X] dropbox-short-lived-api-token
- [X] duffel-api-token
- [X] dynatrace-api-token
- [X] easypost-api-token
- [X] easypost-test-api-token
- [X] etsy-access-token
- [X] fastly-api-token
- [ ] finicity-api-token
- [ ] finicity-client-secret
- [X] finnhub-access-token
- [ ] flickr-access-token
- [ ] flutterwave-encryption-key
- [ ] flutterwave-public-key
- [X] flutterwave-secret-key
- [X] frameio-api-token
- [X] freshbooks-access-token
- [X] gcp-api-key
- [X] generic-api-key
- [X] github-app-token
- [X] github-fine-grained-pat
- [X] github-oauth
- [X] github-pat
- [X] github-refresh-token
- [X] gitlab-pat
- [X] gitlab-ptt
- [X] gitlab-rrt
- [X] gitter-access-token
- [X] gocardless-api-token
- [X] grafana-api-key
- [X] grafana-cloud-api-token
- [X] grafana-service-account-token
- [X] hashicorp-tf-api-token
- [X] hashicorp-tf-password
- [X] heroku-api-key
- [X] hubspot-api-key
- [X] huggingface-access-token
- [X] huggingface-organization-api-token
- [X] infracost-api-token
- [X] intercom-api-key
- [X] jfrog-api-key
- [X] jfrog-identity-token
- [ ] jwt
- [ ] jwt-base64
- [ ] kraken-access-token
- [ ] kucoin-access-token
- [ ] kucoin-secret-key
- [X] launchdarkly-access-token
- [X] linear-api-key
- [ ] linear-client-secret
- [X] linkedin-client-id
- [X] linkedin-client-secret
- [X] lob-api-key
- [X] lob-pub-api-key
- [X] mailchimp-api-key
- [X] mailgun-private-api-token
- [ ] mailgun-pub-key
- [ ] mailgun-signing-key
- [X] mapbox-api-token
- [X] mattermost-access-token
- [X] messagebird-api-token
- [ ] messagebird-client-id
- [X] microsoft-teams-webhook
- [X] netlify-access-token
- [X] new-relic-browser-api-token
- [ ] new-relic-user-api-id
- [X] new-relic-user-api-key
- [X] npm-access-token
- [X] nytimes-access-token
- [X] okta-access-token
- [X] openai-api-key
- [ ] plaid-api-token
- [X] plaid-client-id
- [X] plaid-secret-key
- [X] planetscale-api-token
- [X] planetscale-oauth-token
- [ ] planetscale-password
- [X] postman-api-token
- [X] prefect-api-token
- [ ] private-key
- [X] pulumi-api-token
- [X] pypi-upload-token
- [ ] rapidapi-access-token
- [X] readme-api-token
- [X] rubygems-api-token
- [X] scalingo-api-token
- [X] sendbird-access-id
- [X] sendbird-access-token
- [X] sendgrid-api-token
- [X] sendinblue-api-token
- [X] sentry-access-token
- [X] shippo-api-token
- [X] shopify-access-token
- [X] shopify-custom-access-token
- [X] shopify-private-app-access-token
- [ ] shopify-shared-secret
- [ ] sidekiq-secret
- [X] sidekiq-sensitive-url
- [X] slack-app-token
- [X] slack-bot-token
- [X] slack-config-access-token
- [X] slack-config-refresh-token
- [X] slack-legacy-bot-token
- [X] slack-legacy-token
- [X] slack-legacy-workspace-token
- [X] slack-user-token
- [X] slack-webhook-url
- [X] snyk-api-token
- [X] square-access-token
- [X] squarespace-access-token
- [X] stripe-access-token
- [X] sumologic-access-id
- [X] sumologic-access-token
- [X] telegram-bot-api-token
- [X] travisci-access-token
- [ ] twilio-api-key
- [X] twitch-api-token
- [X] twitter-access-secret
- [X] twitter-access-token
- [X] twitter-api-key
- [X] twitter-api-secret
- [X] twitter-bearer-token
- [X] typeform-api-token
- [X] vault-batch-token
- [X] vault-service-token
- [X] yandex-access-token
- [X] yandex-api-key
- [X] yandex-aws-access-token
- [X] zendesk-secret-key
- [ ] 1password-secret-key
- [ ] 1password-service-account-token
- [X] airtable-personnal-access-token
- [X] anthropic-admin-api-key
- [X] anthropic-api-key
- [X] artifactory-api-key
- [X] artifactory-reference-token
- [ ] aws-amazon-bedrock-api-key-long-lived
- [ ] aws-amazon-bedrock-api-key-short-lived
- [ ] azure-ad-client-secret
- [X] cisco-meraki-api-key
- [ ] clickhouse-cloud-api-secret-key
- [X] cloudflare-api-key
- [X] cloudflare-global-api-key
- [X] cloudflare-origin-ca-key
- [X] cohere-api-token
- [ ] curl-auth-header
- [ ] curl-auth-user
- [X] facebook-access-token
- [X] facebook-page-access-token
- [ ] facebook-secret
- [X] flyio-access-token
- [ ] freemius-secret-key
- [X] gitlab-cicd-job-token
- [ ] gitlab-deploy-token
- [ ] gitlab-feature-flag-client-token
- [X] gitlab-feed-token
- [ ] gitlab-incoming-mail-token
- [ ] gitlab-kubernetes-agent-token
- [ ] gitlab-oauth-app-secret
- [X] gitlab-pat-routable
- [X] gitlab-runner-authentication-token
- [X] gitlab-runner-authentication-token-routable
- [ ] gitlab-scim-token
- [X] gitlab-session-cookie
- [ ] harness-api-key
- [X] heroku-api-key-v2
- [ ] intra42-client-secret
- [ ] kubernetes-secret-yaml
- [X] looker-client-id
- [X] looker-client-secret
- [ ] maxmind-license-key
- [ ] new-relic-insert-key
- [X] notion-api-token
- [ ] nuget-config-password
- [X] octopus-deploy-api-key
- [ ] openshift-user-token
- [X] perplexity-api-key
- [ ] pkcs12-file
- [ ] privateai-api-token
- [X] sentry-org-token
- [X] sentry-user-token
- [ ] settlemint-application-access-token
- [ ] settlemint-personal-access-token
- [ ] settlemint-service-access-token
- [X] sonar-api-token
- [X] sourcegraph-access-token
