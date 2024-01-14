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
- [ ] adafruit-api-key
- [ ] adobe-client-id
- [ ] adobe-client-secret
- [ ] age secret key
- [ ] airtable-api-key
- [ ] algolia-api-key
- [ ] alibaba-access-key-id
- [ ] alibaba-secret-key
- [ ] asana-client-id
- [X] asana-client-secret
- [X] atlassian-api-token
- [ ] authress-service-client-access-key
- [X] aws-access-token
- [ ] beamer-api-token
- [ ] bitbucket-client-id
- [ ] bitbucket-client-secret
- [ ] bittrex-access-key
- [ ] bittrex-secret-key
- [ ] clojars-api-token
- [ ] codecov-access-token
- [ ] coinbase-access-token
- [X] confluent-access-token
- [X] confluent-secret-key
- [ ] contentful-delivery-api-token
- [X] databricks-api-token
- [ ] datadog-access-token
- [ ] defined-networking-api-token
- [ ] digitalocean-access-token
- [ ] digitalocean-pat
- [ ] digitalocean-refresh-token
- [ ] discord-api-token
- [ ] discord-client-id
- [X] discord-client-secret
- [ ] doppler-api-token
- [X] droneci-access-token
- [ ] dropbox-api-token
- [ ] dropbox-long-lived-api-token
- [ ] dropbox-short-lived-api-token
- [ ] duffel-api-token
- [X] dynatrace-api-token
- [X] easypost-api-token
- [X] easypost-test-api-token
- [ ] etsy-access-token
- [ ] facebook
- [ ] fastly-api-token
- [ ] finicity-api-token
- [ ] finicity-client-secret
- [ ] finnhub-access-token
- [ ] flickr-access-token
- [ ] flutterwave-encryption-key
- [ ] flutterwave-public-key
- [ ] flutterwave-secret-key
- [ ] frameio-api-token
- [ ] freshbooks-access-token
- [X] gcp-api-key
- [ ] generic-api-key
- [X] github-app-token
- [X] github-fine-grained-pat
- [X] github-oauth
- [X] github-pat
- [X] github-refresh-token
- [X] gitlab-pat
- [X] gitlab-ptt
- [X] gitlab-rrt
- [ ] gitter-access-token
- [ ] gocardless-api-token
- [X] grafana-api-key
- [ ] grafana-cloud-api-token
- [X] grafana-service-account-token
- [ ] hashicorp-tf-api-token
- [X] hashicorp-tf-password
- [X] heroku-api-key
- [ ] hubspot-api-key
- [ ] huggingface-access-token
- [ ] huggingface-organization-api-token
- [ ] infracost-api-token
- [ ] intercom-api-key
- [X] jfrog-api-key
- [X] jfrog-identity-token
- [ ] jwt
- [ ] jwt-base64
- [ ] kraken-access-token
- [ ] kucoin-access-token
- [ ] kucoin-secret-key
- [ ] launchdarkly-access-token
- [ ] linear-api-key
- [ ] linear-client-secret
- [ ] linkedin-client-id
- [ ] linkedin-client-secret
- [ ] lob-api-key
- [ ] lob-pub-api-key
- [ ] mailchimp-api-key
- [ ] mailgun-private-api-token
- [ ] mailgun-pub-key
- [ ] mailgun-signing-key
- [ ] mapbox-api-token
- [ ] mattermost-access-token
- [ ] messagebird-api-token
- [ ] messagebird-client-id
- [X] microsoft-teams-webhook
- [X] netlify-access-token
- [X] new-relic-browser-api-token
- [ ] new-relic-user-api-id
- [X] new-relic-user-api-key
- [X] npm-access-token
- [ ] nytimes-access-token
- [ ] okta-access-token
- [X] openai-api-key
- [ ] plaid-api-token
- [ ] plaid-client-id
- [ ] plaid-secret-key
- [ ] planetscale-api-token
- [ ] planetscale-oauth-token
- [ ] planetscale-password
- [X] postman-api-token
- [ ] prefect-api-token
- [ ] private-key
- [ ] pulumi-api-token
- [X] pypi-upload-token
- [ ] rapidapi-access-token
- [ ] readme-api-token
- [ ] rubygems-api-token
- [ ] scalingo-api-token
- [ ] sendbird-access-id
- [ ] sendbird-access-token
- [X] sendgrid-api-token
- [ ] sendinblue-api-token
- [ ] sentry-access-token
- [ ] shippo-api-token
- [ ] shopify-access-token
- [ ] shopify-custom-access-token
- [ ] shopify-private-app-access-token
- [ ] shopify-shared-secret
- [ ] sidekiq-secret
- [ ] sidekiq-sensitive-url
- [X] slack-app-token
- [X] slack-bot-token
- [X] slack-config-access-token
- [X] slack-config-refresh-token
- [X] slack-legacy-bot-token
- [X] slack-legacy-token
- [X] slack-legacy-workspace-token
- [X] slack-user-token
- [X] slack-webhook-url
- [ ] snyk-api-token
- [ ] square-access-token
- [ ] squarespace-access-token
- [X] stripe-access-token
- [ ] sumologic-access-id
- [ ] sumologic-access-token
- [X] telegram-bot-api-token
- [X] travisci-access-token
- [ ] twilio-api-key
- [X] twitch-api-token
- [X] twitter-access-secret
- [X] twitter-access-token
- [ ] twitter-api-key
- [ ] twitter-api-secret
- [X] twitter-bearer-token
- [ ] typeform-api-token
- [X] vault-batch-token
- [X] vault-service-token
- [X] yandex-access-token
- [X] yandex-api-key
- [X] yandex-aws-access-token
- [X] zendesk-secret-key