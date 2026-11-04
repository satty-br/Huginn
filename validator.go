// File: golang/validator.go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// PostJSON issues a POST request with a JSON body and arbitrary headers.
// Used by GraphQL-based APIs (Linear, Sourcegraph, Fly.io) that cannot be
// probed with a plain GET request.
func (v *Validator) PostJSON(url string, headers map[string]string, body string) *http.Response {
	client := &http.Client{}
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	response, err := client.Do(req)
	if err != nil {
		return nil
	}
	return response
}

// PostBasicAuth issues a POST request authenticated with HTTP Basic auth and no body.
func (v *Validator) PostBasicAuth(url string, username string, password string) *http.Response {
	client := &http.Client{}
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil
	}
	req.SetBasicAuth(username, password)
	response, err := client.Do(req)
	if err != nil {
		return nil
	}
	return response
}

// PostForm issues a POST request with a form-urlencoded body.
func (v *Validator) PostForm(url string, body string) *http.Response {
	client := &http.Client{}
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(req)
	if err != nil {
		return nil
	}
	return response
}

// PostFormBasicAuth issues a POST request with a form-urlencoded body, authenticated with HTTP Basic auth.
func (v *Validator) PostFormBasicAuth(url string, username string, password string, body string) *http.Response {
	client := &http.Client{}
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(username, password)
	response, err := client.Do(req)
	if err != nil {
		return nil
	}
	return response
}

// FindSecretInFile looks up another secret of a given RuleID discovered in the
// same file, so that validators needing a pair of values (client id + secret,
// access id + token, ...) can reconstruct the pair gitleaks reports separately.
func (v *Validator) FindSecretInFile(filePath string, ruleID string) string {
	for _, s := range v.Secrets {
		if s.File == filePath && s.RuleID == ruleID {
			return s.Secret
		}
	}
	return ""
}

// Secret represents a secret found in a file.
type Secret struct {
	Description string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Match       string
	Secret      string
	File        string
	SymlinkFile string
	Commit      string
	Entropy     float64
	Author      string
	Email       string
	Date        string
	Message     string
	Tags        []string
	RuleID      string
	Fingerprint string
	Valid       bool
}

// Validator is used to validate secrets.
type Validator struct {
	Project string
	Secrets []Secret
}

// UTILS FUNCTIONS
func (v *Validator) FileSearch(secret Secret, regex string) string {
	file, err := os.ReadFile(secret.File)
	if err != nil {
		return ""
	}
	lines := regexp.MustCompile(`\r?\n`).Split(string(file), -1)
	for _, line := range lines {
		match := regexp.MustCompile(regex).FindStringSubmatch(line)
		if len(match) > 0 {
			return match[0]
		}
	}
	return ""
}

func (v *Validator) Post(url string, data map[string]string) *http.Response {
	client := &http.Client{}
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil
	}
	for key, value := range data {
		req.Header.Set(key, value)
	}
	response, err := client.Do(req)
	if err != nil {
		return nil
	}
	return response
}

func (v *Validator) GenericAuth(prefix, secret string) map[string]string {
	return map[string]string{"Authorization": fmt.Sprintf("%s %s", prefix, secret)}
}

func (v *Validator) DefaultBearer(secret string) map[string]string {
	return v.GenericAuth("Bearer", secret)
}

func (v *Validator) DefaultBasic(secret string) map[string]string {
	return v.GenericAuth("Basic", secret)
}

func (v *Validator) Get(url string, headers map[string]string) *http.Response {
	return v.GetAuth(url, headers, "", "")
}

func (v *Validator) GetAuth(url string, headers map[string]string, username string, password string) *http.Response {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if username != "" {
		req.SetBasicAuth(username, password)
	}
	response, err := client.Do(req)
	if err != nil {
		return nil
	}
	return response
}

func (v *Validator) ReturnNone(secret Secret) bool {
	return false
}

func (v *Validator) getparsed(scheme string, host string) string {
	return fmt.Sprintf("%s://%s", scheme, host)
}

func (v *Validator) IsResponseSuccessful(response *http.Response) bool {
	return response.StatusCode < 401
}
func (v *Validator) FindGitlabLink(secret Secret) string {
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*(git\.|gitlab\.)[a-z0-9./-]*`)
	gitlabUrl := "https://gitlab.com"
	if match != "" {
		parsedURL, _ := url.Parse(match)
		gitlabUrl = v.getparsed(parsedURL.Scheme, parsedURL.Host)
	}
	return gitlabUrl
}

func (v *Validator) FindVaultLink(secret Secret) string {
	urlVault := "https://vault"
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*vault.[a-z0-9./-]*`)
	if match != "" {
		parsedURL, _ := url.Parse(match)
		urlVault = v.getparsed(parsedURL.Scheme, parsedURL.Host)
	}
	return urlVault
}

func (v *Validator) hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (v *Validator) hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func (v *Validator) canonicalRequest(req *http.Request) string {
	var canonicalHeaders []string
	for key, values := range req.Header {
		canonicalHeaders = append(canonicalHeaders, strings.ToLower(key)+":"+strings.Join(values, ","))
	}
	return strings.Join([]string{
		req.Method,
		req.URL.Path,
		req.URL.RawQuery,
		strings.Join(canonicalHeaders, "\n") + "\n",
		"content-type;host;x-amz-date",
		hex.EncodeToString(v.hash([]byte(""))),
	}, "\n")
}

//END OF UTILS FUNCTIONS

func (v *Validator) Validate(secret Secret) bool {
	functionMap := map[string]func(Secret) bool{
		"zendesk-secret-key":                          v.Zendesk,
		"github-app-token":                            v.GithubAppToken,
		"github-fine-grained-pat":                     v.GithubToken,
		"github-oauth":                                v.GithubToken,
		"github-pat":                                  v.GithubToken,
		"github-token":                                v.GithubToken,
		"github-refresh-token":                        v.GithubToken,
		"gitlab-pat":                                  v.GitlabAPIToken,
		"gitlab-ptt":                                  v.GitLabPipelineToken,
		"gitlab-rrt":                                  v.GitLabRunnerToken,
		"yandex-aws-access-token":                     v.YandexAWSAccessToken,
		"yandex-access-token":                         v.YandexAPIKey,
		"yandex-api-key":                              v.YandexAPIKey,
		"typeform-api-token":                          v.TypeformAPIKey,
		"droneci-access-token":                        v.DroneCIAccessToken,
		"easypost-test-api-token":                     v.EasyPostAPIToken,
		"easypost-api-token":                          v.EasyPostAPIToken,
		"gcp-api-key":                                 v.GCPAPIKey,
		"grafana-api-key":                             v.GrafanaAPIKey,
		"grafana-service-account-token":               v.GrafanaAPIKey,
		"grafana-cloud-api-token":                     v.GrafanaCloudAPIKey,
		"hashicorp-vault-token":                       v.HashicorpVaultToken,
		"hashicorp-tf-password":                       v.HashicorpVaultPassword,
		"hashicorp-tf-api-token":                      v.HashicorpTFAPIToken,
		"heroku-api-key":                              v.HerokuAPIKey,
		"heroku-api-key-v2":                           v.HerokuAPIKey,
		"jfrog-api-key":                               v.JFrogAPIKey,
		"jfrog-identity-token":                        v.JFrogAPIKey,
		"aws-access-token":                            v.AWSTokenTest,
		"slack-api-token":                             v.SlackAPIToken,
		"slack-user-token":                            v.SlackAPIToken,
		"slack-app-token":                             v.SlackAPIToken,
		"slack-bot-token":                             v.SlackAPIToken,
		"slack-config-access-token":                   v.SlackAPIToken,
		"slack-config-refresh-token":                  v.SlackAPIToken,
		"slack-legacy-bot-token":                      v.SlackAPIToken,
		"slack-legacy-token":                          v.SlackAPIToken,
		"slack-legacy-workspace-token":                v.SlackAPIToken,
		"slack-webhook-url":                           v.SlackWebhookURL,
		"openai-api-key":                              v.OpenAIAPIKey,
		"asana-client-secret":                         v.Asana,
		"atlassian-api-token":                         v.AtlassianAPIToken,
		"twitter-api-token":                           v.TwitterAPIToken,
		"twitter-bearer-token":                        v.TwitterAPIToken,
		"twitter-access-token":                        v.TwitterAPIToken,
		"twitter-access-secret":                       v.TwitterAPIToken,
		"twitch-api-token":                            v.TwitchAPIToken,
		"sendgrid-api-token":                          v.SendgridAPIToken,
		"postman-api-token":                           v.PostmanAPIToken,
		"pypi-upload-token":                           v.PyPIUploadToken,
		"npm-access-token":                            v.NPMAccessToken,
		"new-relic-user-api-key":                      v.NewRelicUserAPIKey,
		"new-relic-browser-api-token":                 v.NewRelicUserAPIKey,
		"microsoft-teams-webhook":                     v.MicrosoftTeamsWebhook,
		"discord-client-secret":                       v.DiscordClientSecret,
		"dynatrace-api-token":                         v.DynatraceAPIToken,
		"netlify-access-token":                        v.NetlifyAccessToken,
		"confluent-access-token":                      v.ConfluentAccessToken,
		"confluent-secret-key":                        v.ConfluentAccessToken,
		"databricks-api-token":                        v.DatabricksAPIToken,
		"vault-batch-token":                           v.HashicorpVaultToken,
		"vault-service-token":                         v.HashicorpVaultToken,
		"stripe-access-token":                         v.StripeAccessToken,
		"travisci-access-token":                       v.TravisCIAccessToken,
		"telegram-bot-api-token":                      v.TelegramBotAPIToken,
		"airtable-api-key":                            v.AirtableAPIKey,
		"coinbase-access-token":                       v.CoinbaseAccessToken,
		"digitalocean-access-token":                   v.DigitalOceanAccessToken,
		"digitalocean-pat":                            v.DigitalOceanAccessToken,
		"digitalocean-refresh-token":                  v.DigitalOceanAccessToken,
		"discord-api-token":                           v.DiscordAPIToken,
		"dropbox-api-token":                           v.DropboxAPIToken,
		"dropbox-long-lived-api-token":                v.DropboxAPIToken,
		"dropbox-short-lived-api-token":               v.DropboxAPIToken,
		"fastly-api-token":                            v.FastlyAPIToken,
		"freshbooks-access-token":                     v.FreshbooksAccessToken,
		"hubspot-api-key":                             v.HubspotAPIKey,
		"huggingface-access-token":                    v.HuggingFaceAccessToken,
		"huggingface-organization-api-token":          v.HuggingFaceAccessToken,
		"intercom-api-key":                            v.IntercomAPIKey,
		"launchdarkly-access-token":                   v.LaunchDarklyAccessToken,
		"lob-api-key":                                 v.LobAPIKey,
		"lob-pub-api-key":                             v.LobAPIKey,
		"mailchimp-api-key":                           v.MailchimpAPIKey,
		"mailgun-private-api-token":                   v.MailgunAPIToken,
		"mapbox-api-token":                            v.MapboxAPIToken,
		"messagebird-api-token":                       v.MessageBirdAPIToken,
		"nytimes-access-token":                        v.NYTimesAccessToken,
		"okta-access-token":                           v.OktaAccessToken,
		"planetscale-api-token":                       v.PlanetScaleAPIToken,
		"planetscale-oauth-token":                     v.PlanetScaleAPIToken,
		"pulumi-api-token":                            v.PulumiAPIToken,
		"readme-api-token":                            v.ReadmeAPIToken,
		"rubygems-api-token":                          v.RubygemsAPIToken,
		"sendinblue-api-token":                        v.SendinblueAPIToken,
		"sentry-access-token":                         v.SentryAccessToken,
		"sentry-org-token":                            v.SentryAccessToken,
		"sentry-user-token":                           v.SentryAccessToken,
		"shippo-api-token":                            v.ShippoAPIToken,
		"shopify-access-token":                        v.ShopifyAccessToken,
		"shopify-custom-access-token":                 v.ShopifyAccessToken,
		"shopify-private-app-access-token":            v.ShopifyAccessToken,
		"snyk-api-token":                              v.SnykAPIToken,
		"square-access-token":                         v.SquareAccessToken,
		"gitlab-pat-routable":                         v.GitlabAPIToken,
		"gitlab-runner-authentication-token":          v.GitLabRunnerToken,
		"gitlab-runner-authentication-token-routable": v.GitLabRunnerToken,
		"notion-api-token":                            v.NotionAPIToken,
		"cohere-api-token":                            v.CohereAPIToken,
		"anthropic-api-key":                           v.AnthropicAPIKey,
		"anthropic-admin-api-key":                     v.AnthropicAPIKey,
		"sonar-api-token":                             v.SonarAPIToken,
		"cloudflare-api-key":                          v.CloudflareAPIKey,
		"datadog-access-token":                        v.DatadogAccessToken,
		"finnhub-access-token":                        v.FinnhubAccessToken,
		"frameio-api-token":                           v.FrameioAPIToken,
		"gitter-access-token":                         v.GitterAccessToken,
		"flutterwave-secret-key":                      v.FlutterwaveSecretKey,
		"contentful-delivery-api-token":               v.ContentfulDeliveryAPIToken,
		"mattermost-access-token":                     v.MattermostAccessToken,
		"octopus-deploy-api-key":                      v.OctopusDeployAPIKey,
		"duffel-api-token":                            v.DuffelAPIToken,
		"gocardless-api-token":                        v.GoCardlessAPIToken,
		"doppler-api-token":                           v.DopplerAPIToken,
		"scalingo-api-token":                          v.ScalingoAPIToken,
		"sidekiq-sensitive-url":                       v.SidekiqSensitiveURL,
		"squarespace-access-token":                    v.SquarespaceAccessToken,
		"cisco-meraki-api-key":                        v.MerakiAPIKey,
		"cloudflare-origin-ca-key":                    v.CloudflareOriginCAKey,
		"facebook-access-token":                       v.FacebookAccessToken,
		"facebook-page-access-token":                  v.FacebookAccessToken,
		"gitlab-cicd-job-token":                       v.GitlabCICDJobToken,
		"gitlab-session-cookie":                       v.GitlabSessionCookie,
		"linear-api-key":                              v.LinearAPIKey,
		"sourcegraph-access-token":                    v.SourcegraphAccessToken,
		"flyio-access-token":                          v.FlyioAccessToken,
		"airtable-personnal-access-token":             v.AirtableAPIKey,
		"artifactory-api-key":                         v.JFrogAPIKey,
		"artifactory-reference-token":                 v.JFrogAPIKey,
		"beamer-api-token":                            v.BeamerAPIToken,
		"etsy-access-token":                           v.EtsyAccessToken,
		"prefect-api-token":                           v.PrefectAPIToken,
		"perplexity-api-key":                          v.PerplexityAPIKey,
		"bitbucket-client-id":                         v.BitbucketOAuth,
		"bitbucket-client-secret":                     v.BitbucketOAuth,
		"linkedin-client-id":                          v.LinkedInOAuth,
		"linkedin-client-secret":                      v.LinkedInOAuth,
		"twitter-api-key":                             v.TwitterAppOnly,
		"twitter-api-secret":                          v.TwitterAppOnly,
		"sendbird-access-id":                          v.SendbirdAPIToken,
		"sendbird-access-token":                       v.SendbirdAPIToken,
		"sumologic-access-id":                         v.SumoLogicAPIToken,
		"sumologic-access-token":                      v.SumoLogicAPIToken,
		"plaid-client-id":                             v.PlaidClientPair,
		"plaid-secret-key":                            v.PlaidClientPair,
		"gitlab-feed-token":                           v.GitlabFeedToken,
		"infracost-api-token":                         v.InfracostAPIToken,
		"adafruit-api-key":                            v.AdafruitAPIKey,
		"looker-client-id":                            v.LookerOAuth,
		"looker-client-secret":                        v.LookerOAuth,
		"cloudflare-global-api-key":                   v.CloudflareGlobalAPIKey,
		"algolia-api-key":                             v.AlgoliaAPIKey,
	}

	fn := functionMap[secret.RuleID]
	if fn != nil {
		return fn(secret)
	}
	return false
}

func (v *Validator) Zendesk(secret Secret) bool {
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*zendesk.com[a-z0-9./-]*`)
	if match != "" {
		parsedURL, _ := url.Parse(match)
		zendeskURL := v.getparsed(parsedURL.Scheme, parsedURL.Host) // Assign the result of getparsed to zendeskURL
		url := fmt.Sprintf("%s/api/v2/tickets.json", zendeskURL)
		headers := v.DefaultBearer(secret.Secret)
		response := v.Get(url, headers)
		return response.StatusCode < 401
	}

	return false
}

func (v *Validator) GithubToken(secret Secret) bool {
	url := "https://api.github.com/user"
	headers := map[string]string{
		"Authorization": fmt.Sprintf("token %s", secret.Secret),
	}
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) GithubAppToken(secret Secret) bool {
	url := "https://api.github.com/repos/"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) GitlabAPIToken(secret Secret) bool {
	gitlabUrl := v.FindGitlabLink(secret)
	gitlabUrl = fmt.Sprintf("%s/api/v4/projects?private_token=%s", gitlabUrl, secret.Secret)
	response := v.Get(gitlabUrl, nil)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) GitLabPipelineToken(secret Secret) bool {
	gitlabUrl := v.FindGitlabLink(secret)
	gitlabUrl = fmt.Sprintf("%s/api/v4/projects/1/trigger/pipeline", gitlabUrl)
	response := v.Post(gitlabUrl, map[string]string{"pRIVATE-TOKEn": secret.Secret})
	return v.IsResponseSuccessful(response)
}

func (v *Validator) GitLabRunnerToken(secret Secret) bool {
	gitlabUrl := v.FindGitlabLink(secret)
	gitlabUrl = fmt.Sprintf("%s/api/v4/runners/all?scope=online", gitlabUrl)
	response := v.Post(gitlabUrl, map[string]string{"pRIVATE-TOKEn": secret.Secret})
	return v.IsResponseSuccessful(response)
}

func (v *Validator) YandexAWSAccessToken(secret Secret) bool {
	url := "https://iam.api.cloud.yandex.net/iam/v1/roles"
	data := v.DefaultBearer(secret.Secret)
	response := v.Post(url, data)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) SlackAPIToken(secret Secret) bool {
	url := fmt.Sprintf("https://slack.com/api/auth.test?token=%s&pretty=1", secret.Secret)
	response := v.Post(url, nil)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) YandexAPIKey(secret Secret) bool {
	url := "https://cloud-api.yandex.net/v1/disk/resources/public"
	headers := map[string]string{
		"Authorization": fmt.Sprintf("OAuth %s", secret.Secret),
	}
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) TypeformAPIKey(secret Secret) bool {
	url := "https://api.typeform.com/me"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) DroneCIAccessToken(secret Secret) bool {
	url := "https://cloud.drone.io/api/user"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) EasyPostAPIToken(secret Secret) bool {
	url := "https://api.easypost.com/v2/addresses"
	headers := v.DefaultBasic(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) GCPAPIKey(secret Secret) bool {
	url := fmt.Sprintf("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s", secret.Secret)
	response := v.Get(url, nil)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) GrafanaAPIKey(secret Secret) bool {
	urlGrafana := "https://grafana.com"
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*grafana[a-z0-9./-]*`)
	if match != "" {
		parsedURL, _ := url.Parse(match)
		urlGrafana = v.getparsed(parsedURL.Scheme, parsedURL.Host)
	}
	headers := v.DefaultBasic(secret.Secret)
	response := v.Get(fmt.Sprintf("%s/api/grafana-auth/user", urlGrafana), headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) GrafanaCloudAPIKey(secret Secret) bool {
	headers := v.DefaultBasic(secret.Secret)
	response := v.Get("http://www.grafana.com/api/v1/accesspolicies", headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) HashicorpVaultToken(secret Secret) bool {
	urlVault := v.FindVaultLink(secret)
	headers := map[string]string{
		"X-Vault-Token": fmt.Sprintf("%s", secret.Secret),
	}
	response := v.Get(fmt.Sprintf("%s/v1/auth/token/lookup-self", urlVault), headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) HashicorpVaultPassword(secret Secret) bool {
	urlVault := v.FindVaultLink(secret)
	sampleUsernames := []string{"sqladmin", "vaultadmin", "vault", "admin"}
	for _, user := range sampleUsernames {
		response := v.Post(fmt.Sprintf("%s/v1/auth/ldap/login/%s", urlVault, user), map[string]string{"password": secret.Secret})
		if response.StatusCode < 401 {
			return true
		}
	}
	return false
}

func (v *Validator) HerokuAPIKey(secret Secret) bool {
	url := "https://api.heroku.com/account"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) JFrogAPIKey(secret Secret) bool {
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*(artifactory\.|jfrog\.)[a-z0-9./-]*`)
	urlArtifactory := "https://artifactory"
	if match != "" {
		parsedURL, _ := url.Parse(match)
		urlArtifactory = v.getparsed(parsedURL.Scheme, parsedURL.Host)
	}
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(fmt.Sprintf("%s/artifactory/api/system/ping", urlArtifactory), headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) FindAWSRegion(filePath string) string {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}
	content := string(file)
	match := regexp.MustCompile(`(?<=AWS_REGIOn=)[\'"]?([a-z]{2}-[a-z]+-\d)[\'"]?`).FindStringSubmatch(content)
	if len(match) > 0 {
		return match[1]
	} else {
		return ""
	}
}

func (v *Validator) AWSTokenTest(secret Secret) bool {
	region := v.FindAWSRegion(secret.File)
	if region == "" {
		return false
	}
	keys := v.FindAWSKeyInFile(secret.File)
	if len(keys) > 0 {
		return false
	}
	valid := false
	for _, key := range keys {
		client := &http.Client{}
		req, err := http.NewRequest("GET", "https://sts.amazonaws.com/", nil)
		if err != nil {
			//like a ninja
		}

		t := time.Now().UTC()
		amzDate := t.Format("20060102T150405Z")
		dateStamp := t.Format("20060102")
		canonicalRequest := v.canonicalRequest(req)
		req.Header.Set("Authorization", v.generateAwsAuthorizationHeader(secret.Secret, key, region, amzDate, dateStamp, canonicalRequest))

		req.Header.Set("x-amz-date", amzDate)
		response, err := client.Do(req)
		if err != nil {
			//like a ninja
		}
		if v.IsResponseSuccessful(response) {
			valid = true
		}
	}
	return valid
}

func (v *Validator) generateAwsAuthorizationHeader(accessKey, secretKey, region, amzDate, dateStamp, canonicalRequest string) string {
	service := "sts"
	algorithm := "AWS4-HMAC-SHA256"
	stringToSign := strings.Join([]string{
		algorithm,
		amzDate,
		strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/"),
		hex.EncodeToString(v.hash([]byte(canonicalRequest))),
	}, "\n")
	kDate := v.hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := v.hmacSHA256(kDate, []byte(region))
	kService := v.hmacSHA256(kRegion, []byte(service))
	kSigning := v.hmacSHA256(kService, []byte("aws4_request"))
	return fmt.Sprintf("%s Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%s",
		algorithm,
		accessKey,
		dateStamp,
		region,
		service,
		"content-type;host;x-amz-date",
		hex.EncodeToString(v.hmacSHA256(kSigning, []byte(stringToSign))),
	)
}

func (v *Validator) FindAWSKeyInFile(filePath string) []string {
	ret := []string{}
	for _, secret := range v.Secrets {
		if secret.File == filePath && secret.RuleID == "generic-api-key" {
			ret = append(ret, secret.Secret)
		}
	}
	return ret
}

func (v *Validator) SlackWebhookURL(secret Secret) bool {
	response := v.Post(secret.Secret, map[string]string{"text": "yamete kudasai!"})
	return v.IsResponseSuccessful(response)
}

func (v *Validator) OpenAIAPIKey(secret Secret) bool {
	url := "https://api.openai.com/v1/engines"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(fmt.Sprintf("%s/artifactory/api/system/ping", url), headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) Asana(secret Secret) bool {
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*asana[a-z0-9./-]*`)
	if match != "" {
		parsedURL, _ := url.Parse(match)
		url := v.getparsed(parsedURL.Scheme, parsedURL.Host)
		headers := v.DefaultBearer(secret.Secret)
		response := v.Get(fmt.Sprintf("%s/api/1.0/users/me", url), headers)
		return v.IsResponseSuccessful(response)
	}
	return false
}

func (v *Validator) AtlassianAPIToken(secret Secret) bool {
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*(atlassian\.|confluence\.|jira\.|bitbucket\.)[a-z0-9./-]*`)
	if match != "" {
		parsedURL, _ := url.Parse(match)
		url := v.getparsed(parsedURL.Scheme, parsedURL.Host)
		headers := v.DefaultBearer(secret.Secret)
		response := v.Get(fmt.Sprintf("%s/rest/api/latest/serverInfo", url), headers)
		return v.IsResponseSuccessful(response)
	}
	return false
}

func (v *Validator) TwitterAPIToken(secret Secret) bool {
	url := "https://api.twitter.com/1.1/statuses/user_timeline.json"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) TwitchAPIToken(secret Secret) bool {
	url := "https://api.twitch.tv/helix/users"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) SendgridAPIToken(secret Secret) bool {
	url := "https://api.sendgrid.com/v3/marketing/contacts"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) PostmanAPIToken(secret Secret) bool {
	url := "https://api.getpostman.com/me"
	headers := map[string]string{
		"X-Api-Key": fmt.Sprintf("%s", secret.Secret),
	}
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) PyPIUploadToken(secret Secret) bool {
	url := "https://upload.pypi.org/legacy/"
	headers := v.DefaultBasic(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) NPMAccessToken(secret Secret) bool {
	url := "https://registry.npmjs.org/-/npm/v1/user"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) NewRelicUserAPIKey(secret Secret) bool {
	url := "https://api.newrelic.com/v2/applications.json"
	headers := map[string]string{
		"X-Api-Key": fmt.Sprintf("%s", secret.Secret),
	}
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) NetlifyAccessToken(secret Secret) bool {
	url := "https://api.netlify.com/api/v1/sites"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) MicrosoftTeamsWebhook(secret Secret) bool {
	url := secret.Secret
	data := map[string]string{
		"text": "yamete kudasai!!!",
	}
	response := v.Post(url, data)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) DiscordClientSecret(secret Secret) bool {
	url := "https://discord.com/api/v8/users/@me"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) DynatraceAPIToken(secret Secret) bool {
	url := "https://api.dynatrace.com/api/v1/deployment/installer/agent/connectioninfo"
	headers := v.GenericAuth("Api-Token", secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) ConfluentAccessToken(secret Secret) bool {
	url := "https://api.confluent.cloud/v1/organizations"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) DatabricksAPIToken(secret Secret) bool {
	url := "https://api.cloud.databricks.com/api/2.0/clusters/list"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) StripeAccessToken(secret Secret) bool {
	url := "https://api.stripe.com/v1/charges"
	response := v.GetAuth(url, make(map[string]string), secret.Secret, "")
	return v.IsResponseSuccessful(response)
}

func (v *Validator) TravisCIAccessToken(secret Secret) bool {
	url := "https://api.travis-ci.com/user"
	headers := v.GenericAuth("token", secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) TelegramBotAPIToken(secret Secret) bool {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/getMe", secret.Secret)
	response := v.Get(url, nil)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) HashicorpTFAPIToken(secret Secret) bool {
	url := "https://app.terraform.io/api/v2/account/details"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) AirtableAPIKey(secret Secret) bool {
	url := "https://api.airtable.com/v0/meta/bases"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) CoinbaseAccessToken(secret Secret) bool {
	url := "https://api.coinbase.com/v2/user"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) DigitalOceanAccessToken(secret Secret) bool {
	url := "https://api.digitalocean.com/v2/account"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) DiscordAPIToken(secret Secret) bool {
	url := "https://discord.com/api/v10/users/@me"
	headers := v.GenericAuth("Bot", secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) DropboxAPIToken(secret Secret) bool {
	url := "https://api.dropboxapi.com/2/users/get_current_account"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Post(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) FastlyAPIToken(secret Secret) bool {
	url := "https://api.fastly.com/current_user"
	headers := map[string]string{"Fastly-Key": secret.Secret}
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) FreshbooksAccessToken(secret Secret) bool {
	url := "https://api.freshbooks.com/auth/api/v1/users/me"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) HubspotAPIKey(secret Secret) bool {
	url := fmt.Sprintf("https://api.hubapi.com/integrations/v1/me?hapikey=%s", secret.Secret)
	response := v.Get(url, nil)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) HuggingFaceAccessToken(secret Secret) bool {
	url := "https://huggingface.co/api/whoami-v2"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) IntercomAPIKey(secret Secret) bool {
	url := "https://api.intercom.io/me"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) LaunchDarklyAccessToken(secret Secret) bool {
	url := "https://app.launchdarkly.com/api/v2/account"
	headers := map[string]string{"Authorization": secret.Secret}
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) LobAPIKey(secret Secret) bool {
	url := "https://api.lob.com/v1/addresses"
	response := v.GetAuth(url, make(map[string]string), secret.Secret, "")
	return v.IsResponseSuccessful(response)
}

func (v *Validator) MailchimpAPIKey(secret Secret) bool {
	parts := strings.Split(secret.Secret, "-")
	if len(parts) < 2 {
		return false
	}
	datacenter := parts[len(parts)-1]
	url := fmt.Sprintf("https://%s.api.mailchimp.com/3.0/", datacenter)
	response := v.GetAuth(url, make(map[string]string), "anystring", secret.Secret)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) MailgunAPIToken(secret Secret) bool {
	url := "https://api.mailgun.net/v3/domains"
	response := v.GetAuth(url, make(map[string]string), "api", secret.Secret)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) MapboxAPIToken(secret Secret) bool {
	url := fmt.Sprintf("https://api.mapbox.com/tokens/v2?access_token=%s", secret.Secret)
	response := v.Get(url, nil)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) MessageBirdAPIToken(secret Secret) bool {
	url := "https://rest.messagebird.com/balance"
	headers := v.GenericAuth("AccessKey", secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) NYTimesAccessToken(secret Secret) bool {
	url := fmt.Sprintf("https://api.nytimes.com/svc/search/v2/articlesearch.json?api-key=%s&q=test", secret.Secret)
	response := v.Get(url, nil)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) OktaAccessToken(secret Secret) bool {
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*okta[a-z0-9./-]*`)
	if match == "" {
		return false
	}
	parsedURL, _ := url.Parse(match)
	oktaURL := v.getparsed(parsedURL.Scheme, parsedURL.Host)
	headers := v.GenericAuth("SSWS", secret.Secret)
	response := v.Get(fmt.Sprintf("%s/api/v1/users/me", oktaURL), headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) PlanetScaleAPIToken(secret Secret) bool {
	url := "https://api.planetscale.com/v1/organizations"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) PulumiAPIToken(secret Secret) bool {
	url := "https://api.pulumi.com/api/user"
	headers := v.GenericAuth("token", secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) ReadmeAPIToken(secret Secret) bool {
	url := "https://dash.readme.com/api/v1"
	response := v.GetAuth(url, make(map[string]string), secret.Secret, "")
	return v.IsResponseSuccessful(response)
}

func (v *Validator) RubygemsAPIToken(secret Secret) bool {
	url := "https://rubygems.org/api/v1/profile/me.json"
	headers := map[string]string{"Authorization": secret.Secret}
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) SendinblueAPIToken(secret Secret) bool {
	url := "https://api.sendinblue.com/v3/account"
	headers := map[string]string{"api-key": secret.Secret}
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) SentryAccessToken(secret Secret) bool {
	url := "https://sentry.io/api/0/organizations/"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) ShippoAPIToken(secret Secret) bool {
	url := "https://api.goshippo.com/addresses/"
	headers := v.GenericAuth("ShippoToken", secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) ShopifyAccessToken(secret Secret) bool {
	match := v.FileSearch(secret, `[a-z0-9-]+\.myshopify\.com`)
	if match == "" {
		return false
	}
	headers := map[string]string{"X-Shopify-Access-Token": secret.Secret}
	response := v.Get(fmt.Sprintf("https://%s/admin/api/2023-10/shop.json", match), headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) SnykAPIToken(secret Secret) bool {
	url := "https://api.snyk.io/rest/self?version=2024-10-15"
	headers := v.GenericAuth("token", secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) SquareAccessToken(secret Secret) bool {
	url := "https://connect.squareup.com/v2/locations"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) NotionAPIToken(secret Secret) bool {
	url := "https://api.notion.com/v1/users/me"
	headers := v.DefaultBearer(secret.Secret)
	headers["Notion-Version"] = "2022-06-28"
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) CohereAPIToken(secret Secret) bool {
	url := "https://api.cohere.ai/v1/models"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) AnthropicAPIKey(secret Secret) bool {
	url := "https://api.anthropic.com/v1/models"
	headers := map[string]string{
		"x-api-key":         secret.Secret,
		"anthropic-version": "2023-06-01",
	}
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) SonarAPIToken(secret Secret) bool {
	url := "https://sonarcloud.io/api/authentication/validate"
	response := v.GetAuth(url, make(map[string]string), secret.Secret, "")
	return v.IsResponseSuccessful(response)
}

func (v *Validator) CloudflareAPIKey(secret Secret) bool {
	url := "https://api.cloudflare.com/client/v4/user/tokens/verify"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) DatadogAccessToken(secret Secret) bool {
	url := "https://api.datadoghq.com/api/v1/validate"
	headers := map[string]string{"DD-API-KEY": secret.Secret}
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) FinnhubAccessToken(secret Secret) bool {
	url := fmt.Sprintf("https://finnhub.io/api/v1/quote?symbol=AAPL&token=%s", secret.Secret)
	response := v.Get(url, nil)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) FrameioAPIToken(secret Secret) bool {
	url := "https://api.frame.io/v2/me"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) GitterAccessToken(secret Secret) bool {
	url := "https://api.gitter.im/v1/user"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) FlutterwaveSecretKey(secret Secret) bool {
	url := "https://api.flutterwave.com/v3/transactions"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) ContentfulDeliveryAPIToken(secret Secret) bool {
	match := v.FileSearch(secret, `(?i)[a-z0-9.-]*contentful\.com/spaces/[a-z0-9]+`)
	if match == "" {
		return false
	}
	parts := strings.Split(match, "/spaces/")
	if len(parts) < 2 {
		return false
	}
	spaceID := parts[1]
	url := fmt.Sprintf("https://cdn.contentful.com/spaces/%s/environments/master/entries?access_token=%s", spaceID, secret.Secret)
	response := v.Get(url, nil)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) MattermostAccessToken(secret Secret) bool {
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*mattermost[a-z0-9./-]*`)
	if match == "" {
		return false
	}
	parsedURL, _ := url.Parse(match)
	mattermostURL := v.getparsed(parsedURL.Scheme, parsedURL.Host)
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(fmt.Sprintf("%s/api/v4/users/me", mattermostURL), headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) OctopusDeployAPIKey(secret Secret) bool {
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*octopus[a-z0-9./-]*`)
	if match == "" {
		return false
	}
	parsedURL, _ := url.Parse(match)
	octopusURL := v.getparsed(parsedURL.Scheme, parsedURL.Host)
	headers := map[string]string{"X-Octopus-ApiKey": secret.Secret}
	response := v.Get(fmt.Sprintf("%s/api/users/me", octopusURL), headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) DuffelAPIToken(secret Secret) bool {
	url := "https://api.duffel.com/air/airlines"
	headers := v.DefaultBearer(secret.Secret)
	headers["Duffel-Version"] = "v2"
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) GoCardlessAPIToken(secret Secret) bool {
	url := "https://api.gocardless.com/creditors"
	headers := v.DefaultBearer(secret.Secret)
	headers["GoCardless-Version"] = "2015-07-06"
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) DopplerAPIToken(secret Secret) bool {
	url := "https://api.doppler.com/v3/me"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) ScalingoAPIToken(secret Secret) bool {
	url := "https://auth.scalingo.com/v1/tokens/exchange"
	response := v.PostBasicAuth(url, "", secret.Secret)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) SidekiqSensitiveURL(secret Secret) bool {
	response := v.Get(secret.Secret, nil)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) SquarespaceAccessToken(secret Secret) bool {
	url := "https://api.squarespace.com/1.0/commerce/orders"
	headers := v.DefaultBearer(secret.Secret)
	headers["User-Agent"] = "huginn-secret-validator"
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) MerakiAPIKey(secret Secret) bool {
	url := "https://api.meraki.com/api/v1/organizations"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) CloudflareOriginCAKey(secret Secret) bool {
	url := "https://api.cloudflare.com/client/v4/certificates"
	headers := map[string]string{"X-Auth-User-Service-Key": secret.Secret}
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) FacebookAccessToken(secret Secret) bool {
	url := fmt.Sprintf("https://graph.facebook.com/me?access_token=%s", secret.Secret)
	response := v.Get(url, nil)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) GitlabCICDJobToken(secret Secret) bool {
	gitlabUrl := v.FindGitlabLink(secret)
	headers := map[string]string{"JOB-TOKEN": secret.Secret}
	response := v.Get(fmt.Sprintf("%s/api/v4/job", gitlabUrl), headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) GitlabSessionCookie(secret Secret) bool {
	gitlabUrl := v.FindGitlabLink(secret)
	headers := map[string]string{"Cookie": fmt.Sprintf("_gitlab_session=%s", secret.Secret)}
	response := v.Get(fmt.Sprintf("%s/api/v4/user", gitlabUrl), headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) LinearAPIKey(secret Secret) bool {
	url := "https://api.linear.app/graphql"
	headers := map[string]string{"Authorization": secret.Secret}
	response := v.PostJSON(url, headers, `{"query":"{ viewer { id } }"}`)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) SourcegraphAccessToken(secret Secret) bool {
	url := "https://sourcegraph.com/.api/graphql"
	headers := v.GenericAuth("token", secret.Secret)
	response := v.PostJSON(url, headers, `{"query":"query { currentUser { username } }"}`)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) FlyioAccessToken(secret Secret) bool {
	url := "https://api.fly.io/graphql"
	headers := v.DefaultBearer(secret.Secret)
	response := v.PostJSON(url, headers, `{"query":"query { viewer { email } }"}`)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) BeamerAPIToken(secret Secret) bool {
	url := "https://api.getbeamer.com/v0/ping"
	headers := map[string]string{"Beamer-Api-Key": secret.Secret}
	response := v.Post(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) EtsyAccessToken(secret Secret) bool {
	url := "https://openapi.etsy.com/v3/application/openapi-ping"
	headers := map[string]string{"x-api-key": secret.Secret}
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) PrefectAPIToken(secret Secret) bool {
	url := "https://api.prefect.cloud/api/me/"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) PerplexityAPIKey(secret Secret) bool {
	url := "https://api.perplexity.ai/router/v1/models"
	headers := v.DefaultBearer(secret.Secret)
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}

// BitbucketOAuth validates a Bitbucket OAuth consumer by exchanging the
// client id/secret pair (discovered together in the same file) for an
// access token via the client_credentials grant.
func (v *Validator) BitbucketOAuth(secret Secret) bool {
	var clientID, clientSecret string
	if secret.RuleID == "bitbucket-client-id" {
		clientID = secret.Secret
		clientSecret = v.FindSecretInFile(secret.File, "bitbucket-client-secret")
	} else {
		clientSecret = secret.Secret
		clientID = v.FindSecretInFile(secret.File, "bitbucket-client-id")
	}
	if clientID == "" || clientSecret == "" {
		return false
	}
	response := v.PostFormBasicAuth("https://bitbucket.org/site/oauth2/access_token", clientID, clientSecret, "grant_type=client_credentials")
	return v.IsResponseSuccessful(response)
}

// LinkedInOAuth validates a LinkedIn OAuth app via the 2-legged
// client_credentials grant, using the id/secret pair found in the same file.
func (v *Validator) LinkedInOAuth(secret Secret) bool {
	var clientID, clientSecret string
	if secret.RuleID == "linkedin-client-id" {
		clientID = secret.Secret
		clientSecret = v.FindSecretInFile(secret.File, "linkedin-client-secret")
	} else {
		clientSecret = secret.Secret
		clientID = v.FindSecretInFile(secret.File, "linkedin-client-id")
	}
	if clientID == "" || clientSecret == "" {
		return false
	}
	body := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s", url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	response := v.PostForm("https://www.linkedin.com/oauth/v2/accessToken", body)
	return v.IsResponseSuccessful(response)
}

// TwitterAppOnly validates a Twitter/X OAuth1 consumer key/secret pair by
// requesting an app-only bearer token.
func (v *Validator) TwitterAppOnly(secret Secret) bool {
	var apiKey, apiSecret string
	if secret.RuleID == "twitter-api-key" {
		apiKey = secret.Secret
		apiSecret = v.FindSecretInFile(secret.File, "twitter-api-secret")
	} else {
		apiSecret = secret.Secret
		apiKey = v.FindSecretInFile(secret.File, "twitter-api-key")
	}
	if apiKey == "" || apiSecret == "" {
		return false
	}
	response := v.PostFormBasicAuth("https://api.twitter.com/oauth2/token", apiKey, apiSecret, "grant_type=client_credentials")
	return v.IsResponseSuccessful(response)
}

// SendbirdAPIToken validates a Sendbird application API token together with
// the application id (access id) found in the same file.
func (v *Validator) SendbirdAPIToken(secret Secret) bool {
	var appID, token string
	if secret.RuleID == "sendbird-access-id" {
		appID = secret.Secret
		token = v.FindSecretInFile(secret.File, "sendbird-access-token")
	} else {
		token = secret.Secret
		appID = v.FindSecretInFile(secret.File, "sendbird-access-id")
	}
	if appID == "" || token == "" {
		return false
	}
	apiUrl := fmt.Sprintf("https://api-%s.sendbird.com/v3/applications/settings/auto_event_message", appID)
	headers := map[string]string{"Api-Token": token}
	response := v.Get(apiUrl, headers)
	return v.IsResponseSuccessful(response)
}

// SumoLogicAPIToken validates a Sumo Logic access id/key pair found in the
// same file via HTTP Basic auth against the default US1 deployment.
func (v *Validator) SumoLogicAPIToken(secret Secret) bool {
	var accessID, accessKey string
	if secret.RuleID == "sumologic-access-id" {
		accessID = secret.Secret
		accessKey = v.FindSecretInFile(secret.File, "sumologic-access-token")
	} else {
		accessKey = secret.Secret
		accessID = v.FindSecretInFile(secret.File, "sumologic-access-id")
	}
	if accessID == "" || accessKey == "" {
		return false
	}
	response := v.GetAuth("https://api.sumologic.com/api/v1/collectors", make(map[string]string), accessID, accessKey)
	return v.IsResponseSuccessful(response)
}

// PlaidClientPair validates a Plaid client_id/secret pair (no item access
// token required) against the institutions/get endpoint.
func (v *Validator) PlaidClientPair(secret Secret) bool {
	var clientID, clientSecret string
	if secret.RuleID == "plaid-client-id" {
		clientID = secret.Secret
		clientSecret = v.FindSecretInFile(secret.File, "plaid-secret-key")
	} else {
		clientSecret = secret.Secret
		clientID = v.FindSecretInFile(secret.File, "plaid-client-id")
	}
	if clientID == "" || clientSecret == "" {
		return false
	}
	body := fmt.Sprintf(`{"client_id":"%s","secret":"%s","country_codes":["US"],"count":1,"offset":0}`, clientID, clientSecret)
	response := v.PostJSON("https://production.plaid.com/institutions/get", nil, body)
	return v.IsResponseSuccessful(response)
}

// GitlabFeedToken validates a GitLab personal feed token against the
// Atom activity feed. An invalid/missing token redirects to the sign-in
// page instead of returning a 401, so it needs an exact 200 check.
func (v *Validator) GitlabFeedToken(secret Secret) bool {
	gitlabUrl := v.FindGitlabLink(secret)
	apiUrl := fmt.Sprintf("%s/dashboard/issues?feed_token=%s&format=atom", gitlabUrl, secret.Secret)
	response := v.Get(apiUrl, nil)
	if response == nil {
		return false
	}
	return response.StatusCode == 200
}

// InfracostAPIToken validates an Infracost Cloud API key against the
// dashboard GraphQL API using the universal __typename introspection field,
// which is valid against any GraphQL schema and needs no knowledge of
// Infracost's own query shape.
func (v *Validator) InfracostAPIToken(secret Secret) bool {
	url := "https://dashboard.api.infracost.io/graphql"
	headers := map[string]string{"X-Api-Key": secret.Secret}
	response := v.PostJSON(url, headers, `{"query":"{ __typename }"}`)
	return v.IsResponseSuccessful(response)
}

// AdafruitAPIKey tries to recover the Adafruit IO username from a nearby
// io.adafruit.com URL in the same file (the HTTP API is scoped per user),
// then checks the key against that user's feed list.
func (v *Validator) AdafruitAPIKey(secret Secret) bool {
	match := v.FileSearch(secret, `(?i)io\.adafruit\.com/[a-zA-Z0-9_-]+/`)
	if match == "" {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(match, "/"), "/")
	username := parts[len(parts)-1]
	headers := map[string]string{"X-AIO-Key": secret.Secret}
	response := v.Get(fmt.Sprintf("https://io.adafruit.com/api/v2/%s/feeds", username), headers)
	return v.IsResponseSuccessful(response)
}

// LookerOAuth validates a Looker API3 client id/secret pair against the
// instance domain discovered in the same file.
func (v *Validator) LookerOAuth(secret Secret) bool {
	var clientID, clientSecret string
	if secret.RuleID == "looker-client-id" {
		clientID = secret.Secret
		clientSecret = v.FindSecretInFile(secret.File, "looker-client-secret")
	} else {
		clientSecret = secret.Secret
		clientID = v.FindSecretInFile(secret.File, "looker-client-id")
	}
	if clientID == "" || clientSecret == "" {
		return false
	}
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*looker[a-z0-9./-]*`)
	if match == "" {
		return false
	}
	parsedURL, _ := url.Parse(match)
	lookerURL := v.getparsed(parsedURL.Scheme, parsedURL.Host)
	body := fmt.Sprintf("client_id=%s&client_secret=%s", url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	response := v.PostForm(fmt.Sprintf("%s/api/4.0/login", lookerURL), body)
	return v.IsResponseSuccessful(response)
}

// CloudflareGlobalAPIKey tries to recover an account email from the same
// file as the leaked Global API Key, since Cloudflare's legacy auth scheme
// requires both X-Auth-Email and X-Auth-Key together.
func (v *Validator) CloudflareGlobalAPIKey(secret Secret) bool {
	match := v.FileSearch(secret, `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	if match == "" {
		return false
	}
	headers := map[string]string{
		"X-Auth-Email": match,
		"X-Auth-Key":   secret.Secret,
	}
	response := v.Get("https://api.cloudflare.com/client/v4/user", headers)
	return v.IsResponseSuccessful(response)
}

// AlgoliaAPIKey tries to recover the Application ID that must accompany an
// Algolia API key by looking, on the same line as the leaked key, for the
// 10-character uppercase identifier Algolia SDKs are typically initialized
// with (e.g. algoliasearch("APPID123X", "<key>")).
func (v *Validator) AlgoliaAPIKey(secret Secret) bool {
	match := v.FileSearch(secret, `(?i)algolia[^\n]{0,80}?\b([A-Z0-9]{10})\b`)
	if match == "" {
		return false
	}
	appIDRegexp := regexp.MustCompile(`\b[A-Z0-9]{10}\b`)
	appID := appIDRegexp.FindString(match)
	if appID == "" {
		return false
	}
	url := fmt.Sprintf("https://%s-dsn.algolia.net/1/keys/%s", strings.ToLower(appID), secret.Secret)
	headers := map[string]string{
		"X-Algolia-Application-Id": appID,
		"X-Algolia-API-Key":        secret.Secret,
	}
	response := v.Get(url, headers)
	return v.IsResponseSuccessful(response)
}
