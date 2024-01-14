// File: golang/validator.go
package huginn

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
)

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

//END OF UTILS FUNCTIONS

func (v *Validator) Validate(secret Secret) bool {
	functionMap := map[string]func(Secret) bool{
		"zendesk-secret-key":            v.Zendesk,
		"github-app-token":              v.GithubAppToken,
		"github-fine-grained-pat":       v.GithubToken,
		"github-oauth":                  v.GithubToken,
		"github-pat":                    v.GithubToken,
		"github-token":                  v.GithubToken,
		"github-refresh-token":          v.GithubToken,
		"gitlab-pat":                    v.GitlabAPIToken,
		"gitlab-ptt":                    v.GitLabPipelineToken,
		"gitlab-rrt":                    v.GitLabRunnerToken,
		"yandex-aws-access-token":       v.YandexAWSAccessToken,
		"yandex-access-token":           v.YandexAPIKey,
		"yandex-api-key":                v.YandexAPIKey,
		"typeform-api-key":              v.TypeformAPIKey,
		"droneci-access-token":          v.DroneCIAccessToken,
		"easypost-test-api-token":       v.EasyPostAPIToken,
		"easypost-api-token":            v.EasyPostAPIToken,
		"gcp-api-key":                   v.GCPAPIKey,
		"grafana-api-key":               v.GrafanaAPIKey,
		"grafana-service-account-token": v.GrafanaAPIKey,
		"grafana-cloud-api-key":         v.GrafanaCloudAPIKey,
		"hashicorp-vault-token":         v.HashicorpVaultToken,
		"hashicorp-tf-password":         v.HashicorpVaultPassword,
		"heroku-api-key":                v.HerokuAPIKey,
		"jfrog-api-key":                 v.JFrogAPIKey,
		"jfrog-identity-token":          v.JFrogAPIKey,
		"aws-access-token":              v.AWSTokenTest,
		"slack-api-token":               v.SlackAPIToken,
		"slack-user-token":              v.SlackAPIToken,
		"slack-app-token":               v.SlackAPIToken,
		"slack-bot-token":               v.SlackAPIToken,
		"slack-config-access-token":     v.SlackAPIToken,
		"slack-config-refresh-token":    v.SlackAPIToken,
		"slack-legacy-bot-token":        v.SlackAPIToken,
		"slack-legacy-token":            v.SlackAPIToken,
		"slack-legacy-workspace-token":  v.SlackAPIToken,
		"slack-webhook-url":             v.SlackWebhookURL,
		"openai-api-key":                v.OpenAIAPIKey,
		"asana-client-secret":           v.Asana,
		"atlassian-api-token":           v.AtlassianAPIToken,
		"twitter-api-token":             v.TwitterAPIToken,
		"twitter-bearer-token":          v.TwitterAPIToken,
		"twitter-access-token":          v.TwitterAPIToken,
		"twitter-access-secret":         v.TwitterAPIToken,
		"twitch-api-token":              v.TwitchAPIToken,
		"sendgrid-api-token":            v.SendgridAPIToken,
		"postman-api-token":             v.PostmanAPIToken,
		"pypi-upload-token":             v.PyPIUploadToken,
		"npm-access-token":              v.NPMAccessToken,
		"new-relic-user-api-key":        v.NewRelicUserAPIKey,
		"new-relic-browser-api-token":   v.NewRelicUserAPIKey,
		"microsoft-teams-webhook":       v.MicrosoftTeamsWebhook,
		"discord-client-secret":         v.DiscordClientSecret,
		"dynatrace-api-token":           v.DynatraceAPIToken,
		"netlify-access-token":          v.NetlifyAccessToken,
		"confluent-access-token":        v.ConfluentAccessToken,
		"confluent-secret-key":          v.ConfluentAccessToken,
		"databricks-api-token":          v.DatabricksAPIToken,
		"vault-batch-token":             v.VaultBashToken,
		"vault-service-token":           v.VaultBashToken,
		"stripe-access-token":           v.StripeAccessToken,
		"travisci-access-token":         v.TravisCIAccessToken,
		"telegram-bot-api-token":        v.TelegramBotAPIToken,
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
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*(git\.|gitlab\.)[a-z0-9./-]*`)
	gitlabUrl := "https://gitlab.com"
	if match != "" {
		parsedURL, _ := url.Parse(match)
		gitlabUrl = v.getparsed(parsedURL.Scheme, parsedURL.Host)
	}
	gitlabUrl = fmt.Sprintf("%s/api/v4/projects?private_token=%s", gitlabUrl, secret.Secret)
	response := v.Get(gitlabUrl, nil)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) GitLabPipelineToken(secret Secret) bool {
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*(git\.|gitlab\.)[a-z0-9./-]*`)
	gitlabUrl := "https://gitlab.com"
	if match != "" {
		parsedURL, _ := url.Parse(match)
		gitlabUrl = v.getparsed(parsedURL.Scheme, parsedURL.Host)
	}
	gitlabUrl = fmt.Sprintf("%s/api/v4/projects/1/trigger/pipeline", gitlabUrl)
	response := v.Post(gitlabUrl, map[string]string{"pRIVATE-TOKEn": secret.Secret})
	return v.IsResponseSuccessful(response)
}

func (v *Validator) GitLabRunnerToken(secret Secret) bool {
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*(git\.|gitlab\.)[a-z0-9./-]*`)
	gitlabUrl := "https://gitlab.com"
	if match != "" {
		parsedURL, _ := url.Parse(match)
		gitlabUrl = v.getparsed(parsedURL.Scheme, parsedURL.Host)
	}
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
	urlVault := "https://vault"
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*vault.[a-z0-9./-]*`)
	if match != "" {
		parsedURL, _ := url.Parse(match)
		urlVault = v.getparsed(parsedURL.Scheme, parsedURL.Host)
	}
	headers := map[string]string{
		"X-Vault-Token": fmt.Sprintf("%s", secret.Secret),
	}
	response := v.Get(fmt.Sprintf("%s/v1/auth/token/lookup-self", urlVault), headers)
	return v.IsResponseSuccessful(response)
}

func (v *Validator) HashicorpVaultPassword(secret Secret) bool {
	urlVault := "https://vault"
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*vault.[a-z0-9./-]*`)
	if match != "" {
		parsedURL, _ := url.Parse(match)
		urlVault = v.getparsed(parsedURL.Scheme, parsedURL.Host)
	}
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
	key := v.FindAWSKeyAndSurroundingLines(secret.File, secret.Secret)
	if key == "" {
		return false
	}
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://sts.amazonaws.com/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/20220101/%s/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=xxx", secret.Secret, region))
	req.Header.Set("x-amz-date", "20220101T000000Z")
	response, err := client.Do(req)
	if err != nil {
		return false
	}
	return v.IsResponseSuccessful(response)
}

func (v *Validator) FindAWSKeyAndSurroundingLines(filePath, key string) string {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}
	lines := regexp.MustCompile(`\r?\n`).Split(string(file), -1)
	var previousLine string
	for _, currentLine := range lines {
		if regexp.MustCompile(key).MatchString(currentLine) {
			var nextLine string
			for nextLine == "" || nextLine == "\n" {
				nextLine = lines[0]
				lines = lines[1:]
			}
			matches := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*[\'"]?([^\'"\n]+)[\'"]?`).FindStringSubmatch(nextLine)
			if len(matches) > 0 {
				return matches[1]
			} else {
				matches := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*[\'"]?([^\'"\n]+)[\'"]?`).FindStringSubmatch(previousLine)
				if len(matches) > 0 {
					return matches[1]
				}
				return ""
			}
		}
		if currentLine != "\n" {
			previousLine = currentLine
		}
	}
	return ""
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

func (v *Validator) VaultBashToken(secret Secret) bool {
	urlVault := "https://vault"
	match := v.FileSearch(secret, `https?://[a-z0-9.-]*vault.[a-z0-9./-]*`)
	if match != "" {
		parsedURL, _ := url.Parse(match)
		urlVault = v.getparsed(parsedURL.Scheme, parsedURL.Host)
	}
	headers := map[string]string{
		"X-Vault-Token": fmt.Sprintf("%s", secret.Secret),
	}
	response := v.Get(fmt.Sprintf("%s/v1/auth/token/lookup-self", urlVault), headers)
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
