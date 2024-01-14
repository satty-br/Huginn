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

func (v *Validator) VaultBashToken(secret Secret) bool {
	urlVault := v.FindVaultLink(secret)
	headers := map[string]string{
		"X-Vault-Token": fmt.Sprintf("%s", secret.Secret),
	}
	response := v.Get(fmt.Sprintf("%s/v1/auth/token/lookup-self", urlVault), headers)
	return v.IsResponseSuccessful(response)
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
