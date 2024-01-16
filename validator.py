from urllib.parse import urlparse
import requests
import re
from secret import Secret
import boto3
import botocore.exceptions


class Validator:

    def __init__(self, project: str):
        self.project = project

    def file_search(self, secret: Secret, regex: str):
        with open(secret.file, 'r') as file:
            for line in file:
                match = re.search(regex, line)
                if match:
                    return match.group()

    def validate(self,secret: Secret):

        function_map = {
            "zendesk-secret-key": self.zendesk,
            "github-app-token": self.github_App_Token,
            "github-fine-grained-pat": self.github_Token,
            "github-oauth": self.github_Token,
            "github-pat": self.github_Token,
            "github-token": self.github_Token,
            "github-refresh-token": self.github_Token,
            "gitlab-pat": self.gitlab_ApI_Token,
            "gitlab-ptt": self.gitLab_pipeline_Token,
            "gitlab-rrt": self.gitLab_Runner_token,
            "yandex-aws-access-token": self.yandex_AWS_Access_Token,
            "yandex-access-token": self.yandex_ApI_key,
            "yandex-api-key": self.yandex_ApI_key,
            "typeform-api-key": self.typeform_ApI_key,
            "droneci-access-token": self.droneci_access_token,
            "easypost-test-api-token": self.easypost_api_token,
            "easypost-api-token": self.easypost_api_token,
            "gcp-api-key": self.gcp_api_key,
            "grafana-api-key": self.grafana_api_key,
            "grafana-service-account-token": self.grafana_api_key,
            "grafana-cloud-api-key": self.grafana_cloud_api_key,
            "hashicorp-vault-token": self.hashicorp_vault_token,
            "hashicorp-tf-password": self.hashicorp_vault_password,
            "heroku-api-key": self.heroku_api_key,
            "jfrog-api-key": self.jfrog_api_key,
            "jfrog-identity-token": self.jfrog_api_key,
            "aws-access-token": self.aws_token_test,
            "slack-api-token": self.slack_api_token,
            "slack-user-token": self.slack_api_token,
            "slack-app-token": self.slack_api_token,
            "slack-bot-token": self.slack_api_token,
            "slack-config-access-token": self.slack_api_token,
            "slack-config-refresh-token": self.slack_api_token,
            "slack-legacy-bot-token": self.slack_api_token,
            "slack-legacy-token": self.slack_api_token,
            "slack-legacy-workspace-token": self.slack_api_token,
            "openai-api-key": self.openai_api_key,
            "asana-client-secret": self.asana,
            "atlassian-api-token": self.atlassian_api_token,
            "twitter-api-token": self.twitter_api_token,
            "twitter-bearer-token": self.twitter_api_token,
            "twitter-access-token": self.twitter_api_token,
            "twitter-access-secret": self.twitter_api_token,
            "twitch-api-token": self.twitch_api_token,
            "sendgrid-api-token": self.sendgrid_api_token,
            "postman-api-token": self.postman_api_token,
            "pypi-upload-token": self.pypi_upload_token,
            "npm-access-token": self.npm_access_token,
            "new-relic-user-api-key": self.new_relic_user_api_key,
            "new-relic-browser-api-token": self.new_relic_user_api_key,
            "microsoft-teams-webhook": self.microsoft_teams_webhook,
            "discord-client-secret": self.discord_client_secret,
            "dynatrace-api-token": self.dynatrace_api_token,
            "netlify-access-token": self.netlify_access_token,
            "confluent-access-token": self.confluent_access_token,
            "confluent-secret-key": self.confluent_access_token,
            "databricks-api-token": self.databricks_api_token,
            "vault-batch-token": self.vault_bash_token,
            "vault-service-token": self.vault_bash_token,

        }
        return function_map[secret.rule_id](secret)

    def zendesk(self, secret: Secret):
            match = self.file_search(secret, r'https?://[a-z0-9.-]*zendesk.com[a-z0-9./-]*')
            if match:
                parsed_url = urlparse(match)
                zendesk_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                url = f"{zendesk_url}/api/v2/tickets.json"
                headers = {"Authorization": f"Bearer {secret.secret}"}
                response = requests.get(url, headers=headers)
                if response.status_code < 401:
                    return True
            return False

 
    def github_Token(self, secret: Secret):
        url = f"https://api.github.com/user"
        response = requests.get(url, headers={"Authorization",f"token {secret.secret}"} )
        return self.is_response_successful(response)

    def github_App_Token(self, secret: Secret):
        url = "https://api.github.com/repos/"
        response = requests.get(url, headers={"Authorization",f"Bearer {secret.secret}"} )
        return self.is_response_successful(response)

    def gitlab_ApI_Token(self, secret: Secret):
        match = self.file_search(secret, r'https?://[a-z0-9.-]*(git\.|gitlab\.)[a-z0-9./-]*')
        url = f"https://gitlab.com"
        if match:
            parsed_url = urlparse(match)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        url = f"{url}/api/v4/projects?private_token={secret.secret}"
        response = requests.get(url)
        return self.is_response_successful(response)

    def gitLab_pipeline_Token(self, secret: Secret):
        match = self.file_search(secret, r'https?://[a-z0-9.-]*(git\.|gitlab\.)[a-z0-9./-]*')
        url = f"https://gitlab.com"
        if match:
            parsed_url = urlparse(match)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        url = f"{url}/api/v4/projects/1/trigger/pipeline"
        response = requests.post(url, headers={"pRIVATE-TOKEn": secret})
        return self.is_response_successful(response)

    def gitLab_Runner_token(self, secret: Secret):
        match = self.file_search(secret, r'https?://[a-z0-9.-]*(git\.|gitlab\.)[a-z0-9./-]*')
        url = f"https://gitlab.com"
        if match:
            parsed_url = urlparse(match)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        url = f"{url}/api/v4/runners/all?scope=online"
        response = requests.post(url, headers={"pRIVATE-TOKEn": secret})
        return self.is_response_successful(response)

    def yandex_AWS_Access_Token(self, secret: Secret):
        url = f"https://iam.api.cloud.yandex.net/iam/v1/roles"
        data = {"Authorization: Bearer ": secret.secret}
        response = requests.post(url, json=data)
        return self.is_response_successful(response)

    def slack_api_token(self,secret: Secret):
        url = f"https://slack.com/api/auth.test?token={secret.secret}&pretty=1"
        response = requests.post(url)
        return self.is_response_successful(response)
 
    def yandex_ApI_key(self,secret: Secret):
        url = f"https://cloud-api.yandex.net/v1/disk/resources/public"
        headers = {"Authorization": f"OAuth {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)

    def typeform_ApI_key(self,secret: Secret):
        url = f"https://api.typeform.com/me"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)
    
    def droneci_access_token(self,secret: Secret):
        url = f"https://cloud.drone.io/api/user"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)

    def easypost_api_token(self,secret: Secret):
        url = f"https://api.easypost.com/v2/addresses"
        headers = {"Authorization": f"Basic {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)

    def gcp_api_key(self,secret: Secret):
        url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={secret.secret}"
        response = requests.get(url)
        return self.is_response_successful(response)
    
    def grafana_api_key(self,secret: Secret):
        url = "https://grafana.com"
        match = self.file_search(secret, r'https?://[a-z0-9.-]*grafana[a-z0-9./-]*')
        if match:
            parsed_url = urlparse(match)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        headers = {"Authorization": f"Basic {secret.secret}"}
        response = requests.get(f"{url}/api/grafana-auth/user", headers=headers)
        return self.is_response_successful(response)

    def grafana_cloud_api_key(self,secret: Secret):
        headers = {"Authorization": f"Basic {secret.secret}"}
        response = requests.get(f"http://www.grafana.com/api/v1/accesspolicies", headers=headers)
        return self.is_response_successful(response)

    def hashicorp_vault_token(self,secret: Secret):
        url = f"https://vault"
        match = self.file_search(secret, r'https?://[a-z0-9.-]*vault.[a-z0-9./-]*')
        headers = {"X-Vault-Token": f"{secret.secret}"}
        response = requests.get(f"{url}/v1/auth/token/lookup-self", headers=headers)
        return self.is_response_successful(response)

    def hashicorp_vault_password(self,secret: Secret):
        url = f"https://vault"
        match = self.file_search(secret, r'https?://[a-z0-9.-]*vault.[a-z0-9./-]*')
        if match:
            parsed_url = urlparse(match)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        sampleusernames = ["sqladmin", "vaultadmin", "vault"]
        for user in sampleusernames:
            response = requests.post(f"{url}/v1/auth/ldap/login/{user}",data={ "password": secret.secret }, headers={"Content-Type","application/json"})
            if response.status_code < 401:
                return True
        return False

    def heroku_api_key(self,secret: Secret):
        url = f"https://api.heroku.com/account"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)

    def jfrog_api_key(self,secret: Secret):
        match = self.file_search(secret, r'https?://[a-z0-9.-]*(artifactory\.|jfrog\.)[a-z0-9./-]*')
        url = f"https://artifactory"
        if match:
            parsed_url = urlparse(match)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(f"{url}/artifactory/api/system/ping", headers=headers)
        return self.is_response_successful(response)

    def find_aws_region(file_path):
        with open(file_path, 'r') as file:
            content = file.read()
            match = re.search(r'(?<=AWS_REGIOn=)[\'"]?([a-z]{2}-[a-z]+-\d)[\'"]?', content)
            if match:
                return match.group(1)
            else:
                return None

    def aws_token_test( self,secret: Secret):
        region = self.find_aws_region(secret.file)
        if not region:
            return False
        key = self.find_aws_key_and_surrounding_lines(secret.file, secret.secret)
        try:
            # TODO: yeh i know this is not the best way to do this
            client = boto3.client(
                'sts',
                aws_access_key_id=Secret.secret,
                aws_secret_access_key=key,
                region_name='us-east-1'
            )
            response = client.get_caller_identity()
            return True
        except (botocore.exceptions.noCredentialsError , botocore.exceptions.partialCredentialsError, botocore.exceptions.CredentialRetrievalError, botocore.exceptions.TokenRetrievalError):
            return False

    def find_aws_key_and_surrounding_lines(file_path, key):
        with open(file_path, 'r') as file:
            previous_line = None
            for current_line in file:
                if key in current_line:
                    next_line = None
                    while next_line == None or next_line == '\n':
                        next_line = next(file, None)

                    matches = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*[\'"]?([^\'"\n]+)[\'"]?', next_line)
                    if matches:
                        return matches.group(1)
                    else:
                        matches = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*[\'"]?([^\'"\n]+)[\'"]?', previous_line)
                        if matches:
                            return matches.group(1)
                        return None
                if current_line != '\n':
                    previous_line = current_line
        return None, None
    
    def slack_webhook_url(self,secret: Secret):
        response = requests.post(secret.secret, json={"text": "yamete kudasai!"})
        return self.is_response_successful(response)


    def openai_api_key(self,secret: Secret):
        url = f"https://api.openai.com/v1/engines"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(f"{url}/artifactory/api/system/ping", headers=headers)
        return self.is_response_successful(response)

    def is_response_successful(response):
        return response.status_code < 401
    

    def asana(self, secret: Secret):
        match = self.file_search(secret, r'https?://[a-z0-9.-]*asana[a-z0-9./-]*')
        if match:
            parsed_url = urlparse(match)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            headers = {"Authorization": f"Bearer {secret.secret}"}
            response = requests.get(f"{url}/api/1.0/users/me", headers=headers)
            return self.is_response_successful(response)
        return False

    def atlassian_api_token(self, secret: Secret):
        match = self.file_search(secret, r'https?://[a-z0-9.-]*(atlassian\.|confluence\.|jira\.|bitbucket\.)[a-z0-9./-]*')
        if match:
            parsed_url = urlparse(match)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            headers = {"Authorization": f"Bearer {secret.secret}"}
            response = requests.get(f"{url}/rest/api/latest/serverInfo", headers=headers)
            return self.is_response_successful(response)
        return False

    def twitter_api_token(self,secret: Secret):
        url = f"https://api.twitter.com/1.1/statuses/user_timeline.json"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)

    def twitch_api_token(self,secret: Secret):
        url = f"https://api.twitch.tv/helix/users"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)


    def sendgrid_api_token(self,secret: Secret):
        url = "https://api.sendgrid.com/v3/marketing/contacts"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)

    def postman_api_token(self,secret: Secret):
        url = "https://api.getpostman.com/me"
        headers = {"X-Api-Key": f"{secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)
    

    def pypi_upload_token(self,secret: Secret):
        url = "https://upload.pypi.org/legacy/"
        headers = {"Authorization": f"Basic {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)
    
    def npm_access_token(self,secret: Secret):
        url = "https://registry.npmjs.org/-/npm/v1/user"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)
    
    def new_relic_user_api_key(self,secret: Secret):
        url = "https://api.newrelic.com/v2/applications.json"
        headers = {"X-Api-Key": f"{secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)
    
    def netlify_access_token(self,secret: Secret):
        url = "https://api.netlify.com/api/v1/sites"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)
    
    def microsoft_teams_webhook(self,secret: Secret):
        url = secret.secret
        data = {"text": "yamete kudasai!!!"}
        response = requests.post(url, headers={'Content-Type: application/json'}, data=data)
        return self.is_response_successful(response)

    def discord_client_secret(self,secret: Secret):
        url = "https://discord.com/api/v8/users/@me"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)
    
    def dynatrace_api_token(self,secret: Secret):
        url = "https://api.dynatrace.com/api/v1/deployment/installer/agent/connectioninfo"
        headers = {"Authorization": f"Api-Token {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)


    def netlify_access_token(self,secret: Secret):
        url = "https://api.netlify.com/api/v1/sites"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)

    def confluent_access_token(self,secret: Secret):
        url = "https://api.confluent.cloud/v1/organizations"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)

    def databricks_api_token(self,secret: Secret):
        url = "https://api.cloud.databricks.com/api/2.0/clusters/list"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        return self.is_response_successful(response)

    def vault_bash_token(self,secret: Secret):
        url = f"https://vault"
        match = self.file_search(secret, r'https?://[a-z0-9.-]*vault.[a-z0-9./-]*')
        if match:
            parsed_url = urlparse(match)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        headers = {"X-Vault-Token": f"{secret.secret}"}
        response = requests.get(f"{url}/v1/auth/token/lookup-self", headers=headers)
        return self.is_response_successful(response)
       