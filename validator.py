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
            "github-app-token": self.Github_App_Token,
            "github-fine-grained-pat": self.Github_Token,
            "github-oauth": self.Github_Token,
            "github-pat": self.Github_Token,
            "github-token": self.Github_Token,
            "github-refresh-token": self.Github_Token,
            "gitlab-pat": self.Gitlab_API_Token,
            "gitlab-ptt": self.GitLab_Pipeline_Token,
            "gitlab-rrt": self.GitLab_Runner_token,
            "yandex-aws-access-token": self.Yandex_AWS_Access_Token,
            "slack-api-token": self.Slack_api_token,
            "slack-user-token": self.Slack_api_token,
            "yandex-access-token": self.Yandex_API_key,
            "yandex-api-key": self.Yandex_API_key,
            "typeform-api-key": self.Typeform_API_key,
            "droneci-access-token": self.Droneci_access_token,
            "easypost-test-api-token": self.EasyPost_api_token,
            "easypost-api-token": self.EasyPost_api_token,
            "gcp-api-key": self.Gcp_api_key,
            "grafana-api-key": self.Grafana_api_key,
            "grafana-service-account-token": self.Grafana_api_key,
            "grafana-cloud-api-key": self.Grafana_cloud_api_key,
            "hashicorp-vault-token": self.Hashicorp_vault_token,
            "hashicorp-tf-password": self.Hashicorp_vault_password,
            "heroku-api-key": self.Heroku_api_key,
            "jfrog-api-key": self.Jfrog_api_key,
            "jfrog-identity-token": self.Jfrog_api_key,
            "aws-access-token": self.AWS_token_test,

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

 
    def Github_Token(self, secret: Secret):
        url = f"https://api.github.com/user"
        response = requests.get(url, headers={"Authorization",f"token {secret.secret}"} )
        if response.status_code < 401:
            return True
        return False

    def Github_App_Token(self, secret: Secret):
        url = "https://api.github.com/repos/"
        response = requests.get(url, headers={"Authorization",f"Bearer {secret.secret}"} )
        if response.status_code < 401:
            return True
        return False

    def Gitlab_API_Token(self, secret: Secret):
        match = self.file_search(secret, r'https?://[a-z0-9.-]*(git\.|gitlab\.)[a-z0-9./-]*')
        url = f"https://gitlab.com"
        if match:
            parsed_url = urlparse(match)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        url = f"{url}/api/v4/projects?private_token={secret.secret}"
        response = requests.get(url)
        if response.status_code < 401:
            return True
        return False

    def GitLab_Pipeline_Token(self, secret: Secret):
        match = self.file_search(secret, r'https?://[a-z0-9.-]*(git\.|gitlab\.)[a-z0-9./-]*')
        url = f"https://gitlab.com"
        if match:
            parsed_url = urlparse(match)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        url = f"{url}/api/v4/projects/1/trigger/pipeline"
        response = requests.post(url, headers={"PRIVATE-TOKEN": secret})
        if response.status_code < 401:
            return True
        return False

    def GitLab_Runner_token(self, secret: Secret):
        match = self.file_search(secret, r'https?://[a-z0-9.-]*(git\.|gitlab\.)[a-z0-9./-]*')
        url = f"https://gitlab.com"
        if match:
            parsed_url = urlparse(match)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        url = f"{url}/api/v4/runners/all?scope=online"
        response = requests.post(url, headers={"PRIVATE-TOKEN": secret})
        if response.status_code < 401:
            return True
        return False

    def Yandex_AWS_Access_Token(self, secret: Secret):
        url = f"https://iam.api.cloud.yandex.net/iam/v1/roles"
        data = {"Authorization: Bearer ": secret.secret}
        response = requests.post(url, json=data)
        if response.status_code < 401:
            return True
        return False

    def Slack_api_token(self,secret: Secret):
        url = f"https://slack.com/api/auth.test?token={secret.secret}&pretty=1"
        response = requests.post(url)
        if response.status_code < 401:
            return True
        return False
 
    def Yandex_API_key(self,secret: Secret):
        url = f"https://cloud-api.yandex.net/v1/disk/resources/public"
        headers = {"Authorization": f"OAuth {secret.secret}"}
        response = requests.get(url, headers=headers)
        if response.status_code < 401:
            return True
        return False

    def Typeform_API_key(self,secret: Secret):
        url = f"https://api.typeform.com/me"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        if response.status_code < 401:
            return True
        return False
    
    def Droneci_access_token(self,secret: Secret):
        url = f"https://cloud.drone.io/api/user"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        if response.status_code < 401:
            return True
        return False

    def EasyPost_api_token(self,secret: Secret):
        url = f"https://api.easypost.com/v2/addresses"
        headers = {"Authorization": f"Basic {secret.secret}"}
        response = requests.get(url, headers=headers)
        if response.status_code < 401:
            return True
        return False

    def Gcp_api_key(self,secret: Secret):
        url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={secret.secret}"
        response = requests.get(url)
        if response.status_code < 401:
            return True
        return False
    
    def Grafana_api_key(self,secret: Secret):
        url = "https://grafana.com"
        match = self.file_search(secret, r'https?://[a-z0-9.-]*grafana[a-z0-9./-]*')
        if match:
            parsed_url = urlparse(match)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        headers = {"Authorization": f"Basic {secret.secret}"}
        response = requests.get(f"{url}/api/grafana-auth/user", headers=headers)
        if response.status_code < 401:
            return True
        return False

    def Grafana_cloud_api_key(self,secret: Secret):
        headers = {"Authorization": f"Basic {secret.secret}"}
        response = requests.get(f"http://www.grafana.com/api/v1/accesspolicies", headers=headers)
        if response.status_code < 401:
            return True
        return False

    def Hashicorp_vault_token(self,secret: Secret):
        url = f"https://vault"
        match = self.file_search(secret, r'https?://[a-z0-9.-]*vault.[a-z0-9./-]*')
        headers = {"X-Vault-Token": f"{secret.secret}"}
        response = requests.get(f"{url}/v1/auth/token/lookup-self", headers=headers)
        if response.status_code < 401:
            return True
        return False

    def Hashicorp_vault_password(self,secret: Secret):
        url = f"https://vault"
        match = self.file_search(secret, r'https?://[a-z0-9.-]*vault.[a-z0-9./-]*')
        sampleusernames = ["sqladmin", "vaultadmin", "vault"]
        for user in sampleusernames:
            response = requests.post(f"{url}/v1/auth/ldap/login/{user}",data={ "password": secret.secret }, headers={"Content-Type","application/json"})
            if response.status_code < 401:
                return True
        return False

    def Heroku_api_key(self,secret: Secret):
        url = f"https://api.heroku.com/account"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(url, headers=headers)
        if response.status_code < 401:
            return True
        return False

    def Jfrog_api_key(self,secret: Secret):
        match = self.file_search(secret, r'https?://[a-z0-9.-]*(artifactory\.|jfrog\.)[a-z0-9./-]*')
        url = f"https://artifactory"
        if match:
            parsed_url = urlparse(match)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        headers = {"Authorization": f"Bearer {secret.secret}"}
        response = requests.get(f"{url}/artifactory/api/system/ping", headers=headers)
        if response.status_code < 401:
            return True
        return False

    def find_aws_region(file_path):
        with open(file_path, 'r') as file:
            content = file.read()
            match = re.search(r'(?<=AWS_REGION=)[\'"]?([a-z]{2}-[a-z]+-\d)[\'"]?', content)
            if match:
                return match.group(1)
            else:
                return None

    def AWS_token_test( self,secret: Secret):
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
        except (botocore.exceptions.NoCredentialsError , botocore.exceptions.PartialCredentialsError, botocore.exceptions.CredentialRetrievalError, botocore.exceptions.TokenRetrievalError):
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