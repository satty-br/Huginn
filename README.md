# Hugin
### Hugin is a project that validates the secrets found by gitleaks, a tool that detects leaked credentials in git repositories.

Requirements
Python 3.8 or higher
Gitleaks 7.6.1 or higher
Installation
Clone the project repository to your local machine
Install the project dependencies with the command:
````
pip install -r requirements.txt
````
Usage
Run the main.py file with the gitleaks results file in JSON format as an argument:

````
python main.py ./results.json
````

Hugin will read the JSON file and show the details of the secrets on the screen

Hugin will also return a new file output.json with the same format as the gitleaks file, but with an additional property called isvalid, which can be true or false
If isvalid is true, it means that Hugin validated the secret and confirmed that it is a valid credential
If isvalid is false, it means that the secret can be an invalid credential or a false positive, in that case, you need to do a double check
