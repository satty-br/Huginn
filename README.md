# Hugin
### Hugin is a project that validates the secrets found by gitleaks, a tool that detects leaked credentials in git repositories.


### put the project folder in the same directory or set the variable --project

Installation
Clone the project repository to your local machine
Install the project dependencies with the command:
````
pip install -r requirements.txt
````
Usage

Run the main.py file with the gitleaks results file in JSON format as an argument and set the project folder because I need to search for information within the files:

````
python main.py --project ./project ./results.json
````

Hugin will read the JSON file and show the details of the secrets on the screen

Hugin will also return a new file output.json with the same format as the gitleaks file, but with an additional property called valid, which can be true or false
If valid is true, it means that Hugin validated the secret and confirmed that it is a valid credential
If valid is false, it means that the secret can be an invalid credential or a false positive, in that case, you need to do a double check
