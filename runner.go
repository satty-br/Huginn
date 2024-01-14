package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
)

// main é o ponto de entrada do programa.
func Runner(file string, project string) {
	// Read the contents of the file.
	data, err := os.ReadFile(file)
	if err != nil {
		// handle error
	}

	// Unmarshal the JSON data into a slice of Secret structs.
	var secrets []Secret
	json.Unmarshal(data, &secrets)

	validator := &Validator{
		Project: project,
		Secrets: secrets,
	}

	// Iterate over the secrets and validate each one.
	var out []Secret
	for _, secret := range secrets {
		if validator.Validate(secret) {
			fmt.Println(color.GreenString("Secret '%s' is valid!", secret.Secret))
			secret.Valid = true
		}
		out = append(out, secret)
	}

	// Marshal the secrets slice into JSON format.
	output, err := json.MarshalIndent(out, "", "    ")
	if err != nil {
		// handle error
		fmt.Println(color.RedString(err.Error()))
	}

	// Write the JSON output to a file named "output.json".
	os.WriteFile("output.json", output, 0644)
}
