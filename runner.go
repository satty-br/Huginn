package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
)

// Runner reads a gitleaks JSON report from file, validates every secret it
// contains against the matching upstream API (searching project for
// contextual hints such as a self-hosted service's domain), and writes the
// same report back out to output.json with a "valid" flag added to each
// entry. It returns an error instead of exiting the process, so a caller
// (including tests) can decide how to react to a bad input file.
func Runner(file string, project string) error {
	// Read the contents of the file.
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading gitleaks file %q: %w", file, err)
	}

	// Unmarshal the JSON data into a slice of Secret structs.
	var secrets []Secret
	if err := json.Unmarshal(data, &secrets); err != nil {
		return fmt.Errorf("parsing gitleaks file %q: %w", file, err)
	}

	validator := &Validator{
		Project: project,
		Secrets: secrets,
	}

	// Iterate over the secrets and validate each one.
	out := make([]Secret, 0, len(secrets))
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
		return fmt.Errorf("encoding output: %w", err)
	}

	// Write the JSON output to a file named "output.json".
	if err := os.WriteFile("output.json", output, 0644); err != nil {
		return fmt.Errorf("writing output.json: %w", err)
	}
	return nil
}
