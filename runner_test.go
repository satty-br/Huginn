package main

import (
	"os"
	"testing"
)

func TestRunner(t *testing.T) {
	jsonPath := "./test/test.json"
	outputPath := "./"

	// Call the function being tested
	if err := Runner(jsonPath, outputPath); err != nil {
		t.Fatalf("Runner returned an unexpected error: %v", err)
	}
	t.Cleanup(func() { os.Remove("./output.json") })

	// Check the output
	file, err := os.ReadFile("./output.json")
	if err != nil {
		t.Fatalf("Error reading output file: %v", err)
	}
	if len(file) == 0 {
		t.Error("Output file is empty")
	}
}

func TestRunnerMissingFile(t *testing.T) {
	if err := Runner("./test/does-not-exist.json", "./"); err == nil {
		t.Error("expected an error when the gitleaks file does not exist, got nil")
	}
}

func TestRunnerInvalidJSON(t *testing.T) {
	path := filepathJoinTemp(t, "invalid.json", "{not valid json")
	if err := Runner(path, "./"); err == nil {
		t.Error("expected an error when the gitleaks file is not valid JSON, got nil")
	}
}

// filepathJoinTemp writes content to a temp file named name and returns its
// path, registering cleanup with t.
func filepathJoinTemp(t *testing.T, name string, content string) string {
	t.Helper()
	path := t.TempDir() + string(os.PathSeparator) + name
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}
