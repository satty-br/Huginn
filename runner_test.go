package main

import (
	"os"
	"testing"
)

func TestRunner(t *testing.T) {

	jsonPath := "./test/test.json"
	outputPath := "./"

	// Call the function being tested
	Runner(jsonPath, outputPath)

	// Check the output
	file, err := os.ReadFile("./output.json")
	if file == nil {
		t.Error("Output file not found")
	}
	if err != nil {
		t.Error("Error reading output file")
	}

}
