package test

import (
	"os"
	"testing"

	huginn "github.com/satty-br/Huginn"
)

func TestRunner(t *testing.T) {

	jsonPath := "./test.json"
	outputPath := "./"

	// Call the function being tested
	huginn.Runner(jsonPath, outputPath)

	// Check the output
	file, err := os.ReadFile("./output.json")
	if file == nil {
		t.Error("Output file not found")
	}
	if err != nil {
		t.Error("Error reading output file")
	}

}
