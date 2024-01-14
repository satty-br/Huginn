package readme

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

func main() {
	fileerror := "Error reading file:"
	// Carregue o arquivo rules.toml
	text, err := os.ReadFile("../rules.toml")
	if err != nil {
		fmt.Println(fileerror, err)
		return
	}

	ruleIDs := findRuleIDs(string(text))

	validatorContent, err := os.ReadFile("../validator.go")
	if err != nil {
		fmt.Println(fileerror, err)
		return
	}

	markdownLines := make([]string, 0)
	for _, ruleID := range ruleIDs {
		if strings.Contains(string(validatorContent), ruleID) {
			markdownLines = append(markdownLines, fmt.Sprintf("- [X] %s", ruleID))
		} else {
			markdownLines = append(markdownLines, fmt.Sprintf("- [ ] %s", ruleID))
		}
	}

	readmeContent, err := os.ReadFile("../README.md")
	if err != nil {
		fmt.Println(fileerror, err)
		return
	}

	parts := strings.SplitN(string(readmeContent), "## keys", 2)
	newReadmeContent := parts[0] + "## keys\n" + strings.Join(markdownLines, "\n")
	err = os.WriteFile("../README.md", []byte(newReadmeContent), 0644)
	if err != nil {
		fmt.Println("Error writing file:", err)
		return
	}
}

func findRuleIDs(text string) []string {
	re := regexp.MustCompile(`\[\[rules\]\]\s*id\s*=\s*"([^"]*)"`)
	matches := re.FindAllStringSubmatch(text, -1)
	ruleIDs := make([]string, 0)
	for _, match := range matches {
		ruleIDs = append(ruleIDs, match[1])
	}
	return ruleIDs
}
