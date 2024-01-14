package huginn

import (
	"flag"
	"fmt"
	"os"

	"github.com/fatih/color"
)

// main is the entry point of the program.
func main() {
	// Print the Hugin logo in green color.
	fmt.Println(color.GreenString(`    ██      ██                 ██         
   ░██     ░██          █████ ░░          
   ░██     ░██ ██   ██ ██░░░██ ██ ███████  ███████ 
   ░██████████░██  ░██░██  ░██░██░░██░░░██░░██░░░██
   ░██░░░░░░██░██  ░██░░██████░██ ░██  ░██ ░██  ░██
   ░██     ░██░██  ░██ ░░░░░██░██ ░██  ░██ ░██  ░██
   ░██     ░██░░██████  █████ ░██ ███  ░██ ███  ░██
   ░░      ░░  ░░░░░░  ░░░░░  ░░ ░░░   ░░ ░░░   ░░ 
   `))
	// Print the author's name.
	fmt.Println(color.BlueString("                                    by Satty.com.br"))
	// Print a starting message.
	fmt.Println(color.YellowString("Starting..."))

	// Define command-line flags.
	file := flag.String("file", "", "Gitleaks json output file")
	project := flag.String("project", "./", "Project Folder.")
	flag.Parse()

	// Check if the file flag is empty.
	if *file == "" {
		fmt.Println(color.RedString("The gitleaks file was not specified in the file parameter!"))
		os.Exit(-1)
	}

	// Check if the file exists.
	if _, err := os.Stat(*file); os.IsNotExist(err) {
		fmt.Println(color.RedString("file '%s' not exists!", *file))
		os.Exit(-1)
	}

	Runner(*file, *project)
	fmt.Println(color.GreenString("Done!"))
}
