package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"slackattack/slack"
)

const version = "1.0.0"

func printBanner(silence bool) {
	if !silence {
		banner := getBanner()
		fmt.Println(banner)
	}
}

func getBanner() string {
	return fmt.Sprintf(`
  █████████  ████                    █████           █████████   █████   █████                     █████
 ███░░░░░███░░███                   ░░███           ███░░░░░███ ░░███   ░░███                     ░░███
░███    ░░░  ░███   ██████    ██████ ░███ █████    ░███    ░███ ███████ ███████   ██████    ██████ ░███ █████
░░█████████  ░███  ░░░░░███  ███░░███░███░░███     ░███████████░░░███░ ░░░███░   ░░░░░███  ███░░███░███░░███
 ░░░░░░░░███ ░███   ███████ ░███ ░░░ ░██████░      ░███░░░░░███  ░███    ░███     ███████ ░███ ░░░ ░██████░
 ███    ░███ ░███  ███░░███ ░███  ███░███░░███     ░███    ░███  ░███ ███░███ ██████░░███ ░███  ███░███░░███
░░█████████  █████░░████████░░██████ ████ █████    █████   █████ ░░█████ ░░█████░░████████░░██████ ████ █████
 ░░░░░░░░░  ░░░░░  ░░░░░░░░  ░░░░░░ ░░░░ ░░░░░    ░░░░░   ░░░░░   ░░░░░   ░░░░░  ░░░░░░░░  ░░░░░░ ░░░░ ░░░░░

Slackattack v%s
By: Jonathan Stines - @fr4nk3nst1ner
`, version)
}

func main() {
	// Command line flags
	token := flag.String("token", "", "Slack API token")
	cookie := flag.String("cookie", "", "User-supplied cookie")
	workspaceURL := flag.String("workspace-url", "", "Workspace URL for authenticating user session token")
	
	// Action flags
	test := flag.Bool("test", false, "Test Slack credentials")
	listUsers := flag.Bool("list-users", false, "Get list of users")
	listChannels := flag.Bool("list-channels", false, "Get list of channels")
	checkPerms := flag.Bool("check-permissions", false, "Check API token permissions")
	listFiles := flag.Bool("list-files", false, "List all files from all channels")
	downloadFiles := flag.Bool("download-files", false, "Download files")
	dumpLogs := flag.Bool("dump-logs", false, "Dump team access logs")
	pillage := flag.Bool("pillage", false, "Search conversations for secrets")
	
	// Other flags
	outputJSON := flag.String("output-json", "", "Save output in JSON format to the specified file")
	outputDir := flag.String("output-directory", "", "Output directory for downloaded files")
	verbose := flag.Bool("verbose", false, "Enable verbose logging for troubleshooting")
	proxy := flag.String("proxy", "", "Specify a proxy (e.g., http://127.0.0.1:8080)")

	// Override default usage to include banner
	flag.Usage = func() {
		printBanner(false)
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	// Check if help is requested
	if len(os.Args) == 1 || (len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help")) {
		flag.Usage()
		os.Exit(0)
	}

	// Validate arguments
	if *token == "" && *cookie == "" {
		fmt.Println("Error: Either --token or --cookie must be provided")
		flag.Usage()
		os.Exit(1)
	}

	if *cookie != "" && *workspaceURL == "" {
		fmt.Println("Error: --workspace-url must be provided when using --cookie")
		flag.Usage()
		os.Exit(1)
	}

	// Initialize credentials
	creds := slack.Credentials{
		Token:        *token,
		Cookie:       *cookie,
		WorkspaceURL: *workspaceURL,
	}

	// Format cookie if provided
	if creds.Cookie != "" {
		creds.Cookie = fmt.Sprintf("d=%s", creds.Cookie)
	}

	// Create new Slack client
	client := slack.NewClient(creds, *proxy, *verbose)

	// Handle commands with error checking
	if *test {
		if err := client.TestCredentials(); err != nil {
			fmt.Printf("Error testing credentials: %v\n", err)
			os.Exit(1)
		}
	}

	if *listUsers {
		if err := client.ListUsers(*outputJSON); err != nil {
			fmt.Printf("Error listing users: %v\n", err)
			os.Exit(1)
		}
	}

	if *listChannels {
		if err := client.ListChannels(*outputJSON); err != nil {
			fmt.Printf("Error listing channels: %v\n", err)
			os.Exit(1)
		}
	}

	if *checkPerms {
		fmt.Println("Starting permissions check...")
		if err := client.CheckPermissions(*outputJSON); err != nil {
			log.Fatalf("Permission check failed: %v", err)
		}
		fmt.Println("Permissions check completed")
	}

	if *listFiles {
		if err := client.ListFiles(*outputJSON); err != nil {
			fmt.Printf("Error listing files: %v\n", err)
			os.Exit(1)
		}
	}

	if *downloadFiles {
		if err := client.DownloadFiles(*outputDir); err != nil {
			fmt.Printf("Error downloading files: %v\n", err)
			os.Exit(1)
		}
	}

	if *dumpLogs {
		if err := client.DumpLogs(*outputJSON); err != nil {
			fmt.Printf("Error dumping logs: %v\n", err)
			os.Exit(1)
		}
	}

	if *pillage {
		if err := client.PillageConversations(*outputJSON); err != nil {
			fmt.Printf("Error pillaging conversations: %v\n", err)
			os.Exit(1)
		}
	}
} 