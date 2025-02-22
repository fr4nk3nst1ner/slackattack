package app

import (
	"flag"
	"fmt"
	"log"
//	"os"

	"github.com/fr4nk3nst1ner/slackattack/internal/auth"
	"github.com/fr4nk3nst1ner/slackattack/internal/banner"
	"github.com/fr4nk3nst1ner/slackattack/internal/slack"
)

type Config struct {
	// Authentication
	Token        string
	Cookie       string
	WorkspaceURL string
	ProxyURL     string

	// Actions
	ListChannels       bool
	ListUsers         bool
	ListFiles         bool
	DownloadFiles     bool
	Pillage           string
	DumpChannel       string
	ListDMs           bool
	DumpDM            string
	ChannelMembership bool
	CheckPermissions  bool
	DumpLogs         bool
	Test             bool

	// Output options
	OutputJSON   string
	OutputDir    string
	NoBanner     bool
	Verbose      bool
	ShowExamples bool
}

func Run() {
	cfg := parseFlags()

	// Show examples if requested and exit early
	if cfg.ShowExamples {
		showUsageExamples()
		return
	}

	// Print banner unless disabled
	banner.Print(cfg.NoBanner)

	// Create credentials
	creds, err := auth.NewCredentials(cfg.Token, cfg.Cookie, cfg.WorkspaceURL, cfg.ProxyURL)
	if err != nil {
		log.Fatal(err)
	}

	// Create Slack client
	client, err := slack.NewClient(creds)
	if err != nil {
		log.Fatal(err)
	}

	// Execute requested actions
	if err := executeActions(client, cfg); err != nil {
		log.Fatal(err)
	}
}

func parseFlags() *Config {
	cfg := &Config{}

	// Authentication flags
	flag.StringVar(&cfg.Token, "token", "", "Slack API token")
	flag.StringVar(&cfg.Cookie, "cookie", "", "Slack cookie")
	flag.StringVar(&cfg.WorkspaceURL, "workspace-url", "", "Workspace URL (required when using cookie)")
	flag.StringVar(&cfg.ProxyURL, "proxy", "", "Proxy URL (optional)")

	// Action flags
	flag.BoolVar(&cfg.ListChannels, "list-channels", false, "Get list of channels")
	flag.BoolVar(&cfg.ListUsers, "list-users", false, "Get list of users")
	flag.BoolVar(&cfg.ListFiles, "list-files", false, "List all files from all channels")
	flag.BoolVar(&cfg.DownloadFiles, "download-files", false, "Download files")
	flag.StringVar(&cfg.Pillage, "pillage", "", "Search channel for secrets (specify channel name or 'all' for all channels)")
	flag.StringVar(&cfg.DumpChannel, "dump-channel", "", "Dump messages from specified channel name")
	flag.BoolVar(&cfg.ListDMs, "list-dm", false, "List all DM channels")
	flag.StringVar(&cfg.DumpDM, "dump-dm", "", "Dump messages from specified DM channel ID (e.g., D04ES1BJ1E3)")
	flag.BoolVar(&cfg.ChannelMembership, "channel-membership", false, "List channel membership and open DM channels")
	flag.BoolVar(&cfg.CheckPermissions, "check-permissions", false, "Check API token permissions")
	flag.BoolVar(&cfg.DumpLogs, "dump-logs", false, "Dump team access logs")
	flag.BoolVar(&cfg.Test, "test", false, "Test Slack credentials")

	// Output flags
	flag.StringVar(&cfg.OutputJSON, "output-json", "", "Save output in JSON format to the specified file")
	flag.StringVar(&cfg.OutputDir, "output-directory", "", "Output directory for downloaded files")
	flag.BoolVar(&cfg.NoBanner, "nobanner", false, "Disable banner output")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&cfg.ShowExamples, "examples", false, "Show detailed examples for all commands")

	// Parse flags
	flag.Parse()

	// If only showing examples, return early
	if cfg.ShowExamples {
		return cfg
	}

	// Validate required flags
	if cfg.Token == "" && cfg.Cookie == "" {
		log.Fatal("Either token or cookie must be provided")
	}

	if cfg.Cookie != "" && cfg.WorkspaceURL == "" {
		log.Fatal("workspace-url is required when using cookie authentication")
	}

	// Validate that at least one action is specified
	if !cfg.hasAction() {
		log.Fatal("At least one action must be specified")
	}

	return cfg
}

func (c *Config) hasAction() bool {
	return c.ListChannels || c.ListUsers || c.ListFiles || c.DownloadFiles ||
		c.Pillage != "" || c.DumpChannel != "" || c.ListDMs || c.DumpDM != "" ||
		c.ChannelMembership || c.CheckPermissions || c.DumpLogs || c.Test
}

func executeActions(client *slack.Client, cfg *Config) error {
	// Test credentials if requested
	if cfg.Test {
		if err := client.TestCredentials(); err != nil {
			return fmt.Errorf("credential test failed: %v", err)
		}
		fmt.Println("Credentials test successful")
	}

	// Check permissions if requested
	if cfg.CheckPermissions {
		if err := client.CheckPermissions(); err != nil {
			return fmt.Errorf("permission check failed: %v", err)
		}
	}

	// Execute other actions
	if cfg.ListChannels {
		if err := client.ListChannels(cfg.OutputJSON); err != nil {
			return err
		}
	}

	if cfg.ListUsers {
		if err := client.ListUsers(cfg.OutputJSON); err != nil {
			return err
		}
	}

	if cfg.ListFiles {
		if err := client.ListFiles(cfg.OutputJSON); err != nil {
			return err
		}
	}

	if cfg.DownloadFiles {
		if err := client.DownloadFiles(cfg.OutputDir); err != nil {
			return err
		}
	}

	if cfg.Pillage != "" {
		if err := client.Pillage(cfg.Pillage, cfg.OutputJSON); err != nil {
			return err
		}
	}

	if cfg.DumpChannel != "" {
		if err := client.DumpChannelMessages(cfg.DumpChannel, cfg.OutputJSON); err != nil {
			return err
		}
	}

	if cfg.ListDMs {
		if err := client.ListDMChannels(cfg.OutputJSON); err != nil {
			return err
		}
	}

	if cfg.DumpDM != "" {
		if err := client.DumpDMMessages(cfg.DumpDM, cfg.OutputJSON); err != nil {
			return err
		}
	}

	if cfg.ChannelMembership {
		if err := client.ListChannelMembership(cfg.OutputJSON); err != nil {
			return err
		}
	}

	if cfg.DumpLogs {
		if err := client.DumpTeamAccessLogs(cfg.OutputJSON); err != nil {
			return err
		}
	}

	return nil
}

func showUsageExamples() {
	examples := `
Slackattack Usage Examples
=========================

Authentication Options:
---------------------
1. Using Bot Token:
   $ slackattack -token xoxb-your-token -check-permissions
   Returns: List of permissions the bot token has access to

2. Using Cookie:
   $ slackattack -cookie "xoxd-your-cookie" -workspace-url https://yourworkspace.slack.com -check-permissions
   Returns: List of permissions the authenticated user has access to

Channel Operations:
-----------------
1. List All Channels:
   $ slackattack -token $token -list-channels
   Returns: List of all visible channels with their IDs and names

2. Dump Channel Messages:
   $ slackattack -token $token -dump-channel general
   Returns: All messages from the specified channel

3. Show Channel Membership:
   $ slackattack -token $token -channel-membership
   Returns: List of channels the bot has access to

DM Operations:
------------
1. List DM Channels:
   $ slackattack -cookie $cookie -workspace-url $workspace -list-dm
   Returns: List of all open DM channel IDs

2. Dump DM Messages:
   $ slackattack -cookie $cookie -workspace-url $workspace -dump-dm D04ES1BJ1E3
   Returns: All messages from the specified DM channel

File Operations:
--------------
1. List Files:
   $ slackattack -token $token -list-files
   Returns: URLs of all accessible files

2. Download Files:
   $ slackattack -token $token -download-files -output-directory ./downloads
   Action: Downloads all accessible files to specified directory

Security Operations:
-----------------
1. Pillage Mode:
   $ slackattack -token $token -pillage all
   Returns: Scans all accessible channels for sensitive information

   $ slackattack -token $token -pillage general
   Returns: Scans specific channel for sensitive information

User Operations:
--------------
1. List Users:
   $ slackattack -token $token -list-users
   Returns: List of all workspace users with their IDs and names

Output Options:
-------------
1. JSON Output:
   Add -output-json output.json to any command to save results in JSON format
   Example: $ slackattack -token $token -list-channels -output-json channels.json

2. Proxy Support:
   Add -proxy http://127.0.0.1:8080 to route traffic through a proxy
   Example: $ slackattack -token $token -list-channels -proxy http://127.0.0.1:8080

3. Disable Banner:
   Add -nobanner to suppress the ASCII art banner
   Example: $ slackattack -token $token -list-channels -nobanner

Notes:
-----
- Bot tokens (xoxb-*) have limited access compared to user cookies
- Some operations (like DM access) require cookie authentication
- Use -verbose flag for detailed error messages and debugging
- All commands support JSON output with -output-json flag
`
	fmt.Println(examples)
} 