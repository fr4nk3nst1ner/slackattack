package slack

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fr4nk3nst1ner/slackattack/internal/models"
)

// ListChannels lists all accessible channels
func (c *Client) ListChannels(outputJSON string) error {
	cursor := ""
	for {
		var queryParam string
		if cursor != "" {
			queryParam = "?types=public_channel,private_channel,mpim,im&cursor=" + cursor
		}
		result, err := c.makeRequest("https://slack.com/api/conversations.list"+queryParam, "POST", "")
		if err != nil {
			return fmt.Errorf("failed to list channels: %v", err)
		}

		channels, ok := result["channels"].([]interface{})
		if !ok {
			return fmt.Errorf("no channels found in response")
		}

		var channelList []models.Channel
		for _, ch := range channels {
			if channelMap, ok := ch.(map[string]interface{}); ok {
				channel := models.Channel{
					ID:          getString(channelMap, "id"),
					Name:        getString(channelMap, "name"),
					MemberCount: getInt(channelMap, "num_members"),
					Created:     getInt64(channelMap, "created"),
					Creator:     getString(channelMap, "creator"),
					IsMember:    getBool(channelMap, "is_member"),
				}
				channelList = append(channelList, channel)
			}
		}

		if outputJSON != "" {
			return writeJSON(outputJSON, channelList)
		}

		// Print to stdout
		fmt.Println("\nList of Channels:")
		for _, channel := range channelList {
			fmt.Printf("\nChannel Details:\n")
			fmt.Printf("  Name: %s\n", channel.Name)
			fmt.Printf("  ID: %s\n", channel.ID)
			fmt.Printf("  Member Count: %d\n", channel.MemberCount)
			fmt.Printf("  Creator: %s\n", channel.Creator)
			fmt.Printf("  Is Member: %v\n", channel.IsMember)
		}
		//Handle pagination
		if metadata, ok := result["response_metadata"].(map[string]interface{}); ok {
			if nextCursor, ok := metadata["next_cursor"].(string); ok && nextCursor != "" {
				cursor = nextCursor
			} else {
				break
			}
		} else {
			break
		}
	}
	return nil
}

// ListUsers lists all workspace users
func (c *Client) ListUsers(outputJSON, outputCSV string) error {
	var users []interface{}
	cursor := ""

	for {
		endpoint := "https://slack.com/api/users.list?limit=200"
		if cursor != "" {
			endpoint += "&cursor=" + cursor
		}
		result, err := c.makeRequest(endpoint, "POST", "")
		if err != nil {
			return fmt.Errorf("failed to list users: %v", err)
		}
		members, ok := result["members"].([]interface{})
		if !ok {
			return fmt.Errorf("no users found in response")
		}
		users = append(users, members...)

		meta, _ := result["response_metadata"].(map[string]interface{})
		next, _ := meta["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}

	var userList []map[string]string
	for _, user := range users {
		if userMap, ok := user.(map[string]interface{}); ok {
			profile, _ := userMap["profile"].(map[string]interface{})

			formattedUser := map[string]string{
				"User ID":          getString(userMap, "id"),
				"Username":         getString(userMap, "name"),
				"Real Name":        getString(userMap, "real_name"),
				"Display Name":     getString(profile, "display_name"),
				"Email":            getString(profile, "email"),
				"Is Admin":         formatBool(getBool(userMap, "is_admin")),
				"Is Owner":         formatBool(getBool(userMap, "is_owner")),
				"Is Primary Owner": formatBool(getBool(userMap, "is_primary_owner")),
			}
			userList = append(userList, formattedUser)
		}
	}

	return writeOutput(outputJSON, outputCSV, userList, func() {
		fmt.Println("\nList of Users:")
		for _, user := range userList {
			fmt.Printf("\nUser Details:\n")
			for key, value := range user {
				fmt.Printf("  %s: %s\n", key, value)
			}
		}
	})
}

// FindExternalChannels returns channels shared with external organizations or workspaces
func (c *Client) FindExternalChannels(outputJSON, outputCSV string) error {
	cursor := ""
	var results []map[string]string

	for {
		endpoint := "https://slack.com/api/conversations.list?types=public_channel,private_channel,mpim,im&limit=200"
		if cursor != "" {
			endpoint += "&cursor=" + cursor
		}
		result, err := c.makeRequest(endpoint, "POST", "")
		if err != nil {
			return fmt.Errorf("failed to list channels: %v", err)
		}

		channels, _ := result["channels"].([]interface{})
		for _, ch := range channels {
			chMap, ok := ch.(map[string]interface{})
			if !ok {
				continue
			}
			isShared := getBool(chMap, "is_shared")
			isExtShared := getBool(chMap, "is_ext_shared")
			if isShared || isExtShared {
				results = append(results, map[string]string{
					"Channel ID":    getString(chMap, "id"),
					"Name":          getString(chMap, "name"),
					"Is Shared":     formatBool(isShared),
					"Is Ext Shared": formatBool(isExtShared),
					"Member Count":  fmt.Sprintf("%d", getInt(chMap, "num_members")),
				})
			}
		}

		meta, _ := result["response_metadata"].(map[string]interface{})
		next, _ := meta["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}

	return writeOutput(outputJSON, outputCSV, results, func() {
		fmt.Println("\nExternal / Shared Channels:")
		for _, ch := range results {
			fmt.Printf("\nChannel Details:\n")
			for k, v := range ch {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}
	})
}

// ListFiles lists all accessible files
func (c *Client) ListFiles(outputJSON, outputCSV string) error {
	result, err := c.makeRequest("https://slack.com/api/files.list", "POST", "")
	if err != nil {
		return fmt.Errorf("failed to list files: %v", err)
	}

	files, ok := result["files"].([]interface{})
	if !ok {
		return fmt.Errorf("no files found in response")
	}

	var fileList []map[string]string
	for _, file := range files {
		if fileMap, ok := file.(map[string]interface{}); ok {
			formattedFile := map[string]string{
				"ID":       getString(fileMap, "id"),
				"Name":     getString(fileMap, "name"),
				"Title":    getString(fileMap, "title"),
				"URL":      getString(fileMap, "url_private"),
				"Created":  formatTimestamp(getInt64(fileMap, "created")),
				"Filetype": getString(fileMap, "filetype"),
				"Size":     fmt.Sprintf("%d bytes", getInt64(fileMap, "size")),
			}
			fileList = append(fileList, formattedFile)
		}
	}

	return writeOutput(outputJSON, outputCSV, fileList, func() {
		fmt.Println("\nList of Files:")
		for _, file := range fileList {
			fmt.Printf("\nFile Details:\n")
			for key, value := range file {
				fmt.Printf("  %s: %s\n", key, value)
			}
		}
	})
}

// Pillage searches for secrets in the specified channel
func (c *Client) Pillage(channelName string, outputJSON string) error {
	// First get channel ID if not "all"
	var channelsToScan []string
	if channelName != "all" {
		result, err := c.makeRequest("https://slack.com/api/conversations.list", "POST", "")
		if err != nil {
			return fmt.Errorf("failed to list channels: %v", err)
		}

		channels, ok := result["channels"].([]interface{})
		if !ok {
			return fmt.Errorf("no channels found")
		}

		found := false
		for _, ch := range channels {
			if channelMap, ok := ch.(map[string]interface{}); ok {
				if getString(channelMap, "name") == channelName {
					channelsToScan = append(channelsToScan, getString(channelMap, "id"))
					found = true
					break
				}
			}
		}

		if !found {
			return fmt.Errorf("channel '%s' not found", channelName)
		}
	} else {
		// Get all channel IDs
		result, err := c.makeRequest("https://slack.com/api/conversations.list", "POST", "")
		if err != nil {
			return fmt.Errorf("failed to list channels: %v", err)
		}

		channels, ok := result["channels"].([]interface{})
		if !ok {
			return fmt.Errorf("no channels found")
		}

		for _, ch := range channels {
			if channelMap, ok := ch.(map[string]interface{}); ok {
				channelsToScan = append(channelsToScan, getString(channelMap, "id"))
			}
		}
	}

	// TODO: Implement actual secret scanning logic
	fmt.Printf("Scanning %d channels for secrets...\n", len(channelsToScan))
	return nil
}

var webhookRe = regexp.MustCompile(`https://hooks\.slack\.com/\S+`)

// secretPatterns maps pattern names to regexes used during file content scanning
var secretPatterns = map[string]*regexp.Regexp{
	"AWS Access Key":       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"AWS Secret Key":       regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*\S+`),
	"Slack Token":          regexp.MustCompile(`xox[bpao]-[0-9A-Za-z-]+`),
	"Private Key Header":   regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`),
	"Generic Password":     regexp.MustCompile(`(?i)password\s*[:=]\s*\S+`),
	"Generic API Key":      regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*\S+`),
	"GitHub Token":         regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
}

// binaryMimeTypes contains MIME prefixes that indicate non-text content to skip
var binaryMimeTypes = []string{
	"image/", "video/", "audio/", "application/pdf",
	"application/zip", "application/octet-stream",
}

// ScanFileContent downloads accessible text files and scans them for secret patterns
func (c *Client) ScanFileContent(outputJSON, outputCSV string) error {
	result, err := c.makeRequest("https://slack.com/api/files.list", "POST", "")
	if err != nil {
		return fmt.Errorf("failed to list files: %v", err)
	}

	files, _ := result["files"].([]interface{})
	var findings []map[string]string

	for _, f := range files {
		fileMap, ok := f.(map[string]interface{})
		if !ok {
			continue
		}
		mimetype := getString(fileMap, "mimetype")
		for _, prefix := range binaryMimeTypes {
			if strings.HasPrefix(mimetype, prefix) {
				goto nextFile
			}
		}

		{
			url := getString(fileMap, "url_private")
			name := getString(fileMap, "name")
			if url == "" {
				continue
			}

			content, err := c.fetchFileContent(url)
			if err != nil {
				continue
			}

			for patternName, re := range secretPatterns {
				matches := re.FindAllString(content, -1)
				for _, match := range matches {
					findings = append(findings, map[string]string{
						"File Name": name,
						"File URL":  url,
						"Pattern":   patternName,
						"Match":     match,
					})
				}
			}
		}
	nextFile:
	}

	return writeOutput(outputJSON, outputCSV, findings, func() {
		fmt.Println("\nFile Content Scan Findings:")
		for _, f := range findings {
			fmt.Printf("\nFinding:\n")
			for k, v := range f {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}
	})
}

// fetchFileContent downloads a private Slack file and returns its content as a string
func (c *Client) fetchFileContent(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.credentials.Token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// FindHighValueTargets returns workspace admins and owners — accounts with elevated privileges
func (c *Client) FindHighValueTargets(outputJSON, outputCSV string) error {
	var users []interface{}
	cursor := ""

	for {
		endpoint := "https://slack.com/api/users.list?limit=200"
		if cursor != "" {
			endpoint += "&cursor=" + cursor
		}
		result, err := c.makeRequest(endpoint, "POST", "")
		if err != nil {
			return fmt.Errorf("failed to list users: %v", err)
		}
		members, _ := result["members"].([]interface{})
		users = append(users, members...)

		meta, _ := result["response_metadata"].(map[string]interface{})
		next, _ := meta["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}

	var targets []map[string]string
	for _, u := range users {
		userMap, ok := u.(map[string]interface{})
		if !ok {
			continue
		}
		if !getBool(userMap, "is_admin") && !getBool(userMap, "is_owner") && !getBool(userMap, "is_primary_owner") {
			continue
		}
		profile, _ := userMap["profile"].(map[string]interface{})
		targets = append(targets, map[string]string{
			"User ID":          getString(userMap, "id"),
			"Username":         getString(userMap, "name"),
			"Real Name":        getString(userMap, "real_name"),
			"Email":            getString(profile, "email"),
			"Is Admin":         formatBool(getBool(userMap, "is_admin")),
			"Is Owner":         formatBool(getBool(userMap, "is_owner")),
			"Is Primary Owner": formatBool(getBool(userMap, "is_primary_owner")),
		})
	}

	return writeOutput(outputJSON, outputCSV, targets, func() {
		fmt.Println("\nHigh-Value Targets (Admins / Owners):")
		for _, t := range targets {
			fmt.Printf("\nUser:\n")
			for k, v := range t {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}
	})
}

// FindWebhooks scans channel topics and purposes for Slack incoming webhook URLs
func (c *Client) FindWebhooks(outputJSON, outputCSV string) error {
	cursor := ""
	var results []map[string]string

	for {
		endpoint := "https://slack.com/api/conversations.list?types=public_channel,private_channel&limit=200"
		if cursor != "" {
			endpoint += "&cursor=" + cursor
		}
		result, err := c.makeRequest(endpoint, "POST", "")
		if err != nil {
			return fmt.Errorf("failed to list channels: %v", err)
		}

		channels, _ := result["channels"].([]interface{})
		for _, ch := range channels {
			chMap, ok := ch.(map[string]interface{})
			if !ok {
				continue
			}
			channelID := getString(chMap, "id")
			channelName := getString(chMap, "name")

			// Check topic and purpose fields for webhook URLs
			for _, field := range []string{"topic", "purpose"} {
				fieldMap, ok := chMap[field].(map[string]interface{})
				if !ok {
					continue
				}
				value := getString(fieldMap, "value")
				for _, match := range webhookRe.FindAllString(value, -1) {
					results = append(results, map[string]string{
						"Channel ID":   channelID,
						"Channel Name": channelName,
						"Field":        field,
						"Webhook URL":  match,
					})
				}
			}
		}

		meta, _ := result["response_metadata"].(map[string]interface{})
		next, _ := meta["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}

	return writeOutput(outputJSON, outputCSV, results, func() {
		fmt.Println("\nWebhooks Found:")
		for _, wh := range results {
			fmt.Printf("\nWebhook:\n")
			for k, v := range wh {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}
	})
}

// AuditTokenScopes calls auth.test and reports the token identity and OAuth scopes
func (c *Client) AuditTokenScopes(outputJSON, outputCSV string) error {
	result, err := c.makeRequest("https://slack.com/api/auth.test", "POST", "")
	if err != nil {
		return fmt.Errorf("failed to call auth.test: %v", err)
	}

	report := map[string]string{
		"User ID":    getString(result, "user_id"),
		"Username":   getString(result, "user"),
		"Team":       getString(result, "team"),
		"Team ID":    getString(result, "team_id"),
		"Bot ID":     getString(result, "bot_id"),
		"Token Type": getString(result, "token_type"),
		"Scopes":     getString(result, "scopes"),
	}

	return writeOutput(outputJSON, outputCSV, []map[string]string{report}, func() {
		fmt.Println("\nToken Scope Audit:")
		for k, v := range report {
			fmt.Printf("  %s: %s\n", k, v)
		}
	})
}

// ScanPins retrieves pinned items from all accessible channels and returns their content
func (c *Client) ScanPins(outputJSON, outputCSV string) error {
	// Fetch all accessible channels
	result, err := c.makeRequest("https://slack.com/api/conversations.list?types=public_channel,private_channel&limit=200", "POST", "")
	if err != nil {
		return fmt.Errorf("failed to list channels: %v", err)
	}
	channels, _ := result["channels"].([]interface{})

	var pins []map[string]string
	for _, ch := range channels {
		chMap, ok := ch.(map[string]interface{})
		if !ok {
			continue
		}
		channelID := getString(chMap, "id")
		channelName := getString(chMap, "name")

		pr, err := c.makeRequest("https://slack.com/api/pins.list?channel="+channelID, "GET", "")
		if err != nil {
			continue
		}
		items, _ := pr["items"].([]interface{})
		for _, item := range items {
			itemMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			pinType := getString(itemMap, "type")
			content := ""
			switch pinType {
			case "message":
				if msg, ok := itemMap["message"].(map[string]interface{}); ok {
					content = getString(msg, "text")
				}
			case "file":
				if f, ok := itemMap["file"].(map[string]interface{}); ok {
					content = getString(f, "name") + ": " + getString(f, "url_private")
				}
			}
			pins = append(pins, map[string]string{
				"Channel ID":   channelID,
				"Channel Name": channelName,
				"Type":         pinType,
				"Content":      content,
				"Created":      formatTimestamp(getInt64(itemMap, "created")),
			})
		}
	}

	return writeOutput(outputJSON, outputCSV, pins, func() {
		fmt.Println("\nPinned Items:")
		for _, pin := range pins {
			fmt.Printf("\nPin:\n")
			for k, v := range pin {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}
	})
}

// DownloadFiles downloads all accessible files
func (c *Client) DownloadFiles(outputDir string) error {
	if outputDir == "" {
		outputDir = "downloaded_files"
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	result, err := c.makeRequest("https://slack.com/api/files.list", "POST", "")
	if err != nil {
		return fmt.Errorf("failed to list files: %v", err)
	}

	files, ok := result["files"].([]interface{})
	if !ok {
		return fmt.Errorf("no files found in response")
	}

	for _, file := range files {
		if fileMap, ok := file.(map[string]interface{}); ok {
			url := getString(fileMap, "url_private")
			name := getString(fileMap, "name")
			if url != "" && name != "" {
				fmt.Printf("Downloading: %s\n", name)
				// TODO: Implement actual file download logic
			}
		}
	}

	return nil
}

// Helper functions

func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if val, ok := m[key].(float64); ok {
		return int(val)
	}
	return 0
}

func getInt64(m map[string]interface{}, key string) int64 {
	if val, ok := m[key].(float64); ok {
		return int64(val)
	}
	return 0
}

func getBool(m map[string]interface{}, key string) bool {
	if val, ok := m[key].(bool); ok {
		return val
	}
	return false
}

func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func formatTimestamp(ts int64) string {
	return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
}

// writeOutput writes data to JSON and/or CSV files; falls back to printFn when neither is set.
func writeOutput(outputJSON, outputCSV string, data []map[string]string, printFn func()) error {
	wrote := false
	if outputJSON != "" {
		if err := writeJSON(outputJSON, data); err != nil {
			return err
		}
		wrote = true
	}
	if outputCSV != "" {
		if err := writeCSV(outputCSV, data); err != nil {
			return err
		}
		wrote = true
	}
	if !wrote {
		printFn()
	}
	return nil
}

// writeCSV writes a slice of map[string]string records to a CSV file.
// Column order is derived from the first record's keys (sorted for determinism).
func writeCSV(filename string, data []map[string]string) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %v", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if len(data) == 0 {
		return nil
	}

	// Determine column order from the first record
	headers := make([]string, 0, len(data[0]))
	for k := range data[0] {
		headers = append(headers, k)
	}
	sort.Strings(headers)

	if err := w.Write(headers); err != nil {
		return err
	}

	for _, record := range data {
		row := make([]string, len(headers))
		for i, h := range headers {
			row[i] = record[h]
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(filename string, data interface{}) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Marshal data with indentation
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// Write to file
	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %v", err)
	}

	return nil
}
