package slack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fr4nk3nst1ner/slackattack/internal/models"
)

// ListChannels lists all accessible channels
func (c *Client) ListChannels(outputJSON string) error {
	result, err := c.makeRequest("https://slack.com/api/conversations.list?types=public_channel,private_channel", "POST", "")
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

	return nil
}

// ListUsers lists all workspace users
func (c *Client) ListUsers(outputJSON string) error {
	result, err := c.makeRequest("https://slack.com/api/users.list", "POST", "")
	if err != nil {
		return fmt.Errorf("failed to list users: %v", err)
	}

	users, ok := result["members"].([]interface{})
	if !ok {
		return fmt.Errorf("no users found in response")
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

	if outputJSON != "" {
		return writeJSON(outputJSON, userList)
	}

	// Print to stdout
	fmt.Println("\nList of Users:")
	for _, user := range userList {
		fmt.Printf("\nUser Details:\n")
		for key, value := range user {
			fmt.Printf("  %s: %s\n", key, value)
		}
	}

	return nil
}

// ListFiles lists all accessible files
func (c *Client) ListFiles(outputJSON string) error {
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

	if outputJSON != "" {
		return writeJSON(outputJSON, fileList)
	}

	// Print to stdout
	fmt.Println("\nList of Files:")
	for _, file := range fileList {
		fmt.Printf("\nFile Details:\n")
		for key, value := range file {
			fmt.Printf("  %s: %s\n", key, value)
		}
	}

	return nil
}

// Pillage searches for secrets in the specified channel
func (c *Client) Pillage(channelName string, outputJSON string) error {
	// First get channel ID if not "all"
	var channelsToScan []string
	if channelName != "all" {
		result, err := c.makeRequest("https://slack.com/api/conversations.list?types=public_channel,private_channel", "POST", "")
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
		result, err := c.makeRequest("https://slack.com/api/conversations.list?types=public_channel,private_channel", "POST", "")
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
