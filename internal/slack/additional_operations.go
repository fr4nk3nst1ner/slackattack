package slack

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TestCredentials tests if the provided credentials are valid
func (c *Client) TestCredentials() error {
	_, err := c.makeRequest("https://slack.com/api/auth.test", "POST", "")
	return err
}

// CheckPermissions checks what permissions the token/cookie has
func (c *Client) CheckPermissions() error {
	endpoints := []struct {
		name string
		url  string
	}{
		{"files.list", "https://slack.com/api/files.list"},
		{"users.list", "https://slack.com/api/users.list"},
		{"conversations.list", "https://slack.com/api/conversations.list"},
	}

	fmt.Println("Checking permissions...")
	for _, endpoint := range endpoints {
		result, err := c.makeRequest(endpoint.url, "POST", "")
		if err != nil {
			fmt.Printf("%s: false (Error: %v)\n", endpoint.name, err)
			continue
		}

		ok, _ := result["ok"].(bool)
		fmt.Printf("%s: %v\n", endpoint.name, ok)
	}

	return nil
}

// DumpChannelMessages dumps all messages from a specific channel
func (c *Client) DumpChannelMessages(channelName string, outputJSON string) error {
	// First get channel ID
	result, err := c.makeRequest("https://slack.com/api/conversations.list?types=public_channel,private_channel", "POST", "")
	if err != nil {
		return fmt.Errorf("failed to list channels: %v", err)
	}

	channels, ok := result["channels"].([]interface{})
	if !ok {
		return fmt.Errorf("no channels found")
	}

	var channelID string
	for _, ch := range channels {
		if channelMap, ok := ch.(map[string]interface{}); ok {
			if getString(channelMap, "name") == channelName {
				channelID = getString(channelMap, "id")
				break
			}
		}
	}

	if channelID == "" {
		return fmt.Errorf("channel '%s' not found", channelName)
	}

	// Get channel history
	var allMessages []map[string]interface{}
	cursor := ""
	for {
		historyURL := fmt.Sprintf("https://slack.com/api/conversations.history?channel=%s&limit=1000", channelID)
		if cursor != "" {
			historyURL += "&cursor=" + cursor
		}

		result, err := c.makeRequest(historyURL, "POST", "")
		if err != nil {
			return fmt.Errorf("failed to get messages: %v", err)
		}

		messages, ok := result["messages"].([]interface{})
		if !ok {
			break
		}

		for _, msg := range messages {
			if msgMap, ok := msg.(map[string]interface{}); ok {
				// Convert timestamp
				if ts, ok := msgMap["ts"].(string); ok {
					if tsFloat, err := strconv.ParseFloat(ts, 64); err == nil {
						msgMap["timestamp"] = time.Unix(int64(tsFloat), 0).Format("2006-01-02 15:04:05")
					}
				}
				allMessages = append(allMessages, msgMap)
			}
		}

		// Handle pagination
		hasMore, _ := result["has_more"].(bool)
		if !hasMore {
			break
		}

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

	if outputJSON != "" {
		return writeJSON(outputJSON, allMessages)
	}

	// Print to stdout
	fmt.Printf("\nMessages from #%s:\n", channelName)
	for _, msg := range allMessages {
		fmt.Printf("\n[%s] ", msg["timestamp"])
		if user, ok := msg["user"].(string); ok {
			fmt.Printf("<%s> ", user)
		}
		if text, ok := msg["text"].(string); ok {
			fmt.Println(text)
		}
	}

	return nil
}

// ListDMChannels lists all DM channels
func (c *Client) ListDMChannels(outputJSON string) error {
	result, err := c.makeRequest("https://slack.com/api/conversations.list?types=im", "GET", "")
	if err != nil {
		return fmt.Errorf("failed to list DM channels: %v", err)
	}

	channels, ok := result["channels"].([]interface{})
	if !ok {
		return fmt.Errorf("no DM channels found")
	}

	var dmList []map[string]string
	for _, ch := range channels {
		if channelMap, ok := ch.(map[string]interface{}); ok {
			dm := map[string]string{
				"ID":      getString(channelMap, "id"),
				"User ID": getString(channelMap, "user"),
				"Created": formatTimestamp(getInt64(channelMap, "created")),
			}
			dmList = append(dmList, dm)
		}
	}

	if outputJSON != "" {
		return writeJSON(outputJSON, dmList)
	}

	// Print to stdout
	fmt.Println("\nDM Channels:")
	for _, dm := range dmList {
		fmt.Printf("\nDM Channel Details:\n")
		for key, value := range dm {
			fmt.Printf("  %s: %s\n", key, value)
		}
	}

	return nil
}

// DumpDMMessages dumps all messages from a specific DM channel
func (c *Client) DumpDMMessages(channelID string, outputJSON string) error {
	var allMessages []map[string]interface{}
	cursor := ""
	for {
		historyURL := fmt.Sprintf("https://slack.com/api/conversations.history?channel=%s&limit=1000", channelID)
		if cursor != "" {
			historyURL += "&cursor=" + cursor
		}

		result, err := c.makeRequest(historyURL, "POST", "")
		if err != nil {
			return fmt.Errorf("failed to get messages: %v", err)
		}

		messages, ok := result["messages"].([]interface{})
		if !ok {
			break
		}

		for _, msg := range messages {
			if msgMap, ok := msg.(map[string]interface{}); ok {
				// Convert timestamp
				if ts, ok := msgMap["ts"].(string); ok {
					if tsFloat, err := strconv.ParseFloat(ts, 64); err == nil {
						msgMap["timestamp"] = time.Unix(int64(tsFloat), 0).Format("2006-01-02 15:04:05")
					}
				}
				allMessages = append(allMessages, msgMap)
			}
		}

		// Handle pagination
		hasMore, _ := result["has_more"].(bool)
		if !hasMore {
			break
		}

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

	if outputJSON != "" {
		return writeJSON(outputJSON, allMessages)
	}

	// Print to stdout
	fmt.Printf("\nMessages from DM Channel %s:\n", channelID)
	for _, msg := range allMessages {
		fmt.Printf("\n[%s] ", msg["timestamp"])
		if user, ok := msg["user"].(string); ok {
			fmt.Printf("<%s> ", user)
		}
		if text, ok := msg["text"].(string); ok {
			fmt.Println(text)
		}
	}

	return nil
}

// ListChannelMembership lists channel membership information
func (c *Client) ListChannelMembership(outputJSON string) error {
	result, err := c.makeRequest("https://slack.com/api/conversations.list?types=public_channel,private_channel", "POST", "")
	if err != nil {
		return fmt.Errorf("failed to list channels: %v", err)
	}

	channels, ok := result["channels"].([]interface{})
	if !ok {
		return fmt.Errorf("no channels found")
	}

	var membershipInfo struct {
		Channels []struct {
			ID          string   `json:"id"`
			Name        string   `json:"name"`
			MemberCount int      `json:"member_count"`
			Members     []string `json:"members,omitempty"`
		} `json:"channels"`
	}

	for _, ch := range channels {
		if channelMap, ok := ch.(map[string]interface{}); ok {
			channelID := getString(channelMap, "id")

			// Get channel members
			membersResult, err := c.makeRequest(
				fmt.Sprintf("https://slack.com/api/conversations.members?channel=%s", channelID),
				"GET",
				"",
			)

			var members []string
			if err == nil {
				if membersList, ok := membersResult["members"].([]interface{}); ok {
					for _, member := range membersList {
						if memberID, ok := member.(string); ok {
							members = append(members, memberID)
						}
					}
				}
			}

			membershipInfo.Channels = append(membershipInfo.Channels, struct {
				ID          string   `json:"id"`
				Name        string   `json:"name"`
				MemberCount int      `json:"member_count"`
				Members     []string `json:"members,omitempty"`
			}{
				ID:          channelID,
				Name:        getString(channelMap, "name"),
				MemberCount: getInt(channelMap, "num_members"),
				Members:     members,
			})
		}
	}

	if outputJSON != "" {
		return writeJSON(outputJSON, membershipInfo)
	}

	// Print to stdout
	fmt.Println("\nChannel Membership:")
	for _, channel := range membershipInfo.Channels {
		fmt.Printf("\nChannel: #%s (%s)\n", channel.Name, channel.ID)
		fmt.Printf("Member Count: %d\n", channel.MemberCount)
		if len(channel.Members) > 0 {
			fmt.Printf("Members: %v\n", channel.Members)
		}
		fmt.Println(strings.Repeat("-", 40))
	}

	return nil
}

// DumpTeamAccessLogs dumps team access logs
func (c *Client) DumpTeamAccessLogs(outputJSON string) error {
	result, err := c.makeRequest("https://slack.com/api/team.accessLogs", "POST", "")
	if err != nil {
		return fmt.Errorf("failed to get access logs: %v", err)
	}

	logs, ok := result["logs"].([]interface{})
	if !ok {
		return fmt.Errorf("no access logs found")
	}

	if outputJSON != "" {
		return writeJSON(outputJSON, logs)
	}

	// Print to stdout
	fmt.Println("\nTeam Access Logs:")
	for _, log := range logs {
		if logMap, ok := log.(map[string]interface{}); ok {
			fmt.Printf("\nAccess Log Entry:\n")
			fmt.Printf("  User ID: %s\n", getString(logMap, "user_id"))
			fmt.Printf("  Username: %s\n", getString(logMap, "username"))
			fmt.Printf("  Date: %s\n", formatTimestamp(getInt64(logMap, "date_first")))
			fmt.Printf("  IP: %s\n", getString(logMap, "ip"))
			fmt.Printf("  User Agent: %s\n", getString(logMap, "user_agent"))
			fmt.Printf("  Count: %d\n", getInt(logMap, "count"))
		}
	}

	return nil
}
