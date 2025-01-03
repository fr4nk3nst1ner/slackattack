package slack

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
//	"net"
	"net/url"
	//"os"
	"strings"
	"time"
	"path"

	"slackattack/utils"
	"os"
)

type Credentials struct {
	Token        string
	Cookie       string
	WorkspaceURL string
}

type Client struct {
	httpClient *http.Client
	creds      Credentials
	baseURL    string
	verbose    bool
}

type SlackResponse struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func NewClient(creds Credentials, proxyURL string, verbose bool) *Client {
	// Create transport with longer timeouts
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
		// Add explicit proxy configuration
		Proxy: func(_ *http.Request) (*url.URL, error) {
			if proxyURL != "" {
				return url.Parse(proxyURL)
			}
			return nil, nil
		},
		// Increase timeouts
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: 60 * time.Second,
		TLSHandshakeTimeout:   60 * time.Second,
		IdleConnTimeout:       60 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		// Increase overall timeout
		Timeout:   time.Second * 60,
	}

	c := &Client{
		httpClient: client,
		creds:      creds,
		baseURL:    "https://slack.com/api",
		verbose:    verbose,
	}

	if verbose {
		fmt.Printf("Initialized client with proxy: %s\n", proxyURL)
	}

	return c
}

func (c *Client) makeRequest(method, endpoint string, payload interface{}) (*http.Response, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, endpoint)
	
	if c.verbose {
		fmt.Printf("\nAttempting %s request to %s\n", method, url)
	}

	var body io.Reader
	if payload != nil {
		jsonData, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("error marshaling payload: %v", err)
		}
		body = bytes.NewBuffer(jsonData)
		if c.verbose {
			fmt.Printf("Request payload: %s\n", string(jsonData))
		}
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	// Add standard headers
	req.Header.Set("User-Agent", "slackattack/1.0")
	req.Header.Set("Accept", "application/json")
	
	if c.creds.Token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.creds.Token))
		if c.verbose {
			fmt.Printf("Using token authentication: %s\n", c.creds.Token)
		}
	} else if c.creds.Cookie != "" {
		req.Header.Set("Cookie", c.creds.Cookie)
		if c.verbose {
			fmt.Printf("Using cookie authentication: %s\n", c.creds.Cookie)
		}
	}

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.verbose {
		fmt.Printf("\nFull request details:\n")
		fmt.Printf("URL: %s\n", req.URL.String())
		fmt.Printf("Method: %s\n", req.Method)
		fmt.Printf("Headers: %v\n", req.Header)
		fmt.Printf("Using proxy: %v\n", c.httpClient.Transport.(*http.Transport).Proxy != nil)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if c.verbose {
			fmt.Printf("Request failed with error: %v\n", err)
			if strings.Contains(err.Error(), "context deadline exceeded") {
				fmt.Println("Timeout error - consider checking proxy configuration or increasing timeout")
			}
		}
		return nil, fmt.Errorf("request failed: %v", err)
	}

	if c.verbose {
		fmt.Printf("Response status code: %d\n", resp.StatusCode)
	}

	return resp, nil
}

func (c *Client) TestCredentials() error {
	resp, err := c.makeRequest("POST", "auth.test", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result SlackResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if !result.Ok {
		return fmt.Errorf("authentication failed: %s", result.Error)
	}

	fmt.Println("Authentication successful!")
	return nil
}

// ListUsers retrieves and displays the list of users
func (c *Client) ListUsers(outputJSON string) error {
	resp, err := c.makeRequest("GET", "users.list", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		SlackResponse
		Members []map[string]interface{} `json:"members"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	// Use utils.SaveJSONOutput to save or display the results
	return utils.SaveJSONOutput(result.Members, outputJSON)
}

// ListChannels retrieves and displays the list of channels
func (c *Client) ListChannels(outputJSON string) error {
	resp, err := c.makeRequest("GET", "conversations.list", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		SlackResponse
		Channels []map[string]interface{} `json:"channels"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	return utils.SaveJSONOutput(result.Channels, outputJSON)
}

// CheckPermissions checks the permissions of the current token/cookie
func (c *Client) CheckPermissions(outputJSON string) error {
	fmt.Println("Making auth test request...")
	
	resp, err := c.makeRequest("GET", "auth.test", nil)
	if err != nil {
		return fmt.Errorf("auth test failed: %v", err)
	}
	
	fmt.Printf("Auth test response received: %+v\n", resp)
	
	// Test various endpoints and collect permissions
	perms := map[string]bool{
		"auth.test":          true,
		"users.list":         true,
		"conversations.list": true,
		"files.list":        true,
	}

	results := make(map[string]interface{})
	for endpoint := range perms {
		if c.verbose {
			fmt.Printf("Testing endpoint: %s\n", endpoint)
		}
		
		resp, err := c.makeRequest("GET", endpoint, nil)
		if err != nil {
			results[endpoint] = false
			if c.verbose {
				fmt.Printf("Error testing %s: %v\n", endpoint, err)
			}
			continue
		}

		var result SlackResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				results[endpoint] = false
				resp.Body.Close()
				if c.verbose {
					fmt.Printf("Error decoding response from %s: %v\n", endpoint, err)
				}
				continue
		}
		resp.Body.Close()
		results[endpoint] = result.Ok
		
		if c.verbose {
			fmt.Printf("Endpoint %s permission: %v\n", endpoint, result.Ok)
		}
	}

	// Print results to console if no output file specified
	if outputJSON == "" {
		fmt.Println("\nPermissions:")
		for endpoint, ok := range results {
			fmt.Printf("%s: %v\n", endpoint, ok)
		}
		return nil
	}

	return utils.SaveJSONOutput(results, outputJSON)
}

// ListFiles retrieves and displays the list of files
func (c *Client) ListFiles(outputJSON string) error {
	resp, err := c.makeRequest("GET", "files.list", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		SlackResponse
		Files []map[string]interface{} `json:"files"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	return utils.SaveJSONOutput(result.Files, outputJSON)
}

// DownloadFiles downloads files from Slack
func (c *Client) DownloadFiles(outputDir string) error {
	// First get the list of files
	resp, err := c.makeRequest("GET", "files.list", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		SlackResponse
		Files []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			URLPrivate string `json:"url_private"`
			MimeType   string `json:"mimetype"`
		} `json:"files"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	// Create output directory if it doesn't exist
	if outputDir == "" {
		outputDir = "downloaded_files"
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Download each file
	for _, file := range result.Files {
		if c.verbose {
			fmt.Printf("Downloading %s...\n", file.URLPrivate)
		}

		// Create request for the file
		req, err := http.NewRequest("GET", file.URLPrivate, nil)
		if err != nil {
			fmt.Printf("Error creating request for %s: %v\n", file.Name, err)
			continue
		}

		// Add authentication
		if c.creds.Token != "" {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.creds.Token))
		} else if c.creds.Cookie != "" {
			req.Header.Set("Cookie", c.creds.Cookie)
		}

		// Make the request
		resp, err := c.httpClient.Do(req)
		if err != nil {
			fmt.Printf("Error downloading %s: %v\n", file.Name, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			fmt.Printf("Error downloading %s: status code %d\n", file.Name, resp.StatusCode)
			continue
		}

		// Generate safe filename
		filename := utils.GenerateUniqueFilename(file.URLPrivate)
		filepath := path.Join(outputDir, filename)

		// Create the file
		out, err := os.Create(filepath)
		if err != nil {
			resp.Body.Close()
			fmt.Printf("Error creating file %s: %v\n", filepath, err)
			continue
		}

		// Copy the response body to the file
		_, err = io.Copy(out, resp.Body)
		resp.Body.Close()
		out.Close()

		if err != nil {
			fmt.Printf("Error saving file %s: %v\n", filepath, err)
			continue
		}

		fmt.Printf("Successfully downloaded: %s\n", filepath)
	}

	return nil
}

// DumpLogs retrieves and displays access logs
func (c *Client) DumpLogs(outputJSON string) error {
	fmt.Println("Fetching team access logs...")
	
	// Slack's team.accessLogs endpoint
	resp, err := c.makeRequest("GET", "team.accessLogs", nil)
	if err != nil {
		return fmt.Errorf("failed to fetch access logs: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		SlackResponse
		Logs []struct {
			UserID    string    `json:"user_id"`
			Username  string    `json:"username"`
			DateFirst int64     `json:"date_first"`
			DateLast  int64     `json:"date_last"`
			Count     int       `json:"count"`
			IP        string    `json:"ip"`
			UserAgent string    `json:"user_agent"`
		} `json:"logins"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	if !result.Ok {
		return fmt.Errorf("failed to get logs: %s", result.Error)
	}

	// If no output file specified, print to console
	if outputJSON == "" {
		fmt.Println("\nTeam Access Logs:")
		for _, log := range result.Logs {
			firstAccess := time.Unix(log.DateFirst, 0)
			lastAccess := time.Unix(log.DateLast, 0)
			
			fmt.Printf("\nUser: %s\n", log.Username)
			fmt.Printf("First access: %s\n", firstAccess.Format(time.RFC3339))
			fmt.Printf("Last access: %s\n", lastAccess.Format(time.RFC3339))
			fmt.Printf("Access count: %d\n", log.Count)
			fmt.Printf("IP: %s\n", log.IP)
			fmt.Printf("User Agent: %s\n", log.UserAgent)
			fmt.Println("----------------------------------------")
		}
		return nil
	}

	// Save to JSON file if outputJSON is specified
	return utils.SaveJSONOutput(result.Logs, outputJSON)
}

// PillageConversations searches conversations for secrets
func (c *Client) PillageConversations(outputJSON string) error {
	// Implementation coming soon
	return nil
} 