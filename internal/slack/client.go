package slack

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"regexp"

	"github.com/fr4nk3nst1ner/slackattack/internal/auth"
)

// Client represents a Slack API client
type Client struct {
	credentials *auth.Credentials
	httpClient  *http.Client
}

// NewClient creates a new Slack client
func NewClient(credentials *auth.Credentials) (*Client, error) {
	httpClient, err := credentials.ConfigureHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to configure HTTP client: %v", err)
	}

	return &Client{
		credentials: credentials,
		httpClient:  httpClient,
	}, nil
}

// makeRequest makes a request to the Slack API
func (c *Client) makeRequest(endpoint, method string, payload string) (map[string]interface{}, error) {
	maxRetries := 3
	retryDelay := time.Second * 2

	var resp *http.Response
	var data map[string]interface{}
	var err error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(retryDelay)
			retryDelay *= 2 // Exponential backoff
		}

		req, err := c.createRequest(endpoint, method, payload)
		if err != nil {
			return nil, err
		}

		resp, err = c.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			continue
		}

		// Check for rate limiting
		if errMsg, ok := data["error"].(string); ok && errMsg == "ratelimited" {
			if attempt < maxRetries-1 {
				continue
			}
			return nil, fmt.Errorf("rate limited")
		}

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

// createRequest creates an HTTP request with appropriate headers
func (c *Client) createRequest(endpoint, method, payload string) (*http.Request, error) {
	req, err := http.NewRequest(method, endpoint, strings.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	if c.credentials.IsTokenAuth() {
		req.Header.Set("Authorization", "Bearer "+c.credentials.Token)
	} else if c.credentials.IsCookieAuth() {
		userSessionToken, err := c.getUserSessionToken()
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+userSessionToken)
		req.Header.Set("Cookie", "d="+c.credentials.Cookie)
	}

	return req, nil
}

// getUserSessionToken gets a user session token using cookie authentication
func (c *Client) getUserSessionToken() (string, error) {
	req, err := http.NewRequest("GET", c.credentials.WorkspaceURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.AddCookie(&http.Cookie{
		Name:  "d",
		Value: c.credentials.Cookie,
	})

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// Extract token using regex
	tokenRegex := regexp.MustCompile(`(xox[a-zA-Z]-[a-zA-Z0-9-]+)`)
	matches := tokenRegex.FindStringSubmatch(string(body))
	if len(matches) > 0 {
		return matches[0], nil
	}

	return "", fmt.Errorf("user session token not found in response")
} 