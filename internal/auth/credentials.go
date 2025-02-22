package auth

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Credentials holds authentication information for Slack
type Credentials struct {
	Token        string
	Cookie       string
	WorkspaceURL string
	ProxyURL     string
}

// NewCredentials creates a new Credentials instance
func NewCredentials(token, cookie, workspaceURL, proxyURL string) (*Credentials, error) {
	if token == "" && cookie == "" {
		return nil, fmt.Errorf("either token or cookie must be provided")
	}
	if cookie != "" && workspaceURL == "" {
		return nil, fmt.Errorf("workspace URL is required when using cookie authentication")
	}

	return &Credentials{
		Token:        token,
		Cookie:       strings.TrimPrefix(cookie, "d="),
		WorkspaceURL: normalizeWorkspaceURL(workspaceURL),
		ProxyURL:     proxyURL,
	}, nil
}

// IsTokenAuth returns true if using token authentication
func (c *Credentials) IsTokenAuth() bool {
	return c.Token != ""
}

// IsCookieAuth returns true if using cookie authentication
func (c *Credentials) IsCookieAuth() bool {
	return c.Cookie != ""
}

// ConfigureHTTPClient configures an http.Client with the credentials
func (c *Credentials) ConfigureHTTPClient() (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	if c.ProxyURL != "" {
		proxyURLParsed, err := url.Parse(c.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy URL: %v", err)
		}
		transport.Proxy = http.ProxyURL(proxyURLParsed)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

// normalizeWorkspaceURL ensures the workspace URL has the correct format
func normalizeWorkspaceURL(workspaceURL string) string {
	if workspaceURL == "" {
		return ""
	}
	if !strings.HasPrefix(workspaceURL, "https://") && !strings.HasPrefix(workspaceURL, "http://") {
		return "https://" + workspaceURL
	}
	return workspaceURL
} 