package slack

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
)

type Client struct {
	httpClient *http.Client
	token      string
	cookie     string
	baseURL    string
	proxy      string
}

func NewClient(creds Credentials, proxy string) *Client {
	client := &http.Client{}
	
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err == nil {
			client.Transport = &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			}
		}
	}

	return &Client{
		httpClient: client,
		token:      creds.Token,
		cookie:     creds.Cookie,
		baseURL:    "https://slack.com/api",
		proxy:      proxy,
	}
}

func (c *Client) makeRequest(method, endpoint string, payload interface{}) (*http.Response, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, endpoint)
	
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	} else if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}

	return c.httpClient.Do(req)
}

// Add more methods for specific API endpoints... 