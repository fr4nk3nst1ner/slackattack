package slack

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fr4nk3nst1ner/slackattack/internal/auth"
)

// newTestClient creates a Client wired to the given test server URL.
func newTestClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	creds, err := auth.NewCredentials("xoxb-test-token", "", "", "")
	if err != nil {
		t.Fatalf("failed to create credentials: %v", err)
	}
	c, err := NewClient(creds)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	c.baseURL = serverURL
	return c
}

func respondJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func makeMember(id, name, email string, isAdmin bool) map[string]interface{} {
	return map[string]interface{}{
		"id":               id,
		"name":             name,
		"real_name":        name,
		"is_admin":         isAdmin,
		"is_owner":         false,
		"is_primary_owner": false,
		"profile": map[string]interface{}{
			"display_name": name,
			"email":        email,
		},
	}
}

func membersResponse(members []map[string]interface{}, nextCursor string) map[string]interface{} {
	list := make([]interface{}, len(members))
	for i, m := range members {
		list[i] = m
	}
	return map[string]interface{}{
		"ok":      true,
		"members": list,
		"response_metadata": map[string]interface{}{
			"next_cursor": nextCursor,
		},
	}
}

// --- TestListUsersSinglePage ---

func TestListUsersSinglePage(t *testing.T) {
	members := []map[string]interface{}{
		makeMember("U1", "alice", "alice@example.com", false),
		makeMember("U2", "bob", "bob@example.com", false),
		makeMember("U3", "carol", "carol@example.com", false),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, membersResponse(members, ""))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "users.json")

	if err := c.ListUsers(outFile); err != nil {
		t.Fatalf("ListUsers returned error: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("could not read output file: %v", err)
	}
	var out []map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(out) != 3 {
		t.Errorf("expected 3 users, got %d", len(out))
	}
}

// --- TestListUsersPagination ---

func TestListUsersPagination(t *testing.T) {
	const cursorPage2 = "cursor_page2"
	var requestCount int32

	page1 := make([]map[string]interface{}, 10)
	for i := range page1 {
		page1[i] = makeMember(fmt.Sprintf("U1%d", i), fmt.Sprintf("user1%d", i), fmt.Sprintf("u1%d@example.com", i), false)
	}
	page2 := make([]map[string]interface{}, 5)
	for i := range page2 {
		page2[i] = makeMember(fmt.Sprintf("U2%d", i), fmt.Sprintf("user2%d", i), fmt.Sprintf("u2%d@example.com", i), false)
	}

	var capturedPage2Query string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&requestCount, 1)
		if n == 1 {
			respondJSON(w, membersResponse(page1, cursorPage2))
		} else {
			capturedPage2Query = r.URL.RawQuery
			respondJSON(w, membersResponse(page2, ""))
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "users.json")

	if err := c.ListUsers(outFile); err != nil {
		t.Fatalf("ListUsers returned error: %v", err)
	}

	if !strings.Contains(capturedPage2Query, "cursor="+cursorPage2) {
		t.Errorf("page 2 request URL %q missing cursor=%s", capturedPage2Query, cursorPage2)
	}

	data, _ := os.ReadFile(outFile)
	var out []map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(out) != 15 {
		t.Errorf("expected 15 users across 2 pages, got %d", len(out))
	}
}

// --- TestListUsersLargeWorkspace ---

func TestListUsersLargeWorkspace(t *testing.T) {
	cursors := []string{"page2", "page3", ""}
	var requestCount int32

	makeMembers := func(n int, prefix string) []map[string]interface{} {
		m := make([]map[string]interface{}, n)
		for i := range m {
			m[i] = makeMember(fmt.Sprintf("%s%d", prefix, i), fmt.Sprintf("%s%d", prefix, i), fmt.Sprintf("%s%d@x.com", prefix, i), false)
		}
		return m
	}

	pages := [][]map[string]interface{}{
		makeMembers(10, "A"),
		makeMembers(10, "B"),
		makeMembers(5, "C"),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := int(atomic.AddInt32(&requestCount, 1)) - 1
		if idx >= len(pages) {
			idx = len(pages) - 1
		}
		respondJSON(w, membersResponse(pages[idx], cursors[idx]))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "users.json")

	if err := c.ListUsers(outFile); err != nil {
		t.Fatalf("ListUsers returned error: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	var out []map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(out) != 25 {
		t.Errorf("expected 25 users across 3 pages, got %d", len(out))
	}
}

// --- TestListUsersAdminFlag ---

func TestListUsersAdminFlag(t *testing.T) {
	members := []map[string]interface{}{
		makeMember("UADMIN", "admin", "admin@example.com", true),
		makeMember("UNORM", "normal", "normal@example.com", false),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, membersResponse(members, ""))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "users.json")

	if err := c.ListUsers(outFile); err != nil {
		t.Fatalf("ListUsers returned error: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	var out []map[string]string
	_ = json.Unmarshal(data, &out)

	for _, u := range out {
		if u["User ID"] == "UADMIN" && u["Is Admin"] != "Yes" {
			t.Errorf("admin user: expected Is Admin=Yes, got %q", u["Is Admin"])
		}
		if u["User ID"] == "UNORM" && u["Is Admin"] != "No" {
			t.Errorf("normal user: expected Is Admin=No, got %q", u["Is Admin"])
		}
	}
}

// --- TestListUsersAPIError ---

func TestListUsersAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, map[string]interface{}{
			"ok":    false,
			"error": "not_authed",
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	if err := c.ListUsers(""); err == nil {
		t.Fatal("expected error for not_authed response, got nil")
	}
}

// --- TestListUsersJSONOutput ---

func TestListUsersJSONOutput(t *testing.T) {
	members := []map[string]interface{}{
		makeMember("U999", "testuser", "test@example.com", false),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, membersResponse(members, ""))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "users.json")

	if err := c.ListUsers(outFile); err != nil {
		t.Fatalf("ListUsers error: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output file missing: %v", err)
	}
	var out []map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected at least one user in output")
	}

	user := out[0]
	for _, k := range []string{"User ID", "Username", "Email", "Real Name", "Display Name", "Is Admin", "Is Owner", "Is Primary Owner"} {
		if _, ok := user[k]; !ok {
			t.Errorf("output missing required key %q", k)
		}
	}
	if user["User ID"] != "U999" {
		t.Errorf("expected User ID U999, got %q", user["User ID"])
	}
	if user["Email"] != "test@example.com" {
		t.Errorf("expected email test@example.com, got %q", user["Email"])
	}
}

// --- TestRateLimitWithRetryAfter ---

func TestRateLimitWithRetryAfter(t *testing.T) {
	var requestCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&requestCount, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			respondJSON(w, map[string]interface{}{"ok": false, "error": "ratelimited"})
			return
		}
		respondJSON(w, membersResponse([]map[string]interface{}{
			makeMember("U1", "alice", "alice@example.com", false),
		}, ""))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "users.json")
	if err := c.ListUsers(outFile); err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if atomic.LoadInt32(&requestCount) < 2 {
		t.Error("expected at least 2 requests (rate limited + retry)")
	}
}

func TestRateLimitFallbackBackoff(t *testing.T) {
	var requestCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&requestCount, 1)
		if n == 1 {
			// Rate limited with no Retry-After header
			respondJSON(w, map[string]interface{}{"ok": false, "error": "ratelimited"})
			return
		}
		respondJSON(w, membersResponse([]map[string]interface{}{
			makeMember("U1", "alice", "alice@example.com", false),
		}, ""))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "users.json")
	if err := c.ListUsers(outFile); err != nil {
		t.Fatalf("expected success after backoff retry, got: %v", err)
	}
	if atomic.LoadInt32(&requestCount) < 2 {
		t.Error("expected at least 2 requests")
	}
}

// --- D2: FindExternalChannels ---

func makeChannel(id, name string, isShared, isExtShared bool) map[string]interface{} {
	return map[string]interface{}{
		"id":            id,
		"name":          name,
		"is_shared":     isShared,
		"is_ext_shared": isExtShared,
		"num_members":   float64(5),
	}
}

func channelsResponse(channels []map[string]interface{}, nextCursor string) map[string]interface{} {
	list := make([]interface{}, len(channels))
	for i, c := range channels {
		list[i] = c
	}
	return map[string]interface{}{
		"ok":       true,
		"channels": list,
		"response_metadata": map[string]interface{}{
			"next_cursor": nextCursor,
		},
	}
}

func TestFindExternalChannelsNone(t *testing.T) {
	channels := []map[string]interface{}{
		makeChannel("C1", "general", false, false),
		makeChannel("C2", "random", false, false),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, channelsResponse(channels, ""))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "external.json")
	if err := c.FindExternalChannels(outFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	var out []map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 external channels, got %d", len(out))
	}
}

func TestFindExternalChannelsSome(t *testing.T) {
	channels := []map[string]interface{}{
		makeChannel("C1", "internal", false, false),
		makeChannel("C2", "shared-ext", true, true),
		makeChannel("C3", "org-shared", true, false),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, channelsResponse(channels, ""))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "external.json")
	if err := c.FindExternalChannels(outFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	var out []map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("expected 2 external channels, got %d", len(out))
	}
	for _, ch := range out {
		if ch["Channel ID"] == "C1" {
			t.Error("internal channel should not be in results")
		}
	}
}

func TestFindExternalChannelsExtSharedOnly(t *testing.T) {
	channels := []map[string]interface{}{
		makeChannel("C1", "ext-only", false, true),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, channelsResponse(channels, ""))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "external.json")
	if err := c.FindExternalChannels(outFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	var out []map[string]string
	_ = json.Unmarshal(data, &out)
	if len(out) != 1 {
		t.Errorf("expected 1 channel with is_ext_shared=true, got %d", len(out))
	}
	if out[0]["Is Ext Shared"] != "Yes" {
		t.Errorf("expected Is Ext Shared=Yes, got %q", out[0]["Is Ext Shared"])
	}
}

func TestFindExternalChannelsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, map[string]interface{}{"ok": false, "error": "not_authed"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	if err := c.FindExternalChannels(""); err == nil {
		t.Fatal("expected error for not_authed, got nil")
	}
}

// --- D3: ScanPins ---

func TestScanPinsNoChannels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "conversations.list") {
			respondJSON(w, channelsResponse(nil, ""))
		} else {
			respondJSON(w, map[string]interface{}{"ok": true, "items": []interface{}{}})
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "pins.json")
	if err := c.ScanPins(outFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	var out []map[string]string
	_ = json.Unmarshal(data, &out)
	if len(out) != 0 {
		t.Errorf("expected 0 pins, got %d", len(out))
	}
}

func TestScanPinsWithMessage(t *testing.T) {
	channel := makeChannel("C1", "general", false, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "conversations.list") {
			respondJSON(w, channelsResponse([]map[string]interface{}{channel}, ""))
			return
		}
		// pins.list
		respondJSON(w, map[string]interface{}{
			"ok": true,
			"items": []interface{}{
				map[string]interface{}{
					"type":    "message",
					"created": float64(1700000000),
					"message": map[string]interface{}{
						"text": "super secret: password123",
					},
				},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "pins.json")
	if err := c.ScanPins(outFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	var out []map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 pin, got %d", len(out))
	}
	if out[0]["Type"] != "message" {
		t.Errorf("expected type=message, got %q", out[0]["Type"])
	}
	if !strings.Contains(out[0]["Content"], "password123") {
		t.Errorf("expected pin content to contain password123, got %q", out[0]["Content"])
	}
}

func TestScanPinsWithFile(t *testing.T) {
	channel := makeChannel("C2", "secrets", false, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "conversations.list") {
			respondJSON(w, channelsResponse([]map[string]interface{}{channel}, ""))
			return
		}
		respondJSON(w, map[string]interface{}{
			"ok": true,
			"items": []interface{}{
				map[string]interface{}{
					"type":    "file",
					"created": float64(1700000001),
					"file": map[string]interface{}{
						"name":        "creds.txt",
						"url_private": "https://files.slack.com/creds.txt",
					},
				},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "pins.json")
	if err := c.ScanPins(outFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	var out []map[string]string
	_ = json.Unmarshal(data, &out)
	if len(out) != 1 {
		t.Fatalf("expected 1 pin, got %d", len(out))
	}
	if out[0]["Type"] != "file" {
		t.Errorf("expected type=file, got %q", out[0]["Type"])
	}
	if !strings.Contains(out[0]["Content"], "creds.txt") {
		t.Errorf("expected content to contain filename, got %q", out[0]["Content"])
	}
}

func TestScanPinsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, map[string]interface{}{"ok": false, "error": "not_authed"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	if err := c.ScanPins(""); err == nil {
		t.Fatal("expected error for not_authed, got nil")
	}
}

// --- D4: AuditTokenScopes ---

func TestAuditTokenScopesSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, map[string]interface{}{
			"ok":         true,
			"user_id":    "U123",
			"user":       "testbot",
			"team":       "My Team",
			"team_id":    "T456",
			"bot_id":     "B789",
			"token_type": "bot",
			"scopes":     "channels:read,users:read,files:read",
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "audit.json")
	if err := c.AuditTokenScopes(outFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	var out map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if out["User ID"] != "U123" {
		t.Errorf("expected User ID=U123, got %q", out["User ID"])
	}
	if out["Token Type"] != "bot" {
		t.Errorf("expected Token Type=bot, got %q", out["Token Type"])
	}
	if out["Scopes"] != "channels:read,users:read,files:read" {
		t.Errorf("unexpected scopes: %q", out["Scopes"])
	}
}

func TestAuditTokenScopesRequiredFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, map[string]interface{}{
			"ok":      true,
			"user_id": "UABC",
			"user":    "alice",
			"team":    "ACME",
			"team_id": "TACME",
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "audit.json")
	if err := c.AuditTokenScopes(outFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	var out map[string]string
	_ = json.Unmarshal(data, &out)

	for _, k := range []string{"User ID", "Username", "Team", "Team ID", "Bot ID", "Token Type", "Scopes"} {
		if _, ok := out[k]; !ok {
			t.Errorf("output missing required key %q", k)
		}
	}
}

func TestAuditTokenScopesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, map[string]interface{}{"ok": false, "error": "invalid_auth"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	if err := c.AuditTokenScopes(""); err == nil {
		t.Fatal("expected error for invalid_auth, got nil")
	}
}

// --- D5: FindWebhooks ---

func makeChannelWithMeta(id, name, topic, purpose string) map[string]interface{} {
	return map[string]interface{}{
		"id":   id,
		"name": name,
		"topic": map[string]interface{}{
			"value": topic,
		},
		"purpose": map[string]interface{}{
			"value": purpose,
		},
	}
}

func TestFindWebhooksNone(t *testing.T) {
	channels := []map[string]interface{}{
		makeChannelWithMeta("C1", "general", "No hooks here", "Just a channel"),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, channelsResponse(channels, ""))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "webhooks.json")
	if err := c.FindWebhooks(outFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	var out []map[string]string
	_ = json.Unmarshal(data, &out)
	if len(out) != 0 {
		t.Errorf("expected 0 webhooks, got %d", len(out))
	}
}

func TestFindWebhooksInTopic(t *testing.T) {
	hook := "https://hooks.slack.com/services/T00/B00/abc123"
	channels := []map[string]interface{}{
		makeChannelWithMeta("C1", "alerts", "Webhook: "+hook, ""),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, channelsResponse(channels, ""))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "webhooks.json")
	if err := c.FindWebhooks(outFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	var out []map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 webhook, got %d", len(out))
	}
	if out[0]["Webhook URL"] != hook {
		t.Errorf("expected webhook URL %q, got %q", hook, out[0]["Webhook URL"])
	}
	if out[0]["Field"] != "topic" {
		t.Errorf("expected field=topic, got %q", out[0]["Field"])
	}
}

func TestFindWebhooksInPurpose(t *testing.T) {
	hook := "https://hooks.slack.com/services/T00/B00/xyz789"
	channels := []map[string]interface{}{
		makeChannelWithMeta("C2", "deploys", "", "Post here: "+hook),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, channelsResponse(channels, ""))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "webhooks.json")
	if err := c.FindWebhooks(outFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	var out []map[string]string
	_ = json.Unmarshal(data, &out)
	if len(out) != 1 {
		t.Fatalf("expected 1 webhook, got %d", len(out))
	}
	if out[0]["Field"] != "purpose" {
		t.Errorf("expected field=purpose, got %q", out[0]["Field"])
	}
}

func TestFindWebhooksAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, map[string]interface{}{"ok": false, "error": "not_authed"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	if err := c.FindWebhooks(""); err == nil {
		t.Fatal("expected error for not_authed, got nil")
	}
}
