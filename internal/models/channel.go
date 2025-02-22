package models

// Channel represents a Slack channel
type Channel struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	MemberCount int      `json:"member_count"`
	Members     []string `json:"members,omitempty"`
	Topic       Topic    `json:"topic"`
	Created     int64    `json:"created"`
	Creator     string   `json:"creator"`
	IsMember    bool     `json:"is_member"`
}

// Topic represents a channel's topic
type Topic struct {
	Value   string `json:"value"`
	Creator string `json:"creator"`
	LastSet int64  `json:"last_set"`
}

// DirectMessage represents a Slack DM channel
type DirectMessage struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// MembershipInfo contains information about channel membership
type MembershipInfo struct {
	Channels       []Channel       `json:"channels"`
	DirectMessages []DirectMessage `json:"direct_messages"`
} 