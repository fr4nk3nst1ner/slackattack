package slackattack

import (
	"fmt"
	"log"
	"os"
	"encoding/json"
	"time"
	"strconv"
	"strings"

	"github.com/fr4nk3nst1ner/slackattack/internal/scanner"
)

// Finding represents a secret found in a message
type Finding struct {
	RuleTriggered    string `json:"rule_triggered"`
	ChannelName      string `json:"channel_name"`
	ChannelID        string `json:"channel_id"`
	Timestamp        string `json:"timestamp"`
	SenderInfo       string `json:"sender_info"`
	MatchedWord      string `json:"matched_word"`
	MessageContents  string `json:"message_contents"`
	Description      string `json:"description"`
	Severity        string `json:"severity"`
	Detector        string `json:"detector"`
	Verified        bool   `json:"verified"`
}

// Execute runs the main slackattack functionality
func Execute() error {
	// Your main execution logic here
	return nil
}

// PillageWorkspace scans workspace channels for secrets
func PillageWorkspace(credentials map[string]string, proxyURL string, targetChannel string, outputJSON string) error {
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
		channelName := channel["name"].(string)
		channelID := channel["id"].(string)
		
		// Get channel history
		result, err := makeSlackRequest(
			fmt.Sprintf("https://slack.com/api/conversations.history?channel=%s", channelID),
			credentials,
			"POST",
			"",
			proxyURL,
			false,
		)
		if err != nil {
			log.Printf("Error getting history for channel %s: %v", channelName, err)
			continue
		}

		messages, ok := result["messages"].([]interface{})
		if !ok {
			continue
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

			// Use enhanced scanner
			secrets := scanner.ScanForSecrets(text)
			for _, secret := range secrets {
				finding := Finding{
					RuleTriggered:   secret.Type,
					ChannelName:     channelName,
					ChannelID:       channelID,
					Timestamp:       getTimestamp(msgMap),
					SenderInfo:      getSenderInfo(msgMap, credentials, proxyURL),
					MatchedWord:     secret.Secret,
					MessageContents: text,
					Description:     secret.Description,
					Severity:        secret.Severity,
					Detector:        secret.Detector,
					Verified:        secret.Verified,
				}
				findings = append(findings, finding)
			}
		}
	}

	// Output findings
	if len(findings) > 0 {
		if outputJSON != "" {
			jsonData, err := json.MarshalIndent(findings, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal findings: %v", err)
			}
			if err := os.WriteFile(outputJSON, jsonData, 0644); err != nil {
				return fmt.Errorf("failed to write findings: %v", err)
			}
		} else {
			for _, finding := range findings {
				fmt.Printf("\nSecret Found!\n")
				fmt.Printf("Channel: %s (%s)\n", finding.ChannelName, finding.ChannelID)
				fmt.Printf("Type: %s\n", finding.RuleTriggered)
				fmt.Printf("Severity: %s\n", finding.Severity)
				fmt.Printf("Verified: %v\n", finding.Verified)
				fmt.Printf("Description: %s\n", finding.Description)
				fmt.Printf("Detector: %s\n", finding.Detector)
				fmt.Printf("Timestamp: %s\n", finding.Timestamp)
				fmt.Printf("Sender: %s\n", finding.SenderInfo)
				fmt.Printf("Secret: %s\n", finding.MatchedWord)
				fmt.Printf("Context: %s\n", finding.MessageContents)
				fmt.Println(strings.Repeat("-", 80))
			}
		}
	}

	return nil
} 