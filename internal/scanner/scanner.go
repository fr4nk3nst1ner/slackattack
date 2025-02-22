package scanner

import (
    "encoding/json"
    "fmt"
    "os"
    "regexp"
    "strings"
)

// Result represents a found secret
type Result struct {
    Type        string `json:"type"`
    Secret      string `json:"secret"`
    Description string `json:"description"`
    Severity    string `json:"severity"`
    Detector    string `json:"detector"`
    Verified    bool   `json:"verified"`
    Raw         string `json:"raw_match"`
}

// Detector represents a regex pattern from the JSON file
type Detector struct {
    Name  string `json:"name"`
    Regex string `json:"regex"`
}

// loadDetectors reads the detectors.json file and returns a map of compiled regex patterns
func loadDetectors() (map[string]*regexp.Regexp, error) {
    // Read the JSON file
    data, err := os.ReadFile("detectors.json")
    if err != nil {
        return nil, fmt.Errorf("failed to read detectors.json: %v", err)
    }

    // Parse the JSON into a slice of Detector structs
    var detectors []Detector
    if err := json.Unmarshal(data, &detectors); err != nil {
        return nil, fmt.Errorf("failed to parse detectors.json: %v", err)
    }

    if len(detectors) == 0 {
        return nil, fmt.Errorf("no detectors found in detectors.json")
    }

    // Compile regex patterns
    patterns := make(map[string]*regexp.Regexp)
    for _, d := range detectors {
        // Extract just the regex pattern from the string
        // Remove the quotes, name, and concatenation syntax
        regexStr := d.Regex
        if idx := strings.Index(regexStr, "`"); idx != -1 {
            regexStr = regexStr[idx+1 : len(regexStr)-1] // Remove everything before the backtick and the final backtick
        }

        pattern, err := regexp.Compile(regexStr)
        if err != nil {
            fmt.Printf("Warning: skipping invalid pattern for %s: %v\n", d.Name, err)
            continue
        }
        patterns[d.Name] = pattern
    }

    if len(patterns) == 0 {
        return nil, fmt.Errorf("no valid patterns found in detectors.json")
    }

    return patterns, nil
}

// ScanForSecrets scans content for potential secrets
func ScanForSecrets(content string) []Result {
    var results []Result

    // Load patterns from detectors.json
    patterns, err := loadDetectors()
    if err != nil {
        fmt.Printf("Error loading detectors: %v\n", err)
        return results
    }

    // Scan with regex patterns
    for name, pattern := range patterns {
        matches := pattern.FindAllString(content, -1)
        for _, match := range matches {
            results = append(results, Result{
                Type:        name,
                Secret:      match,
                Description: "Potential secret found",
                Severity:    "HIGH",
                Detector:    "Regex Scanner",
                Verified:    false,
                Raw:         match,
            })
        }
    }

    return results
} 