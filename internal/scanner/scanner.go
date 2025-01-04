package scanner

import (
    "context"
    "regexp"

    "github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
    "github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// Result represents a found secret
type Result struct {
    Type        string `json:"type"`
    Secret      string `json:"secret"`
    Description string `json:"description"`
    Severity    string `json:"severity"`
    Detector    string `json:"detector"`
    Verified    bool   `json:"verified"`
}

// ScanForSecrets scans content for potential secrets using TruffleHog detectors
func ScanForSecrets(content string) []Result {
    var results []Result
    ctx := context.Background()

    // Initialize all requested detectors
    detectorTypes := []detectors.Detector{
        // Cloud Providers
        &detectors.AWS{},
        &detectors.GCP{},
        &detectors.GCPApplicationDefaultCredentials{},
        &detectors.DigitalOceanToken{},

        // Azure Services
        &detectors.AzureBatch{},
        &detectors.AzureEntra{},
        &detectors.AzureOpenAI{},
        &detectors.AzureStorage{},
        &detectors.AzureContainerRegistry{},
        &detectors.AzureDevopsPersonalAccessToken{},
        &detectors.AzureFunctionKey{},
        &detectors.AzureSearchAdminKey{},
        &detectors.AzureSearchQueryKey{},

        // Source Control & CI/CD
        &detectors.Github{},
        &detectors.GithubOauth{},
        &detectors.GithubApp{},
        &detectors.Gitlab{},
        &detectors.TravisCI{},
        &detectors.JiraToken{},
        &detectors.TerraformCloudPersonalToken{},

        // Payment Services
        &detectors.Stripe{},
        &detectors.PaypalOauth{},
        &detectors.Square{},
        &detectors.PlaidKey{},
        &detectors.Coinbase{},

        // Authentication & Identity
        &detectors.Auth0ManagementAPIToken{},
        &detectors.Auth0Oauth{},
        &detectors.Okta{},
        &detectors.OneLogin{},

        // Communication Services
        &detectors.Twilio{},
        &detectors.TwilioAPIKey{},
        &detectors.SendGrid{},
        &detectors.Mailgun{},
        &detectors.Slack{},
        &detectors.SlackWebhook{},
        &detectors.TelegramBotToken{},

        // Container & Package Registries
        &detectors.DockerHub{},
        &detectors.Artifactory{},
        &detectors.Cloudsmith{},

        // Databases
        &detectors.Postgres{},
        &detectors.MongoDB{},
        &detectors.Redis{},
        &detectors.SQLServer{},

        // AI Services
        &detectors.OpenAI{},
        &detectors.Anthropic{},
        &detectors.HuggingFace{},

        // Infrastructure & DevOps
        &detectors.CloudflareAPIToken{},
        &detectors.CloudflareGlobalAPIKey{},
        &detectors.GoDaddy{},
        &detectors.PagerDutyAPIKey{},
        &detectors.Opsgenie{},
        &detectors.Grafana{},
        &detectors.GrafanaServiceAccount{},
        &detectors.SentryToken{},
    }

    // Scan with each detector
    for _, d := range detectorTypes {
        findings, err := d.FromData(ctx, []byte(content))
        if err != nil {
            continue
        }

        for _, finding := range findings {
            result := Result{
                Type:        d.Name(),
                Secret:      finding.Raw,
                Description: finding.Description,
                Severity:    finding.Severity.String(),
                Detector:    finding.DetectorType.String(),
                Verified:    finding.Verified,
            }

            // Only include verified secrets or high confidence matches
            if finding.Verified || finding.Severity >= common.Critical {
                results = append(results, result)
            }
        }
    }

    // Add custom regex patterns for additional coverage
    regexResults := scanWithRegex(content)
    results = append(results, regexResults...)

    return results
}

func scanWithRegex(content string) []Result {
    var results []Result

    // Custom regex patterns for additional coverage
    regexDetectors := map[string]*regexp.Regexp{
        "Private Key":     regexp.MustCompile(`(?i)-----BEGIN (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY( BLOCK)?-----`),
        "Password Field":  regexp.MustCompile(`(?i)(?:password|passwd|pwd)[\s]*[:=>\s]+[\s]*['"]([^'"]{8,})['"]`),
        "API Key":        regexp.MustCompile(`(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?key)[\s]*[:=>\s]+[\s]*['"]([^'"]{16,})['"]`),
        "Bearer Token":   regexp.MustCompile(`(?i)bearer[\s]+[a-zA-Z0-9_\-\.=]+`),
        "Authorization":  regexp.MustCompile(`(?i)authorization[\s]*[:=>\s]+[\s]*['"]([^'"]{16,})['"]`),
        "Connection String": regexp.MustCompile(`(?i)(?:connection[_-]?string|conn[_-]?str)[\s]*[:=>\s]+[\s]*['"]([^'"]{16,})['"]`),
    }

    for detectorName, regex := range regexDetectors {
        matches := regex.FindAllString(content, -1)
        for _, match := range matches {
            results = append(results, Result{
                Type:        detectorName,
                Secret:      match,
                Description: "Potential secret found via pattern matching",
                Severity:    "MEDIUM",
                Detector:    "Custom Regex",
                Verified:    false,
            })
        }
    }

    return results
} 