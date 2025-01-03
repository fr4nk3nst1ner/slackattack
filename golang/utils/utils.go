package utils

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

var (
	UniqueHashes = make(map[string]bool)
)

func GenerateUniqueFilename(url string) string {
	timestamp := time.Now().Format("20060102150405")
	hash := md5.Sum([]byte(url))
	uniqueID := hex.EncodeToString(hash[:])[:4]
	return fmt.Sprintf("%s_%s_%s", timestamp, uniqueID, getLastPathComponent(url))
}

func UnixTimestampToHumanReadable(timestamp int64) string {
	t := time.Unix(timestamp, 0)
	return t.Format("2006-01-02 15:04:05")
}

func getLastPathComponent(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return "unknown"
}

func SaveJSONOutput(data interface{}, filename string) error {
	if filename == "" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(data)
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
} 