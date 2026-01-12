package config

import (
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	VirusTotalKey    string
	AbuseIPDBKey     string
	AlienVaultKey    string
	ShodanKey        string
	URLScanKey       string
	MalwareBazaarKey string
	Timeout          time.Duration
}

func LoadConfig() (*Config, error) {
	_ = godotenv.Load()

	return &Config{
		VirusTotalKey:    getEnv("VIRUSTOTAL_API_KEY", ""),
		AbuseIPDBKey:     getEnv("ABUSEIPDB_API_KEY", ""),
		AlienVaultKey:    getEnv("ALIENVAULT_API_KEY", ""),
		ShodanKey:        getEnv("SHODAN_API_KEY", ""),
		URLScanKey:       getEnv("URLSCAN_API_KEY", ""),
		MalwareBazaarKey: getEnv("MALWAREBAZAAR_API_KEY", ""),
		Timeout:          time.Duration(getEnvAsInt("SCAN_TIMEOUT", 30)) * time.Second,
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}
