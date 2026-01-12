package providers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Zerkem/ravenintel/internal/models"
)

type VirusTotal struct {
	APIKey string
}

func (p *VirusTotal) Name() string { return "VirusTotal" }

func (p *VirusTotal) Enrich(ioc string, iocType string) (models.AnalysisResult, error) {
	var url string
	if iocType == "URL" {
		// VT v3 URL için özel Base64: No Padding
		encodedURL := base64.RawURLEncoding.EncodeToString([]byte(ioc))
		url = fmt.Sprintf("https://www.virustotal.com/api/v3/urls/%s", encodedURL)
	} else if iocType == "IP" {
		url = fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ioc)
	} else if iocType == "HASH" {
		url = fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", ioc)
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-apikey", p.APIKey)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return models.AnalysisResult{ProviderName: p.Name(), Error: err}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return models.AnalysisResult{ProviderName: p.Name(), Details: fmt.Sprintf("API returned status %d", resp.StatusCode)}, nil
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return models.AnalysisResult{ProviderName: p.Name(), Error: err}, err
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return models.AnalysisResult{ProviderName: p.Name(), Details: "No data in response"}, nil
	}

	attrs, _ := data["attributes"].(map[string]interface{})
	stats, _ := attrs["last_analysis_stats"].(map[string]interface{})

	maliciousCount := 0
	if val, exists := stats["malicious"]; exists {
		maliciousCount = int(val.(float64))
	}

	return models.AnalysisResult{
		ProviderName: p.Name(),
		IOC:          ioc,
		IOCType:      iocType,
		IsMalicious:  maliciousCount > 0,
		Severity:     fmt.Sprintf("%d Detections", maliciousCount),
		Details:      fmt.Sprintf("Analyzed by 70+ engines, %d found it malicious.", maliciousCount),
		ScanTime:     time.Now(),
	}, nil
}
