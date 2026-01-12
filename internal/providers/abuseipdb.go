package providers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Zerkem/ravenintel/internal/models"
)

type AbuseIPDB struct {
	APIKey string
}

func (p *AbuseIPDB) Name() string { return "AbuseIPDB" }

func (p *AbuseIPDB) Enrich(ioc string, iocType string) (models.AnalysisResult, error) {
	if iocType != "IP" {
		return models.AnalysisResult{ProviderName: p.Name(), Details: "AbuseIPDB only supports IP addresses."}, nil
	}

	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s", ioc)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Key", p.APIKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return models.AnalysisResult{ProviderName: p.Name(), Error: err}, err
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	return models.AnalysisResult{
		ProviderName: p.Name(),
		IOC:          ioc,
		IOCType:      iocType,
		IsMalicious:  result.Data.AbuseConfidenceScore > 25,
		Severity:     fmt.Sprintf("%d%%", result.Data.AbuseConfidenceScore),
		Details:      fmt.Sprintf("Abuse Confidence Score is %d%%", result.Data.AbuseConfidenceScore),
		RawData:      result.Data,
		ScanTime:     time.Now(),
	}, nil
}
