package providers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Zerkem/ravenintel/internal/models"
)

type AlienVault struct {
	APIKey string
}

func (p *AlienVault) Name() string { return "AlienVault OTX" }

func (p *AlienVault) Enrich(ioc string, iocType string) (models.AnalysisResult, error) {
	var url string
	switch iocType {
	case "IP":
		url = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", ioc)
	case "HASH":
		url = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/file/%s/general", ioc)
	case "URL":
		url = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/url/%s/general", ioc)
	default:
		return models.AnalysisResult{ProviderName: p.Name(), Details: "Unsupported IOC type."}, nil
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-OTX-API-KEY", p.APIKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return models.AnalysisResult{ProviderName: p.Name(), Error: err}, err
	}
	defer resp.Body.Close()

	var result struct {
		PulseInfo struct {
			Count int `json:"count"`
		} `json:"pulse_info"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	return models.AnalysisResult{
		ProviderName: p.Name(),
		IOC:          ioc,
		IOCType:      iocType,
		IsMalicious:  result.PulseInfo.Count > 0,
		Severity:     fmt.Sprintf("%d Pulses", result.PulseInfo.Count),
		Details:      fmt.Sprintf("Found in %d community threat pulses", result.PulseInfo.Count),
		RawData:      result.PulseInfo,
		ScanTime:     time.Now(),
	}, nil
}
