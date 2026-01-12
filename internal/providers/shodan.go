package providers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Zerkem/ravenintel/internal/models"
)

type Shodan struct {
	APIKey string
}

func (p *Shodan) Name() string { return "Shodan" }

func (p *Shodan) Enrich(ioc string, iocType string) (models.AnalysisResult, error) {
	if iocType != "IP" {
		return models.AnalysisResult{ProviderName: p.Name(), Details: "Shodan only supports IP addresses."}, nil
	}

	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ioc, p.APIKey)
	resp, err := http.Get(url)
	if err != nil {
		return models.AnalysisResult{ProviderName: p.Name(), Error: err}, err
	}
	defer resp.Body.Close()

	var result struct {
		Ports []int  `json:"ports"`
		Org   string `json:"org"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	return models.AnalysisResult{
		ProviderName: p.Name(),
		IsMalicious:  len(result.Ports) > 5,
		Severity:     "Info",
		Details:      fmt.Sprintf("Organization: %s | Open Ports: %v", result.Org, result.Ports),
	}, nil
}
