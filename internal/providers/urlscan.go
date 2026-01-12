package providers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Zerkem/ravenintel/internal/models"
)

type URLScan struct {
	APIKey string
}

func (p *URLScan) Name() string { return "URLScan.io" }

func (p *URLScan) Enrich(ioc string, iocType string) (models.AnalysisResult, error) {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", ioc)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("API-Key", p.APIKey)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return models.AnalysisResult{ProviderName: p.Name(), Error: err}, err
	}
	defer resp.Body.Close()

	var result struct {
		Total int `json:"total"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	return models.AnalysisResult{
		ProviderName: p.Name(),
		IsMalicious:  false,
		Severity:     "Info",
		Details:      fmt.Sprintf("Found %d historical scans for this domain.", result.Total),
		ScanTime:     time.Now(),
	}, nil
}
