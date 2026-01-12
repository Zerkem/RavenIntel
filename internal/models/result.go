package models

import "time"

type AnalysisResult struct {
	ProviderName string    `json:"provider"`
	IOC          string    `json:"ioc"`
	IOCType      string    `json:"type"`
	IsMalicious  bool      `json:"is_malicious"`
	Severity     string    `json:"severity"`
	Details      string    `json:"details"`
	RawData      any       `json:"raw_data"`
	ScanTime     time.Time `json:"scan_time"`
	Error        error     `json:"-"`
}

type Enricher interface {
	Name() string
	Enrich(ioc string, iocType string) (AnalysisResult, error)
}
