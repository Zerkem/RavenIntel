package engine

import (
	"context"
	"sync"
	"time"

	"github.com/Zerkem/ravenintel/internal/models"
)

func Scan(ioc string, iocType string, providers []models.Enricher, timeout int) []models.AnalysisResult {
	var wg sync.WaitGroup
	resultsChan := make(chan models.AnalysisResult, len(providers))

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	for _, p := range providers {
		wg.Add(1)
		go func(prov models.Enricher) {
			defer wg.Done()

			resChan := make(chan models.AnalysisResult, 1)
			go func() {
				res, _ := prov.Enrich(ioc, iocType)
				resChan <- res
			}()

			select {
			case res := <-resChan:
				resultsChan <- res
			case <-ctx.Done():
				resultsChan <- models.AnalysisResult{
					ProviderName: prov.Name(),
					Error:        ctx.Err(),
				}
			}
		}(p)
	}

	wg.Wait()
	close(resultsChan)

	var results []models.AnalysisResult
	for r := range resultsChan {
		results = append(results, r)
	}
	return results
}
