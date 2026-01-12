package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Zerkem/ravenintel/internal/config"
	"github.com/Zerkem/ravenintel/internal/engine"
	"github.com/Zerkem/ravenintel/internal/models"
	"github.com/Zerkem/ravenintel/internal/providers"
	"github.com/Zerkem/ravenintel/pkg/utils"
)

func main() {
	iocFlag := flag.String("t", "", "Target IOC (IP, Hash, or URL)")
	flag.Parse()

	target := *iocFlag
	printBanner()

	if target == "" {
		fmt.Print("[?] Enter target (IP, Hash, or URL): ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			target = strings.TrimSpace(scanner.Text())
		}
	}

	iocType := utils.DetectIOCType(target)
	if iocType == "UNKNOWN" {
		log.Fatalf("[!] ERROR: Invalid target. Provide a valid IP, Hash, or URL.")
	}

	fmt.Printf("[*] Detected Type: %s\n", iocType)

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("[!] CONFIG ERROR: %v", err)
	}

	var activeProviders []models.Enricher

	switch iocType {
	case "IP":
		activeProviders = []models.Enricher{
			&providers.AbuseIPDB{APIKey: cfg.AbuseIPDBKey},
			&providers.VirusTotal{APIKey: cfg.VirusTotalKey},
			&providers.AlienVault{APIKey: cfg.AlienVaultKey},
			&providers.Shodan{APIKey: cfg.ShodanKey},
		}
		fmt.Println("[*] Mode: All systems active (Full IP Scan)")

	case "URL":
		activeProviders = []models.Enricher{
			&providers.VirusTotal{APIKey: cfg.VirusTotalKey},
			&providers.URLScan{APIKey: cfg.URLScanKey},
		}
		fmt.Println("[*] Mode: URL Focused Scan (VirusTotal + URLScan)")

	case "HASH":
		activeProviders = []models.Enricher{
			&providers.VirusTotal{APIKey: cfg.VirusTotalKey},
			&providers.MalwareBazaar{APIKey: cfg.MalwareBazaarKey},
		}
		fmt.Println("[*] Mode: Malware Research (VirusTotal + MalwareBazaar)")
	}

	fmt.Printf("[*] Analyzing: %s\n", target)

	results := engine.Scan(target, iocType, activeProviders, int(cfg.Timeout.Seconds()))

	renderDetailedReport(results, target, iocType)
}

func renderDetailedReport(results []models.AnalysisResult, target, iocType string) {
	fmt.Printf("\n" + strings.Repeat("=", 70))
	fmt.Printf("\n          RAVEN INTEL - SECURITY ANALYSIS REPORT")
	fmt.Printf("\nTARGET: %s (%s)", target, iocType)
	fmt.Printf("\n" + strings.Repeat("=", 70) + "\n")

	isAnyThreat := false

	for _, res := range results {
		fmt.Printf("\n[+] SOURCE: %s\n", strings.ToUpper(res.ProviderName))

		if res.Error != nil {
			fmt.Printf("    - STATUS  : ⚠️  SCAN ERROR\n")
			fmt.Printf("    - DETAILS : %v\n", res.Error)
			continue
		}

		status := "🟢 CLEAN"
		if res.IsMalicious {
			status = "🔴 MALICIOUS / HIGH RISK"
			isAnyThreat = true
		}
		fmt.Printf("    - SAFETY STATUS: %s\n", status)
		fmt.Printf("    - SEVERITY     : %s\n", res.Severity)

		fmt.Print("    - WHAT IS THIS?: ")
		switch res.ProviderName {
		case "AbuseIPDB":
			fmt.Println("Database for reported malicious IPs.")
		case "VirusTotal":
			fmt.Println("Multi-engine antivirus and URL scanner report.")
		case "URLScan.io":
			fmt.Println("Web page visibility and domain relationship analysis.")
		case "MalwareBazaar":
			fmt.Println("Database of known malware samples and families.")
		case "Shodan":
			fmt.Println("Infrastructure and open services intelligence.")
		case "AlienVault OTX":
			fmt.Println("Community-driven threat indicators (pulses).")
		default:
			fmt.Println("Security intelligence information.")
		}

		fmt.Printf("    - FINDINGS     : %s\n", res.Details)
		fmt.Println(strings.Repeat("-", 45))
	}

	fmt.Printf("\n" + strings.Repeat("=", 70))
	if isAnyThreat {
		fmt.Printf("\n🚨 FINAL VERDICT: POTENTIALLY DANGEROUS!")
	} else {
		fmt.Printf("\n✅ FINAL VERDICT: NO IMMEDIATE THREATS FOUND.")
	}
	fmt.Printf("\n" + strings.Repeat("=", 70) + "\n\n")
}

func printBanner() {
	fmt.Println(`
    ____                        ____       __ZW 
   / __ \____ __   _____  ____ /  _/____  / /_ 
  / /_/ / __  / | / / _ \/ __ \/ // __ \/ __/ 
 / _, _/ /_/ /| |/ /  __/ / / / // / / / /_   
/_/ |_|\__,_/ |___/\___/_/ /_/___/_/ /_/\__/   v1.0
    >> Zerkem OSINT IOC Enrichment Tool <<
    `)
}
