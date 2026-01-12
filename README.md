# RavenIntel - OSINT IOC Enrichment Tool

**RavenIntel** is a high-performance intelligence gathering tool written in Go. It is designed to provide security analysts and researchers with a quick, "explain-like-I'm-five" (ELI5) detailed report on various **Indicators of Compromise (IOCs)** such as IP addresses, URLs, and Malware Hashes.

RavenIntel doesn't just fetch data; it adapts its engine based on the target type to save API credits and provide the most relevant security context.


##  Installation

### 1. Prerequisites
* Go 1.20 or higher installed.
* API keys for the supported providers (most offer free tiers).

### 2. Clone the Repository
```bash. Install Dependencies
git clone [https://github.com/Zerkem/RavenIntel.git](https://github.com/Zerkem/RavenIntel.git)
cd RavenIntel
```

### 3. Install Dependencies
```bash
go mod tidy
```

### 4. Setup Configuration
Create a .env file in the root directory and add your API keys:
```bash
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
ALIENVAULT_API_KEY=your_key
SHODAN_API_KEY=your_key
URLSCAN_API_KEY=your_key
MALWAREBAZAAR_API_KEY=your_key
SCAN_TIMEOUT=30
```
---
## Usage
You can run RavenIntel using command-line flags or the interactive menu.

### Scan an IP Address
```bash
go run cmd/RavenIntel/main.go -t 141.98.10.20
```

### Scan a Malware Hash
```bash
go run cmd/RavenIntel/main.go -t 098f6bcd4621d373cade4e832627b4f6
```

### Scan a Suspicious URL
```bash
go run cmd/RavenIntel/main.go -t http://suspicious-site.com
```
---
