package utils

import (
	"net"
	"regexp"
	"strings"
)

func DetectIOCType(input string) string {
	if net.ParseIP(input) != nil {
		return "IP"
	}
	isHash, _ := regexp.MatchString(`^[a-fA-F0-9]{32,64}$`, input)
	if isHash {
		return "HASH"
	}
	if strings.HasPrefix(input, "http") || strings.Contains(input, ".") {
		return "URL"
	}
	return "UNKNOWN"
}
