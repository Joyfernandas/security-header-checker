package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
	
	"./checks"
	"./models"
)

func main() {
    // Create a response struct
    type Response struct {
        Success bool           `json:"success"`
        Report  SecurityReport `json:"report,omitempty"`
        Error   string         `json:"error,omitempty"`
    }

    if len(os.Args) < 2 {
        json.NewEncoder(os.Stdout).Encode(Response{
            Success: false,
            Error:   "Usage: scanner <url>",
        })
        os.Exit(1)
    }

    url := os.Args[1]
    report := analyzeURL(url)

    // Ensure we output JSON regardless of outcome
    if err := json.NewEncoder(os.Stdout).Encode(Response{
        Success: report.Success,
        Report:  report,
        Error:   report.Error,
    }); err != nil {
        fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
        os.Exit(1)
    }
}

func analyzeURL(url string) models.SecurityReport {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return models.SecurityReport{
			URL:     url,
			Success: false,
			Error:   err.Error(),
		}
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	report := models.SecurityReport{
		URL:     url,
		Headers: headers,
		Checks:  []models.SecurityCheck{},
	}

	// Run all security checks
	report.Checks = append(report.Checks, checks.VerifyCSP(headers))
	report.Checks = append(report.Checks, checks.VerifyHSTS(headers))
	report.Checks = append(report.Checks, checks.VerifyXFrameOptions(headers))
	report.Checks = append(report.Checks, checks.VerifyXContentTypeOptions(headers))
	report.Checks = append(report.Checks, checks.VerifyReferrerPolicy(headers))
	report.Checks = append(report.Checks, checks.VerifyPermissionsPolicy(headers))

	// Calculate score
	report.Score = calculateScore(report.Checks)
	report.Success = true

	return report
}

func calculateScore(checks []models.SecurityCheck) int {
	totalPossible := 0
	score := 0

	for _, check := range checks {
		weight := getCheckWeight(check.Name)
		totalPossible += weight
		if check.Passed {
			score += weight
		}
	}

	if totalPossible == 0 {
		return 0
	}

	return int(float64(score) / float64(totalPossible) * 100)
}

func getCheckWeight(checkName string) int {
	weights := map[string]int{
		"CSP":                 30,
		"HSTS":                25,
		"X-Frame-Options":     15,
		"X-Content-Type-Options": 10,
		"Referrer-Policy":     10,
		"Permissions-Policy":  10,
	}
	return weights[checkName]
}