package checks

import (
	"strings"

	"../models"
)

func VerifyHSTS(headers map[string]string) models.SecurityCheck {
	check := models.SecurityCheck{
		Name:        "HSTS",
		Description: "HTTP Strict Transport Security header should be present",
		Severity:    "High",
		Expected:    "Strict-Transport-Security header with max-age and includeSubDomains",
	}

	if hsts, exists := headers["Strict-Transport-Security"]; exists {
		check.Passed = true
		check.Value = hsts
		check.Description = "HSTS header is present"

		// Validate HSTS directives
		if !strings.Contains(hsts, "max-age=") {
			check.Passed = false
			check.Description += ", but missing max-age directive"
		} else if strings.Contains(hsts, "max-age=0") {
			check.Passed = false
			check.Description += ", but max-age is 0 (disables HSTS)"
		}

		if !strings.Contains(hsts, "includeSubDomains") {
			check.Description += ", consider adding includeSubDomains"
		}
	} else {
		check.Passed = false
		check.Description = "Missing Strict-Transport-Security header"
	}

	return check
}