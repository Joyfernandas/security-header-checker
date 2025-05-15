package checks

import (
	"strings"

	"../models"
)

func VerifyCSP(headers map[string]string) models.SecurityCheck {
	check := models.SecurityCheck{
		Name:        "CSP",
		Description: "Content Security Policy header should be present",
		Severity:    "High",
		Expected:    "Content-Security-Policy header with secure directives",
	}

	if csp, exists := headers["Content-Security-Policy"]; exists {
		check.Passed = true
		check.Value = csp
		check.Description = "CSP header is present"

		// Additional checks for unsafe directives
		if strings.Contains(csp, "unsafe-inline") {
			check.Passed = false
			check.Description += ", but contains unsafe-inline directive"
		}
		if strings.Contains(csp, "unsafe-eval") {
			check.Passed = false
			check.Description += ", but contains unsafe-eval directive"
		}
	} else {
		check.Passed = false
		check.Description = "Missing Content-Security-Policy header"
	}

	return check
}