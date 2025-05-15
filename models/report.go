package models

type SecurityReport struct {
	URL     string                   `json:"url"`
	Headers map[string]string        `json:"headers"`
	Score   int                      `json:"score"`
	Checks  []SecurityCheck          `json:"checks"`
	Success bool                     `json:"success"`
	Error   string                   `json:"error,omitempty"`
}

type SecurityCheck struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Passed      bool   `json:"passed"`
	Severity    string `json:"severity"`
	Value       string `json:"value,omitempty"`
	Expected    string `json:"expected,omitempty"`
}