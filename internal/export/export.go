// Package export serialises a workspace for other tools: a full JSON dump, a
// flat findings CSV for spreadsheets, and SARIF 2.1.0 for security pipelines
// (GitHub code scanning, DefectDojo, etc.).
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"snitch/internal/store"
)

// JSON writes the whole workspace as indented JSON.
func JSON(w io.Writer, ws *store.Workspace) error {
	payload := struct {
		Project    string             `json:"project"`
		Subdomains []*store.Subdomain `json:"subdomains"`
		Assets     []*store.Asset     `json:"assets"`
		Findings   []*store.Finding   `json:"findings"`
		Paths      []*store.WebPath   `json:"paths"`
	}{
		Project:    ws.Project,
		Subdomains: ws.AllSubdomains(),
		Assets:     ws.AllAssets(),
		Findings:   ws.AllFindings(),
		Paths:      ws.AllPaths(),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

// FindingsCSV writes one row per finding, the shape most people want in a
// spreadsheet or to diff between engagements.
func FindingsCSV(w io.Writer, ws *store.Workspace) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{
		"severity", "name", "host", "port", "template", "location",
		"cvss", "cve", "tags", "source", "first_seen",
	}); err != nil {
		return err
	}
	for _, f := range ws.AllFindings() {
		cvss := ""
		if f.CVSSScore > 0 {
			cvss = strconv.FormatFloat(f.CVSSScore, 'f', 1, 64)
		}
		if err := cw.Write([]string{
			f.Severity, f.Name, f.Host, strconv.Itoa(f.Port), f.TemplateID, f.MatchedAt,
			cvss, strings.Join(f.CVEIDs, " "), strings.Join(f.Tags, " "),
			f.SourceTool, f.FirstSeen.Format("2006-01-02T15:04:05Z"),
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}

// ---------- SARIF 2.1.0 ----------

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      *sarifText     `json:"fullDescription,omitempty"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// sarifLevel maps a snitch severity onto SARIF's error/warning/note scale.
func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity is the 0–10 number GitHub code scanning uses to bucket a
// rule. We prefer the real CVSS score and fall back to a per-severity value.
func securitySeverity(f *store.Finding) string {
	if f.CVSSScore > 0 {
		return strconv.FormatFloat(f.CVSSScore, 'f', 1, 64)
	}
	switch strings.ToLower(f.Severity) {
	case "critical":
		return "9.5"
	case "high":
		return "8.0"
	case "medium":
		return "5.5"
	case "low":
		return "3.0"
	default:
		return "0.0"
	}
}

// SARIF writes the findings as a SARIF 2.1.0 log. Each distinct template
// becomes a rule; each finding becomes a result located at its matched URL.
func SARIF(w io.Writer, ws *store.Workspace) error {
	findings := ws.AllFindings()

	rules := make([]sarifRule, 0)
	seenRule := map[string]bool{}
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		if !seenRule[f.TemplateID] {
			seenRule[f.TemplateID] = true
			rule := sarifRule{
				ID:                   f.TemplateID,
				Name:                 f.Name,
				ShortDescription:     sarifText{Text: f.Name},
				DefaultConfiguration: sarifConfig{Level: sarifLevel(f.Severity)},
				Properties:           map[string]any{"security-severity": securitySeverity(f)},
			}
			if f.Description != "" {
				rule.FullDescription = &sarifText{Text: f.Description}
			}
			if len(f.References) > 0 {
				rule.HelpURI = f.References[0]
			}
			if len(f.Tags) > 0 {
				rule.Properties["tags"] = f.Tags
			}
			rules = append(rules, rule)
		}

		res := sarifResult{
			RuleID:     f.TemplateID,
			Level:      sarifLevel(f.Severity),
			Message:    sarifText{Text: findingMessage(f)},
			Properties: map[string]any{"severity": f.Severity},
		}
		if f.MatchedAt != "" {
			res.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.MatchedAt}},
			}}
		}
		results = append(results, res)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:  "snitch",
				Rules: rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func findingMessage(f *store.Finding) string {
	msg := f.Name
	if f.Host != "" {
		msg = fmt.Sprintf("%s on %s", f.Name, f.Host)
	}
	if f.Description != "" {
		msg += ": " + f.Description
	}
	return msg
}
