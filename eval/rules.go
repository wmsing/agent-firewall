package eval

import (
	_ "embed"
	"encoding/json"
	"regexp"
)

//go:embed rules.json
var rulesJSON []byte

type hardRule struct {
	name    string
	pattern *regexp.Regexp
}

type ruleEntry struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

var hardRules []hardRule

func init() {
	var entries []ruleEntry
	if err := json.Unmarshal(rulesJSON, &entries); err != nil {
		panic("eval: rules.json: " + err.Error())
	}
	rules := make([]hardRule, len(entries))
	for i, e := range entries {
		if e.Name == "" || e.Pattern == "" {
			panic("eval: rules.json: empty name or pattern")
		}
		re, err := regexp.Compile(e.Pattern)
		if err != nil {
			panic("eval: rules.json: rule " + e.Name + ": " + err.Error())
		}
		rules[i] = hardRule{name: e.Name, pattern: re}
	}
	hardRules = rules
}
