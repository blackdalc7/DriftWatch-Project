// Package catalog is the agent's compiled-in copy of the Safe Action Catalog.
//
// The server validates every step before it signs a bundle, and the agent validates it again here. A
// compromised or buggy server can therefore never make the agent run an action or a parameter value that
// is not listed below: there is no free-form command field, and enum values map to fixed command lines.
// Keep this file in sync with src/driftwatch/catalog.py; TestCatalogMatchesPython checks it in CI.
package catalog

import (
	"encoding/json"
	"fmt"
	"math"
)

const (
	Windows = "windows"
	Linux   = "linux"
)

// Param is one typed parameter of an action.
type Param struct {
	Name     string
	Kind     string // "enum" | "int" | "bool"
	Required bool
	Choices  []string
	Min, Max int
	Default  any
}

// Action is a catalog entry.
type Action struct {
	ID        string
	Platforms []string
	Params    []Param
	// ChoicePlatform restricts specific enum values to one platform.
	ChoicePlatform map[string]string
}

var discoveryChoices = map[string]string{
	"whoami_all": Windows, "systeminfo": Windows, "ipconfig_all": Windows, "net_localgroup_admins": Windows,
	"tasklist": Windows, "id": Linux, "uname_a": Linux, "ip_addr": Linux, "getent_group_sudo": Linux,
	"ps_aux": Linux,
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func hold(def int) []Param {
	return []Param{{Name: "hold_seconds", Kind: "int", Min: 1, Max: 120, Default: def}}
}

// Actions is the catalog, keyed by action id.
var Actions = map[string]Action{
	"file.eicar_drop": {ID: "file.eicar_drop", Platforms: []string{Windows, Linux},
		Params: []Param{{Name: "wait_seconds", Kind: "int", Min: 1, Max: 60, Default: 10}}},
	"process.discovery": {ID: "process.discovery", Platforms: []string{Windows, Linux},
		Params:         []Param{{Name: "command", Kind: "enum", Required: true, Choices: keys(discoveryChoices)}},
		ChoicePlatform: discoveryChoices},
	"registry.run_key_canary":      {ID: "registry.run_key_canary", Platforms: []string{Windows}, Params: hold(15)},
	"scheduled_task.canary":        {ID: "scheduled_task.canary", Platforms: []string{Windows}, Params: hold(15)},
	"persistence.autostart_canary": {ID: "persistence.autostart_canary", Platforms: []string{Linux}, Params: hold(15)},
	"dns.sinkhole_query": {ID: "dns.sinkhole_query", Platforms: []string{Windows, Linux},
		Params: []Param{{Name: "count", Kind: "int", Min: 1, Max: 10, Default: 3}}},
	"file.credential_canary_read": {ID: "file.credential_canary_read", Platforms: []string{Windows, Linux}},
	"powershell.encoded_marker":   {ID: "powershell.encoded_marker", Platforms: []string{Windows}},
	"hygiene.collect":             {ID: "hygiene.collect", Platforms: []string{Windows, Linux}},
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Validate checks a step against the catalog for this platform and returns normalized parameters
// (defaults filled in, ints as int). Unknown actions, unknown parameters, wrong types, out-of-range
// values and wrong-platform choices are all rejected.
func Validate(actionID string, raw map[string]json.RawMessage, platform string) (map[string]any, error) {
	action, ok := Actions[actionID]
	if !ok {
		return nil, fmt.Errorf("action %q is not in the compiled-in Safe Action Catalog", actionID)
	}
	if !contains(action.Platforms, platform) {
		return nil, fmt.Errorf("action %s does not support platform %s", actionID, platform)
	}
	known := map[string]Param{}
	for _, p := range action.Params {
		known[p.Name] = p
	}
	for name := range raw {
		if _, ok := known[name]; !ok {
			return nil, fmt.Errorf("action %s does not accept parameter %q", actionID, name)
		}
	}
	out := map[string]any{}
	for _, p := range action.Params {
		value, present := raw[p.Name]
		if !present {
			if p.Required {
				return nil, fmt.Errorf("action %s requires parameter %q", actionID, p.Name)
			}
			if p.Default != nil {
				out[p.Name] = p.Default
			}
			continue
		}
		switch p.Kind {
		case "enum":
			var s string
			if err := json.Unmarshal(value, &s); err != nil || !contains(p.Choices, s) {
				return nil, fmt.Errorf("parameter %q has a value outside the catalog", p.Name)
			}
			if want, ok := action.ChoicePlatform[s]; ok && want != platform {
				return nil, fmt.Errorf("%q is a %s choice", s, want)
			}
			out[p.Name] = s
		case "int":
			var f float64
			if err := json.Unmarshal(value, &f); err != nil || f != math.Trunc(f) {
				return nil, fmt.Errorf("parameter %q must be an integer", p.Name)
			}
			n := int(f)
			if n < p.Min || n > p.Max {
				return nil, fmt.Errorf("parameter %q must be between %d and %d", p.Name, p.Min, p.Max)
			}
			out[p.Name] = n
		case "bool":
			var b bool
			if err := json.Unmarshal(value, &b); err != nil {
				return nil, fmt.Errorf("parameter %q must be true or false", p.Name)
			}
			out[p.Name] = b
		default:
			return nil, fmt.Errorf("unsupported parameter kind %q", p.Kind)
		}
	}
	return out, nil
}
