// Package reach works out which KV paths a Vault or OpenBao token can reach,
// using the token's resultant ACL where LIST is not permitted.
package reach

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Rule is one entry of the resultant ACL of a token.
type Rule struct {
	// Path without a trailing '*'. Segments may be "+".
	Path string
	// Prefix is true for rules written with a trailing '*'.
	Prefix bool
	Caps   []string
}

// Denied reports whether the rule grants nothing.
func (r Rule) Denied() bool {
	if len(r.Caps) == 0 {
		return true
	}
	for _, c := range r.Caps {
		if c == "deny" {
			return true
		}
	}
	return false
}

// Pattern returns the rule path as written in a policy.
func (r Rule) Pattern() string {
	if r.Prefix {
		return r.Path + "*"
	}
	return r.Path
}

// ACL is the parsed response of sys/internal/ui/resultant-acl.
type ACL struct {
	Root  bool
	Rules []Rule
}

type aclPerms struct {
	Capabilities []string `json:"capabilities"`
}

// ParseResultantACL parses the "data" object of sys/internal/ui/resultant-acl.
//
// Vault stores prefix rules without the trailing '*' and reports them under
// glob_paths. Rules containing '+' keep their trailing '*' if they have one.
func ParseResultantACL(data []byte) (*ACL, error) {
	var raw struct {
		Root  bool                `json:"root"`
		Exact map[string]aclPerms `json:"exact_paths"`
		Glob  map[string]aclPerms `json:"glob_paths"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse resultant-acl: %w", err)
	}
	a := &ACL{Root: raw.Root}
	for p, v := range raw.Exact {
		a.Rules = append(a.Rules, Rule{Path: p, Caps: v.Capabilities})
	}
	for p, v := range raw.Glob {
		r := Rule{Path: p, Prefix: true, Caps: v.Capabilities}
		if strings.Contains(p, "+") {
			r.Prefix = strings.HasSuffix(p, "*")
			r.Path = strings.TrimSuffix(p, "*")
		}
		a.Rules = append(a.Rules, r)
	}
	sort.Slice(a.Rules, func(i, j int) bool {
		if a.Rules[i].Path != a.Rules[j].Path {
			return a.Rules[i].Path < a.Rules[j].Path
		}
		return !a.Rules[i].Prefix && a.Rules[j].Prefix
	})
	return a, nil
}

// Child is a name one level below a folder that some rule refers to.
type Child struct {
	// Name is a key ("db") or a folder ("team/").
	Name string
	// Probe is a concrete path whose capabilities decide whether the child is
	// reachable. For a fully concrete rule it is the rule path itself.
	Probe string
	// Rule is the policy path that produced the child.
	Rule string
}

// Pattern is a level below a folder that a rule covers without naming it,
// for example "+" or "db-*". Such names cannot be derived from the ACL.
type Pattern struct {
	Name string
	Rule string
	Caps []string
}

// ProbeName is the key used to ask Vault for the capabilities a glob rule
// grants on names it does not spell out.
const ProbeName = "vault-kv-reach-probe"

// Children returns the names directly below base that rules in the ACL refer
// to. base is a full API path ending in "/" (for example "kv/data/team/"), or
// a mount-relative root such as "kv/data/".
func (a *ACL) Children(base string) ([]Child, []Pattern) {
	bs := strings.Split(strings.TrimSuffix(base, "/"), "/")
	var kids []Child
	var pats []Pattern
	for _, r := range a.Rules {
		if r.Denied() {
			continue
		}
		ps := strings.Split(r.Path, "/")
		if !matchBase(ps, r.Prefix, bs) {
			// A prefix rule that ends inside base covers everything below it.
			if coversAll(ps, r.Prefix, bs) {
				pats = append(pats, Pattern{Name: "*", Rule: r.Pattern(), Caps: r.Caps})
			}
			continue
		}
		j := len(bs)
		if j >= len(ps) {
			continue
		}
		next := ps[j]
		last := j == len(ps)-1
		switch {
		case last && r.Prefix:
			pats = append(pats, Pattern{Name: next + "*", Rule: r.Pattern(), Caps: r.Caps})
		case next == "+":
			pats = append(pats, Pattern{Name: "+" + suffixMark(ps, j, r.Prefix), Rule: r.Pattern(), Caps: r.Caps})
		case last:
			if next == "" {
				continue // the folder itself, e.g. "kv/metadata/team/"
			}
			kids = append(kids, Child{Name: next, Probe: concrete(ps, bs, r.Prefix), Rule: r.Pattern()})
		default:
			kids = append(kids, Child{Name: next + "/", Probe: concrete(ps, bs, r.Prefix), Rule: r.Pattern()})
		}
	}
	return kids, pats
}

func suffixMark(ps []string, j int, prefix bool) string {
	if j < len(ps)-1 || prefix {
		return "/..."
	}
	return ""
}

// matchBase reports whether the first len(bs) segments of the rule match bs
// exactly or through "+", and the rule continues below bs.
func matchBase(ps []string, prefix bool, bs []string) bool {
	if len(ps) <= len(bs) {
		return false
	}
	for i, b := range bs {
		if ps[i] != "+" && ps[i] != b {
			return false
		}
	}
	return true
}

// coversAll reports whether a prefix rule ends at or above base, so that
// every name below base is covered.
func coversAll(ps []string, prefix bool, bs []string) bool {
	if !prefix || len(ps) > len(bs) {
		return false
	}
	for i, p := range ps {
		last := i == len(ps)-1
		switch {
		case last && strings.HasPrefix(bs[i], p):
			return true
		case p == "+" || p == bs[i]:
		default:
			return false
		}
	}
	return false
}

// concrete returns a path to probe: the rule path with "+" segments in the
// base replaced by the base segments. Wildcards below the child, or a prefix
// rule, get ProbeName appended or substituted.
func concrete(ps []string, bs []string, prefix bool) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		switch {
		case i < len(bs):
			out[i] = bs[i]
		case p == "+":
			out[i] = ProbeName
		default:
			out[i] = p
		}
	}
	s := strings.Join(out, "/")
	if prefix {
		s += ProbeName
	}
	return s
}

// Reachable reports whether a capabilities-self result grants anything.
func Reachable(caps []string) bool {
	if len(caps) == 0 {
		return false
	}
	for _, c := range caps {
		if c == "deny" {
			return false
		}
	}
	return true
}
