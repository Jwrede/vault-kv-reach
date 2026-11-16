package reach

import (
	"context"
	"net/http"
	"sort"
	"strings"
)

// Listing is the content of one KV folder as far as the token can tell.
type Listing struct {
	// Source is "list" when Vault answered the LIST itself and "acl" when
	// the keys were derived from the resultant ACL.
	Source   string
	Keys     []string
	Patterns []Pattern
	// Rules maps each derived key to the policy paths that name it.
	Rules map[string][]string
}

// RuleBases returns the API prefixes under which policy rules for a folder
// of the mount can appear. KV v2 rules are written against data/ and
// metadata/; KV v1 rules against the mount itself.
func RuleBases(m Mount, folder string) []string {
	if m.Version == 2 {
		return []string{m.Path + "data/" + folder, m.Path + "metadata/" + folder}
	}
	return []string{m.Path + folder}
}

// ListPath is the API path a LIST on the folder goes to.
func ListPath(m Mount, folder string) string {
	if m.Version == 2 {
		return m.Path + "metadata/" + folder
	}
	return m.Path + folder
}

// Derive computes the keys of a folder from the ACL alone and keeps those for
// which capabilities-self grants something on the probe path.
func Derive(ctx context.Context, c *Client, acl *ACL, m Mount, folder string) (*Listing, error) {
	l := &Listing{Source: "acl", Rules: map[string][]string{}}
	var kids []Child
	seenPat := map[string]bool{}
	for _, base := range RuleBases(m, folder) {
		k, p := acl.Children(base)
		kids = append(kids, k...)
		for _, x := range p {
			key := x.Name + "\x00" + x.Rule
			if !seenPat[key] {
				seenPat[key] = true
				l.Patterns = append(l.Patterns, x)
			}
		}
	}
	var probes []string
	for _, k := range kids {
		probes = append(probes, k.Probe)
	}
	caps, err := c.CapabilitiesSelf(ctx, probes)
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	for _, k := range kids {
		if Reachable(caps[k.Probe]) {
			keep[k.Name] = true
			l.Rules[k.Name] = appendUniq(l.Rules[k.Name], k.Rule)
		}
	}
	// A key and a folder of the same name are both valid in KV.
	for k := range keep {
		l.Keys = append(l.Keys, k)
	}
	sort.Strings(l.Keys)
	sort.Slice(l.Patterns, func(i, j int) bool {
		if l.Patterns[i].Name != l.Patterns[j].Name {
			return l.Patterns[i].Name < l.Patterns[j].Name
		}
		return l.Patterns[i].Rule < l.Patterns[j].Rule
	})
	return l, nil
}

// Folder lists a folder with LIST and falls back to Derive on 403.
func Folder(ctx context.Context, c *Client, acl *ACL, m Mount, folder string) (*Listing, error) {
	keys, err := c.List(ctx, ListPath(m, folder))
	if err == nil {
		return &Listing{Source: "list", Keys: keys}, nil
	}
	if !IsStatus(err, http.StatusForbidden) {
		return nil, err
	}
	return Derive(ctx, c, acl, m, folder)
}

func appendUniq(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

// MountFor returns the mount whose path is the longest prefix of p.
func MountFor(mounts []Mount, p string) (Mount, bool) {
	var best Mount
	ok := false
	for _, m := range mounts {
		if strings.HasPrefix(p, m.Path) || p+"/" == m.Path {
			if !ok || len(m.Path) > len(best.Path) {
				best, ok = m, true
			}
		}
	}
	return best, ok
}
