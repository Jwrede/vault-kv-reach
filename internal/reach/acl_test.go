package reach

import (
	"reflect"
	"sort"
	"testing"
)

const sampleACL = `{
 "root": false,
 "exact_paths": {
  "kv/data/team-b/config": {"capabilities": ["read"]},
  "kv/data/shared/readme": {"capabilities": ["read"]},
  "kv/data/hidden/x": {"capabilities": ["deny"]},
  "legacy/ops/db": {"capabilities": ["read"]}
 },
 "glob_paths": {
  "kv/data/team-a/": {"capabilities": ["list", "read"]},
  "kv/metadata/team-a/": {"capabilities": ["list", "read"]},
  "kv/data/shared/": {"capabilities": ["deny"]},
  "kv/data/apps/+/token": {"capabilities": ["read"]},
  "kv/data/svc/+/conf/*": {"capabilities": ["read"]},
  "kv/data/db-": {"capabilities": ["read"]},
  "+/data/everyone/motd": {"capabilities": ["read"]}
 }
}`

func names(cs []Child) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Name)
	}
	sort.Strings(out)
	return out
}

func patNames(ps []Pattern) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}

func TestParse(t *testing.T) {
	a, err := ParseResultantACL([]byte(sampleACL))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range a.Rules {
		got[r.Pattern()] = true
	}
	for _, want := range []string{"kv/data/team-a/*", "kv/data/apps/+/token", "kv/data/svc/+/conf/*", "kv/data/db-*", "kv/data/team-b/config"} {
		if !got[want] {
			t.Errorf("missing rule %s in %v", want, got)
		}
	}
}

func TestChildren(t *testing.T) {
	a, _ := ParseResultantACL([]byte(sampleACL))
	cases := []struct {
		base string
		kids []string
		pats []string
	}{
		{"kv/data/", []string{"apps/", "everyone/", "svc/", "team-a/", "team-b/", "shared/"}, []string{"db-*"}},
		{"kv/data/team-b/", []string{"config"}, nil},
		{"kv/data/team-a/", nil, []string{"*"}},
		{"kv/data/team-a/deep/", nil, []string{"*"}},
		{"kv/data/apps/", nil, []string{"+/..."}},
		{"kv/data/svc/", nil, []string{"+/..."}},
		{"kv/data/shared/", []string{"readme"}, nil},
		{"kv/data/hidden/", nil, nil},
		{"other/data/", []string{"everyone/"}, nil},
		{"legacy/", []string{"data/", "ops/"}, nil}, // "+/data/everyone/motd" also matches a v1 mount
		{"legacy/ops/", []string{"db"}, nil},
	}
	for _, c := range cases {
		k, p := a.Children(c.base)
		gk, gp := names(k), patNames(p)
		sort.Strings(c.kids)
		if !reflect.DeepEqual(gk, c.kids) || !reflect.DeepEqual(gp, c.pats) {
			t.Errorf("%s: kids %v pats %v, want %v %v", c.base, gk, gp, c.kids, c.pats)
		}
	}
}

func TestProbe(t *testing.T) {
	a, _ := ParseResultantACL([]byte(sampleACL))
	k, _ := a.Children("kv/data/")
	probes := map[string]string{}
	for _, c := range k {
		probes[c.Name+" "+c.Rule] = c.Probe
	}
	want := map[string]string{
		"team-a/ kv/data/team-a/*":       "kv/data/team-a/" + ProbeName,
		"team-b/ kv/data/team-b/config":  "kv/data/team-b/config",
		"apps/ kv/data/apps/+/token":     "kv/data/apps/" + ProbeName + "/token",
		"everyone/ +/data/everyone/motd": "kv/data/everyone/motd",
	}
	for k, v := range want {
		if probes[k] != v {
			t.Errorf("probe for %s = %q, want %q (all: %v)", k, probes[k], v, probes)
		}
	}
}

func TestMountFor(t *testing.T) {
	ms := []Mount{{Path: "kv/", Version: 2}, {Path: "kv/nested/", Version: 1}}
	m, ok := MountFor(ms, "kv/nested/a")
	if !ok || m.Path != "kv/nested/" {
		t.Fatalf("got %v %v", m, ok)
	}
	m, ok = MountFor(ms, "kv")
	if !ok || m.Path != "kv/" {
		t.Fatalf("got %v %v", m, ok)
	}
	if _, ok := MountFor(ms, "kvx/a"); ok {
		t.Fatal("kvx/ matched kv/")
	}
}

func TestReachable(t *testing.T) {
	if Reachable(nil) || Reachable([]string{"deny"}) || !Reachable([]string{"read"}) {
		t.Fatal("Reachable")
	}
}
