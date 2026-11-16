// End-to-end tests against a real Vault or OpenBao dev server.
//
//	VKR_E2E_ADDR=http://127.0.0.1:18200 VKR_E2E_TOKEN=root go test -v ./e2e/
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Jwrede/vault-kv-reach/internal/proxy"
	"github.com/Jwrede/vault-kv-reach/internal/reach"
)

var hc = &http.Client{Timeout: 30 * time.Second}

type result struct {
	code int
	body map[string]any
}

func call(t *testing.T, addr, method, path, token string, body any) result {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimSuffix(addr, "/")+"/v1/"+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	r := result{code: resp.StatusCode}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &r.body)
	}
	return r
}

func must(t *testing.T, r result, path string) result {
	t.Helper()
	if r.code/100 != 2 {
		t.Fatalf("%s: HTTP %d %v", path, r.code, r.body)
	}
	return r
}

func keys(r result) []string {
	d, _ := r.body["data"].(map[string]any)
	ks, _ := d["keys"].([]any)
	var out []string
	for _, k := range ks {
		out = append(out, k.(string))
	}
	sort.Strings(out)
	return out
}

var v2Secrets = []string{
	"team-a/db", "team-a/api", "team-a/deep/x",
	"team-b/config", "team-b/other",
	"apps/web/token", "apps/worker/token", "apps/web/other",
	"shared/readme", "shared/private",
	"hidden/x", "top", "alice/notes", "bob/notes",
}

var v1Secrets = []string{"ops/db", "ops/other"}

func setup(t *testing.T, addr, root string) string {
	t.Helper()
	must(t, call(t, addr, "POST", "sys/mounts/kv", root, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}), "mount kv")
	must(t, call(t, addr, "POST", "sys/mounts/legacy", root, map[string]any{"type": "kv", "options": map[string]string{"version": "1"}}), "mount legacy")
	// KV v2 needs a moment after mounting before it accepts writes.
	deadline := time.Now().Add(30 * time.Second)
	for {
		r := call(t, addr, "POST", "kv/data/top", root, map[string]any{"data": map[string]string{"v": "top"}})
		if r.code/100 == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("kv v2 not ready: %d %v", r.code, r.body)
		}
		time.Sleep(300 * time.Millisecond)
	}
	for _, s := range v2Secrets {
		must(t, call(t, addr, "POST", "kv/data/"+s, root, map[string]any{"data": map[string]string{"v": s}}), s)
	}
	for _, s := range v1Secrets {
		must(t, call(t, addr, "POST", "legacy/"+s, root, map[string]string{"v": s}), s)
	}
	must(t, call(t, addr, "POST", "sys/auth/userpass", root, map[string]any{"type": "userpass"}), "userpass")
	auths := must(t, call(t, addr, "GET", "sys/auth", root, nil), "sys/auth")
	up, _ := auths.body["data"].(map[string]any)["userpass/"].(map[string]any)
	acc, _ := up["accessor"].(string)
	if acc == "" {
		t.Fatalf("no userpass accessor in %v", auths.body)
	}
	policy := `
path "kv/data/team-a/*"     { capabilities = ["read", "list"] }
path "kv/metadata/team-a/*" { capabilities = ["read", "list"] }
path "kv/data/team-b/config" { capabilities = ["read"] }
path "kv/data/apps/+/token" { capabilities = ["read"] }
path "kv/data/shared/readme" { capabilities = ["read"] }
path "kv/data/shared/*"      { capabilities = ["deny"] }
path "kv/data/hidden/*"      { capabilities = ["deny"] }
path "legacy/ops/db"         { capabilities = ["read"] }
path "kv/data/{{identity.entity.aliases.` + acc + `.name}}/*" { capabilities = ["read"] }
path "kv/metadata/{{identity.entity.aliases.` + acc + `.name}}/*" { capabilities = ["read", "list"] }
`
	must(t, call(t, addr, "PUT", "sys/policies/acl/team", root, map[string]string{"policy": policy}), "policy")
	must(t, call(t, addr, "POST", "auth/userpass/users/alice", root, map[string]string{"password": "pw", "token_policies": "team"}), "user")
	lr := must(t, call(t, addr, "POST", "auth/userpass/login/alice", "", map[string]string{"password": "pw"}), "login")
	tok, _ := lr.body["auth"].(map[string]any)["client_token"].(string)
	if tok == "" {
		t.Fatalf("no token: %v", lr.body)
	}
	return tok
}

func TestE2E(t *testing.T) {
	addr := os.Getenv("VKR_E2E_ADDR")
	root := os.Getenv("VKR_E2E_TOKEN")
	if addr == "" || root == "" {
		t.Skip("VKR_E2E_ADDR and VKR_E2E_TOKEN not set")
	}
	alice := setup(t, addr, root)

	// Vault 2.x reports rules with "+" segments in resultant-acl; OpenBao
	// (checked: 2.7.2) and older Vault versions leave them out. Those rules
	// cannot be used then.
	acl0, err := (&reach.Client{Addr: addr, Token: alice}).ResultantACL(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plus := false
	for _, r := range acl0.Rules {
		if strings.Contains(r.Path, "+") {
			plus = true
		}
	}
	t.Logf("server reports '+' rules in resultant-acl: %v", plus)

	u, _ := url.Parse(addr)
	srv := httptest.NewServer(proxy.New(proxy.Config{Upstream: u}))
	defer srv.Close()

	t.Run("baseline: Vault refuses LIST without list capability", func(t *testing.T) {
		for _, p := range []string{"kv/metadata/", "kv/metadata/team-b/", "kv/metadata/shared/", "legacy/", "legacy/ops/"} {
			if r := call(t, addr, "LIST", p, alice, nil); r.code != 403 {
				t.Errorf("direct LIST %s: %d, want 403", p, r.code)
			}
		}
	})

	t.Run("proxy derives keys on 403", func(t *testing.T) {
		root := []string{"alice/", "apps/", "shared/", "team-a/", "team-b/"}
		if !plus {
			root = []string{"alice/", "shared/", "team-a/", "team-b/"}
		}
		cases := map[string][]string{
			"kv/metadata/":         root,
			"kv/metadata/team-b/":  {"config"},
			"kv/metadata/team-b":   {"config"},
			"kv/metadata/shared/":  {"readme"},
			"legacy/":              {"ops/"},
			"legacy/ops/":          {"db"},
			"kv/metadata/apps/":    nil, // only "+" below, stays 403
			"kv/metadata/hidden/":  nil,
			"kv/metadata/nothing/": nil,
		}
		for p, want := range cases {
			for _, variant := range []string{"LIST", "GET?list=true"} {
				var r result
				if variant == "LIST" {
					r = call(t, srv.URL, "LIST", p, alice, nil)
				} else {
					r = call(t, srv.URL, "GET", p+"?list=true", alice, nil)
				}
				if want == nil {
					if r.code != 403 {
						t.Errorf("%s %s: %d %v, want 403", variant, p, r.code, r.body)
					}
					continue
				}
				if r.code != 200 || !reflect.DeepEqual(keys(r), want) {
					t.Errorf("%s %s: %d %v, want 200 %v", variant, p, r.code, keys(r), want)
				}
			}
		}
	})

	t.Run("proxy passes allowed LIST and reads through", func(t *testing.T) {
		r := call(t, srv.URL, "LIST", "kv/metadata/team-a/", alice, nil)
		if r.code != 200 || !reflect.DeepEqual(keys(r), []string{"api", "db", "deep/"}) {
			t.Errorf("team-a: %d %v", r.code, keys(r))
		}
		r = call(t, srv.URL, "GET", "kv/data/team-b/config", alice, nil)
		d, _ := r.body["data"].(map[string]any)
		dd, _ := d["data"].(map[string]any)
		if r.code != 200 || dd["v"] != "team-b/config" {
			t.Errorf("read through proxy: %d %v", r.code, r.body)
		}
		if r := call(t, srv.URL, "GET", "kv/data/team-b/other", alice, nil); r.code != 403 {
			t.Errorf("read of denied secret through proxy: %d", r.code)
		}
		r = call(t, srv.URL, "LIST", "kv/metadata/", root, nil)
		want := []string{"alice/", "apps/", "bob/", "hidden/", "shared/", "team-a/", "team-b/", "top"}
		if r.code != 200 || !reflect.DeepEqual(keys(r), want) {
			t.Errorf("root LIST: %d %v", r.code, keys(r))
		}
		if r := call(t, srv.URL, "LIST", "kv/metadata/", "not-a-token", nil); r.code != 403 {
			t.Errorf("invalid token: %d, want 403", r.code)
		}
	})

	t.Run("tree matches sys/capabilities ground truth", func(t *testing.T) {
		ctx := context.Background()
		c := &reach.Client{Addr: addr, Token: alice}
		mounts, err := c.KVMounts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		acl, err := c.ResultantACL(ctx)
		if err != nil {
			t.Fatal(err)
		}
		es, err := reach.Walk(ctx, c, acl, mounts, "", reach.WalkOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		reach.PrintTree(&buf, mounts, es)
		t.Logf("tree for alice:\n%s", buf.String())

		found := map[string]bool{}
		var patterns []string
		for _, e := range es {
			if e.Error != "" {
				t.Errorf("entry error: %+v", e)
			}
			switch e.Kind {
			case "secret":
				if reach.Reachable(e.Capabilities) {
					found[e.Mount+e.Path] = true
				}
			case "pattern":
				patterns = append(patterns, e.Mount+e.Path)
			}
		}
		// Ground truth: capabilities of alice's token on every secret,
		// asked by the root token.
		all := map[string]string{}
		for _, s := range v2Secrets {
			all["kv/"+s] = "kv/data/" + s
		}
		for _, s := range v1Secrets {
			all["legacy/"+s] = "legacy/" + s
		}
		var paths []string
		for _, p := range all {
			paths = append(paths, p)
		}
		r := must(t, call(t, addr, "POST", "sys/capabilities", root, map[string]any{"token": alice, "paths": paths}), "capabilities")
		data, _ := r.body["data"].(map[string]any)
		for name, p := range all {
			var caps []string
			for _, x := range data[p].([]any) {
				caps = append(caps, x.(string))
			}
			readable := reach.Reachable(caps)
			underPattern := false
			for _, pat := range patterns {
				if strings.HasPrefix(name, pat[:strings.IndexAny(pat, "+*")]) {
					underPattern = true
				}
			}
			switch {
			case readable && !found[name] && !underPattern && !(!plus && strings.HasPrefix(name, "kv/apps/")):
				t.Errorf("%s readable (%v) but not in tree", name, caps)
			case !readable && found[name]:
				t.Errorf("%s in tree but capabilities are %v", name, caps)
			}
		}
		for _, want := range []string{"kv/alice/notes", "kv/team-a/deep/x", "kv/team-b/config", "kv/shared/readme", "legacy/ops/db"} {
			if !found[want] {
				t.Errorf("%s missing from tree", want)
			}
		}
		if found["kv/bob/notes"] || found["kv/team-b/other"] || found["kv/shared/private"] || found["kv/hidden/x"] {
			t.Errorf("tree contains secrets alice cannot read: %v", found)
		}
		if plus && !contains(patterns, "kv/apps/+/...") {
			t.Errorf("pattern for apps/+/token missing: %v", patterns)
		}
	})
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
