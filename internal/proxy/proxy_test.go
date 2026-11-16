package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/Jwrede/vault-kv-reach/internal/reach"
)

func TestFolderOf(t *testing.T) {
	ms := []reach.Mount{{Path: "kv/", Version: 2}, {Path: "legacy/", Version: 1}}
	cases := []struct {
		path, mount, folder string
		ok                  bool
	}{
		{"kv/metadata/", "kv/", "", true},
		{"kv/metadata", "kv/", "", true},
		{"kv/metadata/a/b", "kv/", "a/b/", true},
		{"kv/data/a/", "", "", false},
		{"legacy", "legacy/", "", true},
		{"legacy/ops", "legacy/", "ops/", true},
		{"sys/policies/acl", "", "", false},
	}
	for _, c := range cases {
		m, f, ok := folderOf(ms, c.path)
		if ok != c.ok || (ok && (m.Path != c.mount || f != c.folder)) {
			t.Errorf("%s: %v %q %v", c.path, m.Path, f, ok)
		}
	}
}

func TestIsListAndToken(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/kv/metadata/?list=true", nil)
	r.Header.Set("Authorization", "Bearer abc")
	if !IsList(r) || Token(r) != "abc" {
		t.Fatal("GET ?list=true with bearer token")
	}
	r = httptest.NewRequest("LIST", "/v1/kv/metadata/", nil)
	r.Header.Set("X-Vault-Token", "t")
	if !IsList(r) || Token(r) != "t" {
		t.Fatal("LIST")
	}
	if IsList(httptest.NewRequest("GET", "/v1/kv/data/x", nil)) {
		t.Fatal("plain GET")
	}
}
