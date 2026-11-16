package reach

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Client talks to the Vault or OpenBao HTTP API with one token.
type Client struct {
	Addr      string // e.g. http://127.0.0.1:8200
	Token     string
	Namespace string
	HTTP      *http.Client
}

// StatusError is returned for non-2xx responses.
type StatusError struct {
	Code   int
	Errors []string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.Code, strings.Join(e.Errors, "; "))
}

// IsStatus reports whether err is a StatusError with the given code.
func IsStatus(err error, code int) bool {
	se, ok := err.(*StatusError)
	return ok && se.Code == code
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any) (json.RawMessage, error) {
	u := strings.TrimSuffix(c.Addr, "/") + "/v1/" + strings.TrimPrefix(path, "/")
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("X-Vault-Token", c.Token)
	}
	if c.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(b, &e)
		return nil, &StatusError{Code: resp.StatusCode, Errors: e.Errors}
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	return env.Data, nil
}

// ResultantACL fetches the token's effective policy rules.
func (c *Client) ResultantACL(ctx context.Context) (*ACL, error) {
	d, err := c.do(ctx, http.MethodGet, "sys/internal/ui/resultant-acl", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("resultant-acl: %w", err)
	}
	if d == nil {
		return &ACL{}, nil
	}
	return ParseResultantACL(d)
}

// Mount is a KV secrets engine the token can see.
type Mount struct {
	Path    string // with trailing "/"
	Type    string
	Version int // 1 or 2
}

// KVMounts lists the KV mounts visible to the token via sys/internal/ui/mounts,
// which only returns mounts the token has some access to.
func (c *Client) KVMounts(ctx context.Context) ([]Mount, error) {
	d, err := c.do(ctx, http.MethodGet, "sys/internal/ui/mounts", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("ui mounts: %w", err)
	}
	var m struct {
		Secret map[string]struct {
			Type    string            `json:"type"`
			Options map[string]string `json:"options"`
		} `json:"secret"`
	}
	if err := json.Unmarshal(d, &m); err != nil {
		return nil, err
	}
	var out []Mount
	for p, v := range m.Secret {
		ver := 0
		switch v.Type {
		case "kv", "generic":
			ver = 1
			if v.Options["version"] == "2" {
				ver = 2
			}
		case "kv-v2":
			ver = 2
		default:
			continue
		}
		if !strings.HasSuffix(p, "/") {
			p += "/"
		}
		out = append(out, Mount{Path: p, Type: v.Type, Version: ver})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// List runs a LIST on path. A 404 yields no keys and no error.
func (c *Client) List(ctx context.Context, path string) ([]string, error) {
	d, err := c.do(ctx, "LIST", path, nil, nil)
	if IsStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var l struct {
		Keys []string `json:"keys"`
	}
	if d != nil {
		if err := json.Unmarshal(d, &l); err != nil {
			return nil, err
		}
	}
	return l.Keys, nil
}

// CapabilitiesSelf returns the token's capabilities on each path.
func (c *Client) CapabilitiesSelf(ctx context.Context, paths []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(paths) == 0 {
		return out, nil
	}
	uniq := map[string]bool{}
	var ps []string
	for _, p := range paths {
		if !uniq[p] {
			uniq[p] = true
			ps = append(ps, p)
		}
	}
	for start := 0; start < len(ps); start += 100 {
		end := start + 100
		if end > len(ps) {
			end = len(ps)
		}
		d, err := c.do(ctx, http.MethodPost, "sys/capabilities-self", nil, map[string]any{"paths": ps[start:end]})
		if err != nil {
			return nil, fmt.Errorf("capabilities-self: %w", err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(d, &m); err != nil {
			return nil, err
		}
		for _, p := range ps[start:end] {
			var caps []string
			if raw, ok := m[p]; ok {
				_ = json.Unmarshal(raw, &caps)
			}
			out[p] = caps
		}
	}
	return out, nil
}

// Exists reports whether a KV v2 secret has metadata. It returns nil if the
// token cannot read the metadata.
func (c *Client) Exists(ctx context.Context, metadataPath string) *bool {
	_, err := c.do(ctx, http.MethodGet, metadataPath, nil, nil)
	var v bool
	switch {
	case err == nil:
		v = true
	case IsStatus(err, http.StatusNotFound):
		v = false
	default:
		return nil
	}
	return &v
}
