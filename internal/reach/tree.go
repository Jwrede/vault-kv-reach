package reach

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Entry is one line of the tree.
type Entry struct {
	Mount string `json:"mount"`
	// Path is relative to the mount, folders end in "/".
	Path string `json:"path"`
	// Kind is "secret", "folder" or "pattern".
	Kind string `json:"kind"`
	// Source is "list" if the parent folder could be listed, "acl" if the
	// name comes from a policy rule.
	Source string `json:"source"`
	// Capabilities on the data path (KV v2) or the secret path (KV v1).
	Capabilities []string `json:"capabilities,omitempty"`
	// MetadataCapabilities on the metadata path (KV v2 only).
	MetadataCapabilities []string `json:"metadata_capabilities,omitempty"`
	// Exists is set for derived KV v2 secrets whose metadata is readable.
	Exists *bool    `json:"exists,omitempty"`
	Rules  []string `json:"rules,omitempty"`
	Error  string   `json:"error,omitempty"`
	folder string
}

// WalkOptions limits a walk.
type WalkOptions struct {
	MaxDepth   int // 0 = unlimited
	MaxEntries int // 0 = unlimited
}

// Walk returns every secret, folder and pattern the token can reach in the
// given mounts, starting at prefix (mount-relative, may be empty).
func Walk(ctx context.Context, c *Client, acl *ACL, mounts []Mount, prefix string, opt WalkOptions) ([]Entry, error) {
	var out []Entry
	for _, m := range mounts {
		start := ""
		if prefix != "" {
			if !strings.HasPrefix(prefix, m.Path) {
				continue
			}
			start = strings.TrimPrefix(prefix, m.Path)
			if start != "" && !strings.HasSuffix(start, "/") {
				start += "/"
			}
		}
		es, err := walkMount(ctx, c, acl, m, start, opt, len(out))
		if err != nil {
			return out, err
		}
		out = append(out, es...)
	}
	return out, nil
}

func walkMount(ctx context.Context, c *Client, acl *ACL, m Mount, start string, opt WalkOptions, count int) ([]Entry, error) {
	var out []Entry
	var secrets []int
	var walk func(folder string, depth int) error
	walk = func(folder string, depth int) error {
		if opt.MaxEntries > 0 && count+len(out) >= opt.MaxEntries {
			return nil
		}
		l, err := Folder(ctx, c, acl, m, folder)
		if err != nil {
			out = append(out, Entry{Mount: m.Path, Path: folder, Kind: "folder", Error: err.Error()})
			return nil
		}
		for _, k := range l.Keys {
			if opt.MaxEntries > 0 && count+len(out) >= opt.MaxEntries {
				return nil
			}
			e := Entry{Mount: m.Path, Path: folder + k, Source: l.Source, Rules: l.Rules[k]}
			if strings.HasSuffix(k, "/") {
				e.Kind = "folder"
				out = append(out, e)
				if opt.MaxDepth == 0 || depth+1 < opt.MaxDepth {
					if err := walk(folder+k, depth+1); err != nil {
						return err
					}
				}
				continue
			}
			e.Kind = "secret"
			out = append(out, e)
			secrets = append(secrets, len(out)-1)
		}
		for _, p := range l.Patterns {
			out = append(out, Entry{Mount: m.Path, Path: folder + p.Name, Kind: "pattern", Source: "acl", Capabilities: p.Caps, Rules: []string{p.Rule}, folder: folder})
		}
		return nil
	}
	if err := walk(start, 0); err != nil {
		return out, err
	}
	// Capabilities for all secrets in one batch.
	var paths []string
	for _, i := range secrets {
		paths = append(paths, secretPaths(m, out[i].Path)...)
	}
	caps, err := c.CapabilitiesSelf(ctx, paths)
	if err != nil {
		return out, err
	}
	for _, i := range secrets {
		sp := secretPaths(m, out[i].Path)
		out[i].Capabilities = caps[sp[0]]
		if m.Version == 2 {
			out[i].MetadataCapabilities = caps[sp[1]]
			if out[i].Source == "acl" && contains(out[i].MetadataCapabilities, "read") {
				out[i].Exists = c.Exists(ctx, sp[1])
			}
		}
	}
	return out, nil
}

func secretPaths(m Mount, rel string) []string {
	if m.Version == 2 {
		return []string{m.Path + "data/" + rel, m.Path + "metadata/" + rel}
	}
	return []string{m.Path + rel}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// PrintTree writes entries as an indented tree.
func PrintTree(w io.Writer, mounts []Mount, es []Entry) {
	byMount := map[string][]Entry{}
	for _, e := range es {
		byMount[e.Mount] = append(byMount[e.Mount], e)
	}
	for _, m := range mounts {
		list, ok := byMount[m.Path]
		if !ok {
			continue
		}
		fmt.Fprintf(w, "%s (kv v%d)\n", m.Path, m.Version)
		sort.SliceStable(list, func(i, j int) bool { return list[i].Path < list[j].Path })
		for _, e := range list {
			p := strings.TrimSuffix(e.Path, "/")
			depth := strings.Count(p, "/")
			name := p[strings.LastIndex(p, "/")+1:]
			if e.Kind == "folder" {
				name += "/"
			}
			if e.Kind == "pattern" {
				depth = 0
				if e.folder != "" {
					depth = strings.Count(strings.TrimSuffix(e.folder, "/"), "/") + 1
				}
				name = strings.TrimPrefix(e.Path, e.folder)
			}
			var info []string
			switch e.Kind {
			case "secret":
				info = append(info, strings.Join(e.Capabilities, ","))
			case "pattern":
				info = append(info, "pattern, not listable", strings.Join(e.Capabilities, ","))
			}
			if e.Source == "acl" && e.Kind != "pattern" {
				info = append(info, "from policy")
			}
			if e.Exists != nil && !*e.Exists {
				info = append(info, "does not exist")
			}
			if e.Error != "" {
				info = append(info, "error: "+e.Error)
			}
			line := strings.Repeat("  ", depth+1) + name
			if len(info) > 0 && strings.Join(info, "") != "" {
				line += "  [" + strings.Join(nonEmpty(info), "; ") + "]"
			}
			fmt.Fprintln(w, line)
		}
	}
}

func nonEmpty(xs []string) []string {
	var out []string
	for _, x := range xs {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}
