// Package reduce turns raw httpx events into a small, ranked Raijin result.
//
// It is lossless for what an agent acts on: every probed URL is kept, with its status, title, length,
// server, tech, content type, redirect and IPs. URLs that returned the same response collapse into one
// entry that lists every URL. Only exact duplicates are dropped. A byte budget can cut, but every cut
// is counted in omitted.
package reduce

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/protonnegativo/raijin-probe/internal/httpx"
	"github.com/protonnegativo/raijin-probe/internal/schema"
)

// Options control what the reducer keeps.
type Options struct {
	MaxItems    int // 0 keeps every finding
	MaxBytes    int
	MaxLocation int // longest location string, redirect and IPs included
	// OutlierMin is the number of answering URLs a run needs before a response seen on only one of them
	// can be an outlier (see outlierClusters).
	OutlierMin int
	InScope    func(target string) bool
}

// Defaults keep every finding and cap the JSON at a size that fits comfortably in an agent's context.
func Defaults() Options {
	return Options{MaxBytes: 16000, MaxLocation: 300, OutlierMin: 10}
}

// The rules that make a response a finding. Each tag has a fixed severity; a finding takes the highest.
var tagSeverity = map[string]string{
	"panel":   "medium",
	"listing": "medium",
	"auth":    "low",
	"error":   "low",
	"outlier": "low",
}

var (
	// panelWords match a login or admin page in the title, the URL path or the redirect target.
	panelWords = regexp.MustCompile(`(?i)\b(log ?in|log ?on|sign ?in|sign-in|signin|admin\w*|dashboard|console|control panel|portal|manager|phpmyadmin|webmin|cpanel|plesk|wp-admin|wp-login)\b`)
	// listingTitle matches the title of a directory index.
	listingTitle = regexp.MustCompile(`(?i)^\s*(index of /|directory listing for )`)
	// panelTech are httpx tech names that are themselves an admin or ops panel.
	panelTech = map[string]bool{}
)

func init() {
	for _, t := range []string{
		"Jenkins", "Grafana", "Kibana", "GitLab", "Gitea", "phpMyAdmin", "Webmin", "Jira", "Confluence",
		"SonarQube", "Portainer", "RabbitMQ", "Argo CD", "Jupyter Notebook", "JupyterHub", "Kubernetes Dashboard",
		"Nexus Repository Manager", "Harbor", "Apache Airflow", "Rundeck", "Zabbix", "Nagios", "MinIO", "Traefik",
		"Keycloak", "Splunk", "Cockpit", "pgAdmin", "Adminer", "Prometheus", "Consul", "Nomad", "Vault",
	} {
		panelTech[strings.ToLower(t)] = true
	}
}

type cluster struct {
	key   string
	title string
	resp  schema.Response
	path  []string // URL paths and redirect targets, for the panel rule
	locs  map[string]bool
}

// Reduce collapses events into findings and groups: one entry per distinct response, listing every URL
// that returned it. It also returns every location per finding fingerprint, before any budget, for --state.
func Reduce(events []httpx.Event, opt Options) ([]schema.Finding, []schema.Group, map[string]int, map[string][]string) {
	omitted := map[string]int{}
	clusters := map[string]*cluster{}
	var keys []string

	for _, ev := range events {
		if opt.InScope != nil && !opt.InScope(ev.URL) {
			omitted["out_of_scope"]++
			continue
		}
		key := Signature(ev)
		c, ok := clusters[key]
		if !ok {
			c = &cluster{key: key, title: strings.TrimSpace(ev.Title), resp: response(ev), locs: map[string]bool{}}
			clusters[key] = c
			keys = append(keys, key)
		}
		loc := Location(ev, opt.MaxLocation)
		if c.locs[loc] {
			omitted["duplicates"]++
			continue
		}
		c.locs[loc] = true
		if u, err := url.Parse(ev.URL); err == nil {
			c.path = append(c.path, u.Path)
		}
		c.path = append(c.path, ev.Location, ev.FinalURL)
	}

	outliers := outlierClusters(clusters, keys, opt.OutlierMin)

	findings := []schema.Finding{}
	groups := []schema.Group{}
	allLocations := map[string][]string{}
	for _, key := range keys {
		c := clusters[key]
		locs := sorted(c.locs)
		id := ID(c.resp, key)
		tags := Tags(c.title, c.resp, c.path, outliers[key])
		if len(tags) == 0 {
			groups = append(groups, schema.Group{ID: id, Title: c.title, Response: c.resp, Locations: locs, Count: len(locs)})
			continue
		}
		f := schema.Finding{ID: id, Title: c.title, Tags: tags, Response: c.resp, Locations: locs, Count: len(locs), Fingerprint: fingerprint(id)}
		for _, t := range tags {
			if schema.SeverityRank[tagSeverity[t]] > schema.SeverityRank[f.Severity] {
				f.Severity = tagSeverity[t]
			}
		}
		if len(tags) == 1 && tags[0] == "outlier" {
			f.Confidence = "heuristic"
		}
		allLocations[f.Fingerprint] = locs
		findings = append(findings, f)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if schema.SeverityRank[a.Severity] != schema.SeverityRank[b.Severity] {
			return schema.SeverityRank[a.Severity] > schema.SeverityRank[b.Severity]
		}
		if schema.ConfidenceRank[a.Confidence] != schema.ConfidenceRank[b.Confidence] {
			return schema.ConfidenceRank[a.Confidence] > schema.ConfidenceRank[b.Confidence]
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.ID < b.ID
	})
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return groups[i].ID < groups[j].ID
	})

	if opt.MaxItems > 0 && len(findings) > opt.MaxItems {
		omitted["findings"] += len(findings) - opt.MaxItems
		findings = findings[:opt.MaxItems]
	}
	return findings, groups, omitted, allLocations
}

// Tags returns the rules a response matches, in a fixed order. No tags means it goes to a group.
//
//	panel    a login or admin page: the title, URL path or redirect target says so, or httpx detected panel tech
//	listing  a directory index
//	auth     401, 403 or 407
//	error    5xx
//	outlier  only one URL returned it, in a run where one response covers at least half the URLs
//
// A failed probe has no tags.
func Tags(title string, r schema.Response, paths []string, outlier bool) []string {
	if r.Error != "" && r.Status == 0 {
		return nil
	}
	var tags []string
	panel := panelWords.MatchString(title)
	for _, p := range paths {
		panel = panel || panelWords.MatchString(strings.NewReplacer("/", " ", "-", " ", "_", " ", ".", " ").Replace(p))
	}
	for _, t := range r.Tech {
		panel = panel || panelTech[strings.ToLower(techName(t))]
	}
	if panel {
		tags = append(tags, "panel")
	}
	if listingTitle.MatchString(title) {
		tags = append(tags, "listing")
	}
	switch {
	case r.Status == 401 || r.Status == 403 || r.Status == 407:
		tags = append(tags, "auth")
	case r.Status >= 500:
		tags = append(tags, "error")
	}
	if outlier {
		tags = append(tags, "outlier")
	}
	return tags
}

// outlierClusters marks the responses that stand out from a baseline. A run has a baseline when it has
// at least min answering URLs and one response accounts for at least half of them (50 default pages).
// Then every response returned by a single URL is an outlier: a different title, server, tech or size
// than the rest. A run with no baseline has no outliers, since there is nothing to stand out from.
func outlierClusters(clusters map[string]*cluster, keys []string, min int) map[string]bool {
	out := map[string]bool{}
	answering, largest := 0, 0
	for _, k := range keys {
		if n := len(clusters[k].locs); clusters[k].resp.Status != 0 {
			answering += n
			largest = max(largest, n)
		}
	}
	if min <= 0 || answering < min || 2*largest < answering {
		return out
	}
	for _, k := range keys {
		if c := clusters[k]; c.resp.Status != 0 && len(c.locs) == 1 {
			out[k] = true
		}
	}
	return out
}

func response(ev httpx.Event) schema.Response {
	r := schema.Response{
		Status: ev.StatusCode,
		Length: ev.ContentLength,
		Server: ev.Webserver,
		Type:   ev.ContentType,
	}
	switch {
	case r.Type == "text/html":
		r.Type = "" // the documented default, left out
	case r.Type == "" && ev.StatusCode != 0:
		r.Type = "none"
	}
	if len(ev.Tech) > 0 {
		r.Tech = append([]string(nil), ev.Tech...)
		sort.Strings(r.Tech)
	}
	if ev.CDN {
		r.CDN = ev.CDNName
		if r.CDN == "" {
			r.CDN = "yes"
		}
	}
	if ev.Failed || ev.StatusCode == 0 {
		r.Error = errorText(ev)
		if r.Error == "" {
			r.Error = "no response"
		}
	}
	return r
}

// errorText is httpx's error without the leading port it repeats from the URL ("19199 chain=..."),
// so URLs that failed the same way collapse into one group.
func errorText(ev httpx.Event) string {
	e := strings.TrimSpace(ev.Error)
	if u, err := url.Parse(ev.URL); err == nil {
		port := u.Port()
		if port == "" && u.Scheme == "https" {
			port = "443"
		} else if port == "" {
			port = "80"
		}
		e = strings.TrimPrefix(e, port+" ")
	}
	return e
}

// Signature is what makes two responses the same: status, title, length, words, lines, server, tech,
// content type, CDN, error and body hash. The URL, redirect target and IPs are per location.
func Signature(ev httpx.Event) string {
	r := response(ev)
	b, _ := schema.Marshal([]any{r.Status, strings.TrimSpace(ev.Title), r.Length, ev.Words, ev.Lines, r.Server, r.Tech, r.Type, r.CDN, r.Error, ev.BodyHash()})
	return string(b)
}

// ID is stable across runs while the response does not change: the status (or "failed") and a short
// hash of the signature.
func ID(r schema.Response, signature string) string {
	head := fmt.Sprint(r.Status)
	if r.Status == 0 {
		head = "failed"
	}
	return head + "-" + fingerprint(signature)[:8]
}

// Location is one probed URL: "[METHOD ]url[ -> redirect][ [ip, ...]]". The method is written when it
// is not GET, the redirect is the final URL when httpx followed it and the Location header otherwise,
// and the IPs are written when the URL host is a name.
func Location(ev httpx.Event, max int) string {
	s := ev.URL
	if m := strings.ToUpper(ev.Method); m != "" && m != "GET" {
		s = m + " " + s
	}
	switch {
	case ev.FinalURL != "" && ev.FinalURL != ev.URL:
		s += " -> " + ev.FinalURL
	case ev.Location != "":
		s += " -> " + ev.Location
	}
	if len(ev.A) > 0 {
		if u, err := url.Parse(ev.URL); err == nil && net.ParseIP(u.Hostname()) == nil {
			s += " [" + strings.Join(ev.A, ", ") + "]"
		}
	}
	return trim(s, max)
}

// Fit shrinks the result until its JSON is at most maxBytes. It cuts the least important data first:
// group locations, then groups, then the locations of the lowest-ranked findings (each keeps one, and
// its count), then the lowest-ranked findings. Every cut is counted in Omitted.
func Fit(res *schema.Result, maxBytes int) {
	if maxBytes <= 0 || size(res) <= maxBytes {
		return
	}
	res.Budget.Truncated = true
	if res.Omitted == nil {
		res.Omitted = map[string]int{}
	}
	total := size(res) // now includes the budget object
	for i := len(res.Groups) - 1; i >= 0 && total > maxBytes; i-- {
		g := &res.Groups[i]
		before := size(g)
		res.Omitted["locations"] += len(g.Locations)
		g.Locations = nil
		total += size(g) - before
	}
	for total > maxBytes && len(res.Groups) > 0 {
		last := len(res.Groups) - 1
		total -= size(res.Groups[last]) + 1
		res.Groups = res.Groups[:last]
		res.Omitted["groups"]++
	}
	for i := len(res.Findings) - 1; i >= 0 && total > maxBytes; i-- {
		f := &res.Findings[i]
		if len(f.Locations) <= 1 {
			continue
		}
		before := size(f)
		res.Omitted["locations"] += len(f.Locations) - 1
		f.Locations = f.Locations[:1]
		total += size(f) - before
	}
	for total > maxBytes && len(res.Findings) > 1 {
		last := len(res.Findings) - 1
		total -= size(res.Findings[last]) + 1
		res.Findings = res.Findings[:last]
		res.Omitted["findings"]++
	}
	// the estimate above ignores the omitted counters it adds; settle on the real size
	for size(res) > maxBytes && len(res.Findings) > 1 {
		res.Findings = res.Findings[:len(res.Findings)-1]
		res.Omitted["findings"]++
	}
}

// techName is the tech without its version: "Nginx:1.18.0" -> "Nginx".
func techName(t string) string {
	return strings.SplitN(t, ":", 2)[0]
}

func size(v any) int {
	b, _ := schema.Marshal(v)
	return len(b)
}

func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

func trim(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
