package reduce

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-probe/internal/httpx"
	"github.com/protonnegativo/raijin-probe/internal/schema"
	"github.com/protonnegativo/raijin-probe/internal/scope"
)

func load(t *testing.T) []httpx.Event {
	t.Helper()
	f, err := os.Open("../../testdata/sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := httpx.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// ev is an answering URL; the body hash defaults to one derived from the title.
func ev(url string, status int, title string) httpx.Event {
	return httpx.Event{URL: url, Method: "GET", StatusCode: status, Title: title, ContentLength: 100, Webserver: "nginx", Tech: []string{"Nginx"}, ContentType: "text/html", Hash: map[string]any{"body_mmh3": title}}
}

func TestReduce(t *testing.T) {
	events := load(t)
	if len(events) != 8 {
		t.Fatalf("parsed %d events, want 8 (the log line is skipped)", len(events))
	}
	sc, _ := scope.Parse([]string{"*.example.com"})
	opt := Defaults()
	opt.InScope = sc.Allowed

	findings, groups, omitted, all := Reduce(events, opt)

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
	login, forbidden := findings[0], findings[1]
	if login.Title != "Admin Login" || login.Severity != "medium" || strings.Join(login.Tags, ",") != "panel" {
		t.Errorf("first finding = %+v", login)
	}
	if forbidden.Status != 403 || forbidden.Severity != "low" || strings.Join(forbidden.Tags, ",") != "auth" {
		t.Errorf("second finding = %+v", forbidden)
	}
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3: %+v", len(groups), groups)
	}
	nginx := groups[0]
	if nginx.Title != "Welcome to nginx!" || strings.Join(nginx.Locations, ",") != "https://a.example.com [192.0.2.10],https://b.example.com [192.0.2.11]" {
		t.Errorf("identical default pages should be one group listing every URL: %+v", nginx)
	}
	if strings.Join(nginx.Tech, ",") != "Nginx:1.18.0,Ubuntu" {
		t.Errorf("tech is sorted, so the same tech in another order is the same response: %v", nginx.Tech)
	}
	byID := map[string]schema.Group{}
	for _, g := range groups {
		byID[strings.SplitN(g.ID, "-", 2)[0]] = g
	}
	if g := byID["301"]; len(g.Locations) != 1 || g.Locations[0] != "http://d.example.com -> https://d.example.com/ [192.0.2.14]" {
		t.Errorf("the redirect target stays with its URL: %+v", g)
	}
	if g := byID["failed"]; g.Status != 0 || g.Error != `chain="connection refused"` || g.Locations[0] != "https://e.example.com" {
		t.Errorf("a failed probe is a group with its error, without the port httpx repeats: %+v", g)
	}
	if omitted["duplicates"] != 1 || omitted["out_of_scope"] != 1 {
		t.Errorf("omitted = %v", omitted)
	}
	if len(all[login.Fingerprint]) != 1 {
		t.Errorf("state locations for the login finding = %v", all[login.Fingerprint])
	}
}

// Every URL is in exactly one entry: identical responses collapse, but no URL is dropped.
func TestEveryURLIsListedOnce(t *testing.T) {
	var events []httpx.Event
	for i := 0; i < 50; i++ {
		events = append(events, ev(fmt.Sprintf("http://h%02d.example.com", i), 200, "Welcome to nginx!"))
	}
	events = append(events, ev("http://x.example.com", 200, "Internal wiki"))
	findings, groups, omitted, _ := Reduce(events, Defaults())
	seen := map[string]int{}
	for _, f := range findings {
		for _, l := range f.Locations {
			seen[l]++
		}
	}
	for _, g := range groups {
		for _, l := range g.Locations {
			seen[l]++
		}
	}
	if len(seen) != 51 {
		t.Errorf("listed %d URLs, want 51", len(seen))
	}
	for l, n := range seen {
		if n != 1 {
			t.Errorf("%s listed %d times", l, n)
		}
	}
	if len(groups) != 1 || len(groups[0].Locations) != 50 {
		t.Errorf("50 identical pages should be one group: %+v", groups)
	}
	if len(omitted) != 0 {
		t.Errorf("nothing should be omitted: %v", omitted)
	}
}

// The same URL with a different response is two results, not a duplicate.
func TestSameURLDifferentResponseIsKept(t *testing.T) {
	a := ev("http://a.example.com", 200, "Home")
	b := ev("http://a.example.com", 503, "Maintenance")
	findings, groups, omitted, _ := Reduce([]httpx.Event{a, b, a}, Defaults())
	if len(findings) != 1 || len(groups) != 1 {
		t.Fatalf("findings = %+v, groups = %+v", findings, groups)
	}
	if omitted["duplicates"] != 1 {
		t.Errorf("only the exact repeat is a duplicate: %v", omitted)
	}
}

// Two pages with the same visible fields but a different body are different responses.
func TestDifferentBodyHashIsNotMerged(t *testing.T) {
	a := ev("http://a.example.com", 200, "Home")
	b := ev("http://b.example.com", 200, "Home")
	b.Hash = map[string]any{"body_mmh3": "other"}
	_, groups, _, _ := Reduce([]httpx.Event{a, b}, Defaults())
	if len(groups) != 2 {
		t.Errorf("different bodies must not collapse: %+v", groups)
	}
}

// URLs that return the same response but redirect to different places stay in one entry, each URL
// with its own target.
func TestRedirectTargetIsPerURL(t *testing.T) {
	a := ev("http://a.example.com", 301, "Moved")
	a.Location = "https://a.example.com/"
	b := ev("http://b.example.com", 301, "Moved")
	b.Location = "https://b.example.com/"
	b.FinalURL = "https://b.example.com/home"
	_, groups, _, _ := Reduce([]httpx.Event{a, b}, Defaults())
	if len(groups) != 1 || strings.Join(groups[0].Locations, ",") != "http://a.example.com -> https://a.example.com/,http://b.example.com -> https://b.example.com/home" {
		t.Errorf("groups = %+v", groups)
	}
}

func TestLocationFormat(t *testing.T) {
	e := httpx.Event{URL: "http://10.0.0.1:8080/x", Method: "POST", A: []string{"10.0.0.1"}}
	if got := Location(e, 300); got != "POST http://10.0.0.1:8080/x" {
		t.Errorf("an IP URL does not repeat its IP; a non-GET method is written: %q", got)
	}
	long := httpx.Event{URL: "http://x/" + strings.Repeat("a", 500)}
	if got := Location(long, 300); len(got) != 300 || !strings.HasSuffix(got, "...") {
		t.Errorf("len = %d", len(got))
	}
}

func TestTags(t *testing.T) {
	tests := []struct {
		title string
		r     schema.Response
		paths []string
		want  string
	}{
		{"Admin Login", schema.Response{Status: 200}, nil, "panel"},
		{"Sign in to GitLab", schema.Response{Status: 200}, nil, "panel"},
		{"", schema.Response{Status: 302}, []string{"/", "/admin/login"}, "panel"},
		{"Dashboard [Jenkins]", schema.Response{Status: 200, Tech: []string{"Jenkins:2.401.3"}}, nil, "panel"},
		{"Home", schema.Response{Status: 200, Tech: []string{"Grafana:10.1"}}, nil, "panel"},
		{"Index of /backup", schema.Response{Status: 200}, nil, "listing"},
		{"403 Forbidden", schema.Response{Status: 403}, nil, "auth"},
		{"", schema.Response{Status: 401}, nil, "auth"},
		{"Internal Server Error", schema.Response{Status: 502}, nil, "error"},
		{"Welcome to nginx!", schema.Response{Status: 200}, []string{"/"}, ""},
		{"404 Not Found", schema.Response{Status: 404}, nil, ""},
		{"Logistics", schema.Response{Status: 200}, []string{"/catalog"}, ""},
		{"", schema.Response{Error: "connection refused"}, []string{"/admin"}, ""},
	}
	for _, tt := range tests {
		if got := strings.Join(Tags(tt.title, tt.r, tt.paths, false), ","); got != tt.want {
			t.Errorf("Tags(%q, %d, %v) = %q, want %q", tt.title, tt.r.Status, tt.paths, got, tt.want)
		}
	}
}

// With a baseline (one response on at least half of 10+ URLs), a response seen once is an outlier.
// Without a baseline nothing is.
func TestOutliers(t *testing.T) {
	var events []httpx.Event
	for i := 0; i < 9; i++ {
		events = append(events, ev(fmt.Sprintf("http://h%d.example.com", i), 200, "Welcome to nginx!"))
	}
	odd := ev("http://odd.example.com", 200, "Internal wiki")
	odd.Webserver = "Jetty(10.0.13)"
	events = append(events, odd)
	findings, groups, _, _ := Reduce(events, Defaults())
	if len(findings) != 1 || findings[0].Title != "Internal wiki" || findings[0].Confidence != "heuristic" || findings[0].Severity != "low" {
		t.Errorf("the odd host should be a heuristic outlier: %+v", findings)
	}
	if len(groups) != 1 {
		t.Errorf("groups = %+v", groups)
	}

	var diverse []httpx.Event
	for i := 0; i < 12; i++ {
		diverse = append(diverse, ev(fmt.Sprintf("http://h%d.example.com", i), 200, fmt.Sprintf("site %d", i)))
	}
	if findings, _, _, _ := Reduce(diverse, Defaults()); len(findings) != 0 {
		t.Errorf("no baseline, no outliers: %+v", findings)
	}
}

func TestRanking(t *testing.T) {
	events := []httpx.Event{
		ev("http://a.example.com", 403, "Forbidden"),
		ev("http://b.example.com", 403, "Forbidden"),
		ev("http://c.example.com", 500, "Oops"),
		ev("http://d.example.com", 200, "Admin Login"),
	}
	findings, _, _, _ := Reduce(events, Defaults())
	var order []string
	for _, f := range findings {
		order = append(order, f.Title)
	}
	// severity first, then the number of URLs
	if strings.Join(order, ",") != "Admin Login,Forbidden,Oops" {
		t.Errorf("order = %v", order)
	}
	opt := Defaults()
	opt.MaxItems = 1
	findings, _, omitted, _ := Reduce(events, opt)
	if len(findings) != 1 || omitted["findings"] != 2 {
		t.Errorf("max items: %+v %v", findings, omitted)
	}
}

func TestIDIsStable(t *testing.T) {
	a := ev("http://a.example.com", 403, "Forbidden")
	b := ev("http://b.example.com", 403, "Forbidden")
	f1, _, _, _ := Reduce([]httpx.Event{a}, Defaults())
	f2, _, _, _ := Reduce([]httpx.Event{b, a}, Defaults())
	if f1[0].ID != f2[0].ID || !strings.HasPrefix(f1[0].ID, "403-") {
		t.Errorf("the same response has the same id: %s vs %s", f1[0].ID, f2[0].ID)
	}
}

func TestParseKeepsOddValues(t *testing.T) {
	lines := `{"url":"http://a","status_code":200,"hash":{"body_mmh3":12345}}
{"input":"http://b","failed":true,"error":"timeout"}
{"timestamp":"x"}
not json`
	events, err := httpx.Parse(strings.NewReader(lines))
	if err != nil || len(events) != 2 {
		t.Fatalf("parsed %d events (%v), want 2", len(events), err)
	}
	if events[0].BodyHash() != "body_mmh3:12345" || events[1].URL != "http://b" {
		t.Errorf("events = %+v", events)
	}
}

func TestFitCutsLeastImportantFirstAndCountsEverything(t *testing.T) {
	res := &schema.Result{Omitted: map[string]int{}, Budget: schema.Budget{MaxBytes: 3000}}
	var locs []string
	for i := 0; i < 20; i++ {
		locs = append(locs, fmt.Sprintf("https://host%02d.example.com", i))
	}
	for i := 0; i < 5; i++ {
		res.Findings = append(res.Findings, schema.Finding{ID: fmt.Sprintf("403-%d", i), Severity: "low", Tags: []string{"auth"}, Locations: locs, Count: len(locs)})
	}
	res.Groups = []schema.Group{{ID: "200-x", Locations: locs, Count: len(locs)}}

	Fit(res, 3000)
	b, _ := schema.Marshal(res)
	if len(b) > 3000 {
		t.Errorf("size %d > 3000", len(b))
	}
	if !res.Budget.Truncated {
		t.Error("truncation not reported")
	}
	if len(res.Groups) == 1 && res.Groups[0].Locations != nil {
		t.Error("group locations should go before any finding data")
	}
	if len(res.Findings) == 0 || len(res.Findings[0].Locations) != 20 {
		t.Errorf("the top finding should keep its locations while lower data can be cut: %+v", res.Findings)
	}
	if !strings.Contains(string(b), `"count":20`) {
		t.Errorf("a finding or group that lost locations must show its count: %s", b)
	}
	shown := 0
	for _, f := range res.Findings {
		shown += len(f.Locations)
	}
	for _, g := range res.Groups {
		shown += len(g.Locations)
	}
	cutFindings := 5 - len(res.Findings)
	cutGroups := 1 - len(res.Groups)
	if res.Omitted["findings"] != cutFindings || res.Omitted["groups"] != cutGroups {
		t.Errorf("omitted = %v, cut %d findings and %d groups", res.Omitted, cutFindings, cutGroups)
	}
	if res.Omitted["locations"]+shown < 20*len(res.Findings)+20*len(res.Groups) {
		t.Errorf("locations not accounted for: omitted=%v shown=%d", res.Omitted, shown)
	}
}
