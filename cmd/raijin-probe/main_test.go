package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	engines "github.com/protonnegativo/raijin-probe"
)

func scopeFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte("*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNoBannerByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty without --banner, got %q", errb.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func TestBannerGoesToStderrOnly(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--banner", "--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "TGT-LOCK") || !strings.Contains(errb.String(), "raijin-probe v"+strings.TrimPrefix(version, "v")) {
		t.Errorf("banner missing or without the version: %q", errb.String())
	}
	if strings.Contains(out.String(), "TGT-LOCK") {
		t.Error("banner leaked into stdout")
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON with --banner: %v", err)
	}
}

func TestCompactByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Errorf("default JSON should be one line, got %d lines", n)
	}
	var pretty bytes.Buffer
	if code := run([]string{"--pretty", "--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &pretty, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(pretty.String(), "\n  \"tool\"") {
		t.Errorf("--pretty should indent: %q", pretty.String())
	}
	var a, b map[string]any
	if json.Unmarshal(out.Bytes(), &a) != nil || json.Unmarshal(pretty.Bytes(), &b) != nil || len(a) != len(b) {
		t.Error("compact and pretty should carry the same fields")
	}
}

func TestMissingEngineExitsTwoWithHint(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-u", "a.example.com", "--httpx", "/nonexistent/httpx"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	var v struct {
		Errors []struct{ Kind, Hint string }
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || len(v.Errors) != 1 || v.Errors[0].Kind != "missing_engine" || !strings.Contains(v.Errors[0].Hint, "--httpx") {
		t.Errorf("stdout = %s", out.String())
	}
}

func TestUsageErrorsExitOne(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 1 {
		t.Errorf("no --scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-u", "out.of-scope.net"}, &out, &errb); code != 1 {
		t.Errorf("no target in scope: exit %d, want 1", code)
	}
}

func TestRedirectArrowIsNotEscaped(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "http://d.example.com -> https://d.example.com/") || strings.Contains(out.String(), `\u003e`) {
		t.Errorf("redirects should read as ->: %s", out.String())
	}
	if !strings.Contains(out.String(), `"summary":"6 URLs, 2 findings (1 medium, 1 low), 3 groups, 1 no response"`) {
		t.Errorf("summary: %s", out.String())
	}
}

// With only --scope, every host the scope names is probed and wildcards get a next step.
func TestScopeAloneProbesWhatTheScopeNames(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopePath, []byte("example.com\n*.example.com\n10.0.0.0/30\n!10.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := filepath.Join(dir, "targets.txt")
	fake := filepath.Join(dir, "httpx")
	script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -l ] && cp \"$2\" " + got + "; shift; done\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopePath, "--httpx", fake, "--raw", filepath.Join(dir, "raw.jsonl")}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, errb.String(), out.String())
	}
	b, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(strings.Fields(string(b)), ",") != "example.com,10.0.0.0,10.0.0.2,10.0.0.3" {
		t.Errorf("httpx got targets %q", b)
	}
	var res struct{ Next []string }
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Next) != 1 || !strings.Contains(res.Next[0], "raijin-subs --scope "+scopePath+" -d example.com") {
		t.Errorf("next = %v", res.Next)
	}
}

func TestEngineFormat(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if strings.Contains(out.String(), "engine_format") {
		t.Errorf("sample output got an engine_format error: %s", out.String())
	}
	// testdata/renamed.jsonl is sample.jsonl with status_code renamed to status
	out.Reset()
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/renamed.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var v struct {
		Errors []struct{ Kind, Hint string }
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Errors) != 1 || v.Errors[0].Kind != "engine_format" || !strings.Contains(v.Errors[0].Hint, "renamed.jsonl") {
		t.Errorf("got errors %+v", v.Errors)
	}
}

func TestBuildVersion(t *testing.T) {
	rev := []debug.BuildSetting{{Key: "vcs.revision", Value: "0123456789abcdef0123"}}
	cases := []struct {
		name string
		bi   *debug.BuildInfo
		ok   bool
		want string
	}{
		{"installed release", &debug.BuildInfo{Main: debug.Module{Version: "v0.1.3"}}, true, "v0.1.3"},
		{"no build info", nil, false, "dev"},
		{"devel without vcs", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, "dev"},
		{"local build", &debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20261025000000-0123456789ab"}, Settings: rev}, true, "dev-0123456789ab"},
		{"local dirty build", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: append(rev, debug.BuildSetting{Key: "vcs.modified", Value: "true"})}, true, "dev-0123456789ab+dirty"},
	}
	for _, c := range cases {
		if got := buildVersion(c.bi, c.ok); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func testedHTTPX(t *testing.T) engines.Engine {
	t.Helper()
	tested, err := engines.Tested()
	if err != nil {
		t.Fatal(err)
	}
	return tested["httpx"]
}

func TestVersionLine(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--version"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	want := "raijin-probe " + version + " (tested with httpx " + testedHTTPX(t).Version + ")\n"
	if out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
}

// fakeHTTPX is an httpx that prints v for -version and nothing for a probe.
func fakeHTTPX(t *testing.T, v string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "httpx")
	script := "#!/bin/sh\n[ \"$1\" = -version ] && echo \"[INF] Current httpx version v" + v + " (latest)\" >&2\nexit 0\n"
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEngineVersion(t *testing.T) {
	e := testedHTTPX(t)
	want, ok := engines.Parse(e.Version)
	if !ok {
		t.Fatalf("tested version %q does not parse", e.Version)
	}
	for _, c := range []struct {
		installed string
		warn      bool
	}{
		{e.Version, false},
		{fmt.Sprintf("%d.0.0", want[0]+1), true},
	} {
		var out, errb bytes.Buffer
		if code := run([]string{"--scope", scopeFile(t), "-u", "a.example.com", "--httpx", fakeHTTPX(t, c.installed), "--raw", filepath.Join(t.TempDir(), "raw.jsonl")}, &out, &errb); code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
		var v struct {
			Errors []struct{ Kind, Hint string }
		}
		if err := json.Unmarshal(out.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		warned := false
		for _, x := range v.Errors {
			if x.Kind == "engine_version" {
				warned = true
				if !strings.HasSuffix(x.Hint, ", or run raijin-mcp update") {
					t.Errorf("hint %q does not point to the updater", x.Hint)
				}
			}
		}
		if warned != c.warn {
			t.Errorf("httpx %s: engine_version warning = %v, want %v (%+v)", c.installed, warned, c.warn, v.Errors)
		}
	}
}

func TestOutputStartsWithSchemaVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.HasPrefix(out.String(), `{"schema_version":1,"tool":"raijin-probe",`) {
		t.Errorf("output must start with schema_version: %.80s", out.String())
	}
}

func TestInvalidScopeIsStructuredAndRunsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.txt")
	body := "example.com\nexample.com:443\n10.0.0.7/24\n*.ok.example\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	// The engine path does not exist: if anything tried to run it, the result would hold missing_engine.
	code := run([]string{"--scope", path, "-u", "example.com", "--httpx", "/nonexistent/httpx"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d for an invalid scope, want 2: %s", code, out.String())
	}
	if !strings.HasPrefix(out.String(), `{"schema_version":1,`) {
		t.Fatalf("stdout does not start with the schema version: %.60s", out.String())
	}
	var v struct {
		SchemaVersion int `json:"schema_version"`
		Summary       string
		Errors        []struct{ Kind, Hint string }
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v: %s", err, out.String())
	}
	if v.SchemaVersion != 1 || len(v.Errors) != 2 {
		t.Fatalf("want schema_version 1 and one error per bad line (2), got %+v", v)
	}
	for i, want := range []string{"line 2: port in rule", "line 3: CIDR has host bits set"} {
		if e := v.Errors[i]; e.Kind != "scope" || !strings.Contains(e.Hint, want) {
			t.Errorf("error %d = %+v, want kind scope and %q", i, e, want)
		}
	}
	if !strings.Contains(v.Summary, "nothing probed") {
		t.Errorf("summary = %q", v.Summary)
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty, got %q", errb.String())
	}
}

func TestMissingScopeFileIsStructured(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", filepath.Join(t.TempDir(), "nope.txt"), "-u", "example.com"}, &out, &errb)
	var v struct{ Errors []struct{ Kind, Hint string } }
	if code == 0 || json.Unmarshal(out.Bytes(), &v) != nil || len(v.Errors) != 1 || v.Errors[0].Kind != "scope" {
		t.Errorf("exit %d, stdout %s", code, out.String())
	}
}

func TestStateMarksNewFindingsAcrossRuns(t *testing.T) {
	state := filepath.Join(t.TempDir(), "probe.state.json")
	newCount := func() string {
		var out, errb bytes.Buffer
		args := []string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl", "--state", state}
		if code := run(args, &out, &errb); code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
		var v struct {
			Summary string
			Errors  []struct{ Kind, Hint string }
		}
		if err := json.Unmarshal(out.Bytes(), &v); err != nil || len(v.Errors) != 0 {
			t.Fatalf("stdout = %s", out.String())
		}
		return v.Summary
	}
	if s := newCount(); !strings.Contains(s, " new") || strings.HasSuffix(s, ", 0 new") {
		t.Errorf("first run should report new findings: %q", s)
	}
	if s := newCount(); !strings.HasSuffix(s, ", 0 new") {
		t.Errorf("second run should report 0 new: %q", s)
	}
}

func TestReleaseVersionWinsOverBuildInfo(t *testing.T) {
	old := releaseVersion
	t.Cleanup(func() { releaseVersion = old })
	releaseVersion = "v9.9.9"
	if got := buildVersion(&debug.BuildInfo{Main: debug.Module{Version: "v0.1.3"}}, true); got != "v9.9.9" {
		t.Errorf("got %q, want v9.9.9", got)
	}
	if got := buildVersion(nil, false); got != "v9.9.9" {
		t.Errorf("got %q, want v9.9.9", got)
	}
}

func TestWildcardOnlyScopeIsStructuredExit2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(path, []byte("*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", path}, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, out.String())
	}
	if !strings.HasPrefix(out.String(), `{"schema_version":1,`) {
		t.Fatalf("stdout = %.60s", out.String())
	}
}

func TestUsageErrorsExit1WithoutJSON(t *testing.T) {
	for _, args := range [][]string{{"--input", "x"}, {"--nope"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 1 || out.Len() != 0 {
			t.Errorf("%v: exit %d, stdout %q; want 1 and empty", args, code, out.String())
		}
	}
}
