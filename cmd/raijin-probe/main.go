// Command raijin-probe runs httpx and returns a small, grouped, ranked result for AI agents.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"

	core "github.com/protonnegativo/raijin-core/schema"
	"github.com/protonnegativo/raijin-core/scope"
	"github.com/protonnegativo/raijin-core/state"
	engines "github.com/protonnegativo/raijin-probe"
	"github.com/protonnegativo/raijin-probe/internal/banner"
	"github.com/protonnegativo/raijin-probe/internal/httpx"
	"github.com/protonnegativo/raijin-probe/internal/reduce"
	"github.com/protonnegativo/raijin-probe/internal/schema"
)

// releaseVersion is set by the release build (-ldflags "-X main.releaseVersion=vX.Y.Z"). It has to be a
// plain string variable: the linker cannot set one that is initialized by a function call.
var releaseVersion string

// version is the release this binary was built as, installed from, or "dev-<revision>" for a local build.
var version = buildVersion(debug.ReadBuildInfo())

// buildVersion is releaseVersion when the release build set it, else the module version when the binary
// was installed with go install ...@vX.Y.Z or @latest. A local go build carries VCS settings instead (and
// since Go 1.24 a pseudo-version made from them), so it reports "dev", the first 12 characters of the
// revision, and "+dirty" for uncommitted changes.
func buildVersion(bi *debug.BuildInfo, ok bool) string {
	if releaseVersion != "" {
		return releaseVersion
	}
	if !ok || bi == nil {
		return "dev"
	}
	rev, dirty := "", false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	v := "dev"
	if rev != "" {
		v += "-" + rev[:min(12, len(rev))]
	}
	if dirty {
		v += "+dirty"
	}
	return v
}

// versionLine is what --version prints: the release and the engine versions it is tested with.
func versionLine() string {
	line := "raijin-probe " + version
	if tested, err := engines.Tested(); err == nil {
		if e, ok := tested["httpx"]; ok {
			line += " (tested with httpx " + e.Version + ")"
		}
	}
	return line
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raijin-probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var targets multi
	fs.Var(&targets, "u", "target URL or host (repeatable; default: every host the scope names)")
	list := fs.String("l", "", "file with one target per line")
	scopeFile := fs.String("scope", "", "scope file (required): domains, *.wildcards, IPs, CIDRs, !exclusions")
	rate := fs.Int("rate", 0, "requests per second (httpx -rl)")
	timeout := fs.Int("timeout", 0, "request timeout in seconds")
	threads := fs.Int("threads", 0, "concurrent probes (httpx -t)")
	follow := fs.Bool("follow", false, "follow redirects on the same host (httpx -fhr)")
	maxItems := fs.Int("max-items", 0, "maximum findings in the output (0 keeps all)")
	maxBytes := fs.Int("max-bytes", reduce.Defaults().MaxBytes, "maximum size of the JSON output; cuts are counted in omitted")
	rawPath := fs.String("raw", "", "file for httpx's full JSONL output (default: a new file in the temp dir)")
	statePath := fs.String("state", "", "state file; marks findings that are new since the last run")
	format := fs.String("format", "json", "output format: json or table")
	pretty := fs.Bool("pretty", false, "indent the JSON (compact by default, which costs fewer tokens)")
	input := fs.String("input", "", "read an existing httpx JSONL file instead of running httpx")
	bin := fs.String("httpx", "httpx", "path to the httpx binary (ProjectDiscovery httpx, not the Python httpx CLI)")
	showVersion := fs.Bool("version", false, "print the version")
	showBanner := fs.Bool("banner", false, "print the Raijin banner to stderr (off by default to keep output small)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-probe --scope scope.txt [-u target | -l targets.txt | --input results.jsonl] [flags] [-- extra httpx args]\n\nWith no targets it probes every host the scope names.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showBanner {
		banner.Write(stderr, "raijin-probe", strings.TrimPrefix(version, "v"), useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, versionLine())
		return 0
	}
	if *scopeFile == "" {
		fmt.Fprintln(stderr, "raijin-probe: --scope is required")
		return 1
	}
	sc, err := scope.Load(*scopeFile)
	if err != nil {
		// An invalid scope is an error the caller can fix: report every bad line and run nothing.
		res := schema.Result{
			Tool:     "raijin-probe",
			Version:  version,
			Target:   *scopeFile,
			Summary:  "invalid scope file, nothing probed",
			Findings: []schema.Finding{},
			Groups:   []schema.Group{},
			Errors:   scope.SchemaErrors(err),
			Budget:   schema.Budget{MaxItems: *maxItems, MaxBytes: *maxBytes},
		}
		write(stdout, &res, *format, *pretty)
		return 1
	}

	res := schema.Result{
		Tool:     "raijin-probe",
		Version:  version,
		Findings: []schema.Finding{},
		Groups:   []schema.Group{},
		Omitted:  map[string]int{},
		Errors:   []schema.Error{},
		Next:     []string{},
		Budget:   schema.Budget{MaxItems: *maxItems, MaxBytes: *maxBytes},
	}

	var events []httpx.Event
	unparsed := 0
	if *input != "" {
		f, err := os.Open(*input)
		if err != nil {
			fmt.Fprintln(stderr, "raijin-probe:", err)
			return 1
		}
		events, unparsed, err = httpx.Parse(f)
		f.Close()
		if err != nil {
			fmt.Fprintln(stderr, "raijin-probe:", err)
			return 1
		}
		res.Target = *input
	} else {
		if *list != "" {
			lines, err := readLines(*list)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-probe:", err)
				return 1
			}
			targets = append(targets, lines...)
		}
		var inScope []string
		if len(targets) == 0 {
			// no targets given: probe what the scope names
			var wildcards, ranges []string
			inScope, wildcards, ranges = sc.Targets()
			for _, w := range wildcards {
				res.Next = append(res.Next, "raijin-subs --scope "+*scopeFile+" -d "+strings.TrimPrefix(w, "*.")+", then raijin-probe -l <subdomains> to cover "+w)
			}
			for _, r := range ranges {
				res.Next = append(res.Next, "raijin-ports --scope "+*scopeFile+" -host "+r+", then raijin-probe -l <open ports> to cover "+r)
			}
		} else {
			inScope = filter(targets, sc, res.Omitted)
		}
		if len(inScope) == 0 {
			if len(res.Next) > 0 {
				res.Summary = "the scope names no single host to scan"
				res.Target = *scopeFile
				write(stdout, &res, *format, *pretty)
				return 1
			}
			fmt.Fprintln(stderr, "raijin-probe: no targets in scope")
			return 1
		}
		res.Target = targetSummary(inScope, res.Omitted["out_of_scope"])

		if *rawPath == "" {
			f, err := os.CreateTemp("", "raijin-probe-*.jsonl")
			if err != nil {
				fmt.Fprintln(stderr, "raijin-probe:", err)
				return 1
			}
			f.Close()
			*rawPath = f.Name()
		}
		res.Raw = *rawPath

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if e := versionError(ctx, *bin); e != nil {
			res.Errors = append(res.Errors, *e)
		}
		var stderrTail string
		events, unparsed, stderrTail, err = httpx.Run(ctx, inScope, httpx.Options{
			Binary: *bin, Rate: *rate, Timeout: *timeout, Threads: *threads, Follow: *follow,
			Extra: fs.Args(), RawPath: *rawPath,
		})
		switch {
		case errors.Is(err, httpx.ErrNotFound):
			res.Errors = append(res.Errors, schema.Error{Kind: "missing_engine", Hint: "install httpx (go install github.com/projectdiscovery/httpx/cmd/httpx@latest) or pass --httpx <path>, or run raijin-mcp update"})
			res.Summary = "httpx not found, nothing probed"
			res.Raw = ""
			write(stdout, &res, *format, *pretty)
			return 2
		case err != nil:
			hint := err.Error()
			if stderrTail != "" {
				hint += ": " + stderrTail
			}
			if strings.Contains(stderrTail, "No such option") || strings.Contains(stderrTail, "Usage: httpx") {
				hint += " (this looks like the Python httpx CLI; pass --httpx with the path to ProjectDiscovery httpx)"
			}
			res.Errors = append(res.Errors, schema.Error{Kind: "engine_error", Hint: hint})
		}
	}

	if hint := httpx.FormatHint(events, unparsed, res.Raw+*input); hint != "" {
		res.Errors = append(res.Errors, schema.Error{Kind: "engine_format", Hint: hint})
	}
	if unparsed > 0 {
		res.Omitted["unparsed"] += unparsed
	}

	opt := reduce.Defaults()
	opt.MaxItems = *maxItems
	opt.MaxBytes = *maxBytes
	opt.InScope = sc.Allowed
	findings, groups, omitted, allLocations := reduce.Reduce(events, opt)
	res.Findings, res.Groups = findings, groups
	for k, v := range omitted {
		res.Omitted[k] += v
	}

	newCount := -1
	if *statePath != "" {
		st, err := state.Load(*statePath)
		if err != nil {
			res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
		} else {
			newCount = state.Mark(st, res.Findings, allLocations,
				func(f *schema.Finding) string { return f.Fingerprint },
				func(f *schema.Finding) { f.New = true })
			if err := st.Save(*statePath); err != nil {
				res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
			}
		}
	}

	res.Summary = summary(res, len(events)-omitted["out_of_scope"]-omitted["duplicates"], newCount)
	if res.Omitted["findings"] > 0 {
		res.Budget.Truncated = true
	}
	reduce.Fit(&res, *maxBytes)
	if res.Budget.Truncated {
		hint := "raise --max-bytes"
		if src := res.Raw + *input; src != "" {
			hint += " or read " + src + " for what was cut"
		}
		res.Next = append(res.Next, hint)
		reduce.Fit(&res, *maxBytes) // the hint takes room too
	}
	write(stdout, &res, *format, *pretty)
	return 0
}

// versionError warns when the installed httpx is not the version raijin-probe was tested with: another
// major version, or an older one. Newer versions of the same major, and output it cannot read, are silent.
func versionError(ctx context.Context, bin string) *schema.Error {
	tested, err := engines.Tested()
	if err != nil {
		return nil
	}
	e, ok := tested["httpx"]
	if !ok {
		return nil
	}
	want, ok := engines.Parse(e.Version)
	if !ok {
		return nil
	}
	out := httpx.Version(ctx, bin)
	got, ok := engines.Parse(out)
	if !ok || !engines.Untested(got, want) {
		return nil
	}
	installed := fmt.Sprintf("%d.%d.%d", got[0], got[1], got[2])
	return &schema.Error{Kind: "engine_version", Hint: "httpx " + installed + " is not the tested " + e.Version +
		"; results may be incomplete. Install the tested version: " + e.Install(e.Version) +
		", or run raijin-mcp update"}
}

// useColor is true when w is a terminal and NO_COLOR is not set.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func filter(targets []string, sc *scope.Scope, omitted map[string]int) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		if !sc.Allowed(t) {
			omitted["out_of_scope"]++
			continue
		}
		out = append(out, t)
	}
	return out
}

func targetSummary(targets []string, skipped int) string {
	s := fmt.Sprintf("%d target(s)", len(targets))
	if len(targets) == 1 {
		s = targets[0]
	}
	if skipped > 0 {
		s += fmt.Sprintf(" (%d out of scope skipped)", skipped)
	}
	return s
}

// summary is written before the budget, so it stays true when Fit cuts.
func summary(res schema.Result, urls, newCount int) string {
	failed := 0
	bySev := map[string]int{}
	for _, f := range res.Findings {
		bySev[f.Severity]++
	}
	for _, g := range res.Groups {
		if g.Status == 0 {
			failed += len(g.Locations)
		}
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	s := fmt.Sprintf("%d URLs, %d findings", urls, len(res.Findings))
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	s += fmt.Sprintf(", %d groups", len(res.Groups))
	if failed > 0 {
		s += fmt.Sprintf(", %d no response", failed)
	}
	if newCount >= 0 {
		s += fmt.Sprintf(", %d new", newCount)
	}
	return s
}

func write(w io.Writer, res *schema.Result, format string, pretty bool) {
	if format == "table" {
		fmt.Fprintln(w, res.Summary)
		for _, f := range res.Findings {
			mark := ""
			if f.New {
				mark = " [new]"
			}
			fmt.Fprintf(w, "%-8s %s %s (%d)%s\n", strings.ToUpper(f.Severity), strings.Join(f.Tags, ","), describe(f.Title, f.Response), max(f.Count, len(f.Locations)), mark)
			for _, l := range f.Locations {
				fmt.Fprintf(w, "         %s\n", l)
			}
		}
		for _, g := range res.Groups {
			fmt.Fprintf(w, "group    %s (%d)\n", describe(g.Title, g.Response), max(g.Count, len(g.Locations)))
		}
		for _, e := range res.Errors {
			fmt.Fprintf(w, "error    %s: %s\n", e.Kind, e.Hint)
		}
		return
	}
	_ = core.Write(w, res, pretty)
}

// describe is a one-line view of a response for the table: status, title, server.
func describe(title string, r schema.Response) string {
	if r.Status == 0 {
		return "failed: " + r.Error
	}
	s := fmt.Sprint(r.Status)
	if title != "" {
		s += " " + fmt.Sprintf("%q", title)
	}
	if r.Server != "" {
		s += " " + r.Server
	}
	return s
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}
