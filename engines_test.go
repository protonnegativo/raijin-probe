package engines

import "testing"

func TestTested(t *testing.T) {
	m, err := Tested()
	if err != nil {
		t.Fatal(err)
	}
	// every engine raijin-probe runs has an entry
	for _, name := range []string{"httpx"} {
		e, ok := m[name]
		if !ok || e.Go == "" {
			t.Fatalf("no entry for %s: %+v", name, m)
		}
		if _, ok := Parse(e.Version); !ok {
			t.Errorf("%s version %q does not parse", name, e.Version)
		}
	}
}

func TestParse(t *testing.T) {
	// httpx -version -duc writes its banner, then the version line, to stderr
	banner := "\n    __    __  __       _  __\n   / /_  / /_/ /_____ | |/ /\n  / __ \\/ __/ __/ __ \\|   /\n" +
		" / / / / /_/ /_/ /_/ /   |\n/_/ /_/\\__/\\__/ .___/_/|_|\n             /_/\n\n\t\tprojectdiscovery.io\n\n"
	for out, want := range map[string][3]int{
		banner + "[\x1b[34mINF\x1b[0m] Current Version: v1.6.10\n": {1, 6, 10},
		"[INF] Current Version: v1.7.0\n":                          {1, 7, 0},
		"[INF] Current Version: v2.0.0-dev\n":                      {2, 0, 0},
	} {
		got, ok := Parse(out)
		if !ok || got != want {
			t.Errorf("Parse(%q) = %v %v, want %v", out, got, ok, want)
		}
	}
	if _, ok := Parse(banner + "[INF] Current Version: dev\n"); ok {
		t.Error("no version should not parse")
	}
}

func TestUntested(t *testing.T) {
	tested := [3]int{1, 6, 10}
	for v, want := range map[[3]int]bool{
		{1, 6, 10}: false,
		{1, 6, 11}: false,
		{1, 7, 0}:  false,
		{1, 6, 9}:  true,
		{1, 5, 99}: true,
		{0, 9, 9}:  true,
		{2, 0, 0}:  true,
	} {
		if got := Untested(v, tested); got != want {
			t.Errorf("Untested(%v) = %v, want %v", v, got, want)
		}
	}
}
