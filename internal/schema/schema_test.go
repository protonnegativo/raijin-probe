package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDerivableFieldsAreLeftOut(t *testing.T) {
	res := Result{
		Tool:     "raijin-probe",
		Findings: []Finding{{ID: "403-ab12cd34", Severity: "low", Tags: []string{"auth"}, Response: Response{Status: 403}, Locations: []string{"http://a", "http://b"}, Count: 2, Fingerprint: "fp"}},
		Groups:   []Group{{ID: "200-ef56ab78", Response: Response{Status: 200}, Locations: []string{"http://c"}, Count: 1}},
		Omitted:  map[string]int{},
		Errors:   []Error{},
		Next:     []string{},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fingerprint", "count", "confidence", "title", "length", "server", "tech", "type", "cdn", "error", "new", "omitted", "errors", "next", "raw", "budget"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s should be left out: %s", k, b)
		}
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("no null values: %s", b)
	}
}

func TestResponseFieldsAreInline(t *testing.T) {
	f := Finding{ID: "200-x", Title: "Admin Login", Severity: "medium", Tags: []string{"panel"}, Response: Response{Status: 200, Length: 262, Server: "nginx", Tech: []string{"Nginx"}}, Locations: []string{"http://a"}}
	b, _ := json.Marshal(f)
	want := `{"id":"200-x","title":"Admin Login","severity":"medium","tags":["panel"],"status":200,"length":262,"server":"nginx","tech":["Nginx"],"locations":["http://a"]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestCountAndBudgetAppearWhenSomethingIsCut(t *testing.T) {
	res := Result{
		Findings: []Finding{{ID: "403-x", Tags: []string{"auth"}, Locations: []string{"http://a"}, Count: 7}},
		Groups:   []Group{{ID: "200-y", Count: 4}},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000, Truncated: true},
	}
	b, _ := json.Marshal(res)
	s := string(b)
	if !strings.Contains(s, `"locations":["http://a"],"count":7`) || !strings.Contains(s, `{"id":"200-y","count":4}`) {
		t.Errorf("count must be written when locations were cut: %s", s)
	}
	if !strings.Contains(s, `"budget":{"max_items":20,"max_bytes":8000,"truncated":true}`) || strings.Count(s, "budget") != 1 {
		t.Errorf("budget must be written once when something was cut: %s", s)
	}
}
