// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
//
// Nothing the engine found is dropped silently: every probed URL is listed, in a finding or in a group,
// and anything a budget cuts is counted in Omitted. What an agent can rebuild is left out of the JSON to
// save tokens: empty lists, the budget when nothing was cut, a count equal to the locations listed, and
// fields at their documented default.
//
// raijin-probe adds the response fields (status, length, server, tech, type, cdn, error) to findings and
// groups: they are what an agent reads to pick its next targets.
package schema

import core "github.com/protonnegativo/raijin-core/schema"

// The envelope (Result, Error, Budget, Marshal and the rank tables) lives in raijin-core, shared by every
// Raijin tool. Finding and Group, and the response fields they carry, are this tool's own.
type (
	Result = core.Result[Finding, Group]
	Error  = core.Error
	Budget = core.Budget
)

var (
	Marshal        = core.Marshal
	SeverityRank   = core.SeverityRank
	ConfidenceRank = core.ConfidenceRank
)

// Response is what every URL in a finding or group answered. Zero values are left out: no status means
// the probe failed (see Error), no length means an empty body, no type means text/html ("none" when the
// server sent no Content-Type).
type Response struct {
	Status int      `json:"status,omitempty"`
	Length int      `json:"length,omitempty"`
	Server string   `json:"server,omitempty"`
	Tech   []string `json:"tech,omitempty"`
	Type   string   `json:"type,omitempty"`
	CDN    string   `json:"cdn,omitempty"`
	Error  string   `json:"error,omitempty"`
}

// Finding is one response worth a look (a panel, a 403, an outlier...) with every URL that returned it.
// The same tool and ID in two runs is the same finding.
type Finding struct {
	ID string `json:"id"`
	// Title is the page title; it is left out when the page has none.
	Title    string `json:"title,omitempty"`
	Severity string `json:"severity"`
	// Confidence is "verified" or "heuristic"; empty means "matched".
	Confidence string `json:"confidence,omitempty"`
	// Tags are the rules that made it a finding: panel, listing, auth, error, outlier.
	Tags []string `json:"tags"`
	Response
	// Locations are every URL that returned this response, each with where it redirects and its IPs.
	Locations []string `json:"locations"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
	// Fingerprint is the internal key for --state; it is derived from the ID and not written.
	Fingerprint string `json:"-"`
	New         bool   `json:"new,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (f Finding) MarshalJSON() ([]byte, error) {
	type plain Finding
	p := plain(f)
	p.Count = core.OmitCount(p.Count, len(p.Locations))
	return Marshal(p)
}

// Group is one response that no rule flagged (a default page, a 404, a failed probe), with every URL
// that returned it. 50 hosts serving the same nginx welcome page are one group.
type Group struct {
	ID    string `json:"id"`
	Title string `json:"title,omitempty"`
	Response
	Locations []string `json:"locations,omitempty"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (g Group) MarshalJSON() ([]byte, error) {
	type plain Group
	p := plain(g)
	p.Count = core.OmitCount(p.Count, len(p.Locations))
	return Marshal(p)
}
