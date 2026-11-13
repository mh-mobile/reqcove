package capture

import "testing"

// At most 100 markers per source, oldest dropped: an agent's 150 never push
// out the user's; they come back oldest first.
func TestMarkersPerSource(t *testing.T) {
	st := NewStore(10, 1<<20)
	st.AddMarker("mine", "cli")
	for range 150 {
		st.AddMarker("agent", "mcp")
	}
	ms := st.Markers(0)
	if len(ms) != 101 || ms[0].Source != "cli" || ms[0].ID != 1 || ms[1].ID != 52 || ms[100].ID != 151 {
		t.Fatalf("%d markers, first %+v, second %+v", len(ms), ms[0], ms[1])
	}
}
