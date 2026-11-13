package capture

import (
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Marker is a note put among the records by the user (`reqcove mark`, source
// cli) or an agent (add_marker, source mcp): a time and a checkpoint to read
// from. The source is the channel, a help, not proof. Kept in memory: gone at
// a restart, as flow ids.
type Marker struct {
	ID     int64
	Time   time.Time
	Text   string // masked as it arrived
	Source string
}

const (
	maxMarkers    = 100 // per source: an agent's cannot push out the user's
	MaxMarkerText = 80  // characters
)

// AddMarker keeps a marker, refusing a text longer than MaxMarkerText or not
// one line (the errors never quote it), and returns it with the checkpoint.
func (s *Store) AddMarker(text, source string) (Marker, int64, error) {
	if utf8.RuneCountInString(text) > MaxMarkerText {
		return Marker{}, 0, errors.New("text: at most 80 characters")
	}
	if !utf8.ValidString(text) || strings.ContainsFunc(text, func(r rune) bool { return unicode.IsControl(r) || unicode.In(r, unicode.Zl, unicode.Zp) }) {
		return Marker{}, 0, errors.New("text: one line, without control characters")
	}
	text = s.maskError(text)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.markers == nil {
		s.markers = map[string][]Marker{}
	}
	s.markerID++
	m := Marker{ID: s.markerID, Time: time.Now(), Text: text, Source: source}
	l := append(s.markers[source], m)
	if len(l) > maxMarkers {
		l = slices.Delete(l, 0, 1)
	}
	s.markers[source] = l
	return m, s.seq, nil
}

// Markers are the markers kept, oldest first; since (unix seconds), when not
// 0, keeps those at or after it.
func (s *Store) Markers(since float64) []Marker {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Marker
	for _, l := range s.markers {
		for _, m := range l {
			if since == 0 || float64(m.Time.UnixMilli())/1000 >= since {
				out = append(out, m)
			}
		}
	}
	slices.SortFunc(out, func(a, b Marker) int { return int(a.ID - b.ID) })
	return out
}
