package capture

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"
)

// A protobuf message read without its schema shows its structure only:
// field numbers, wire types, lengths and, in responses, numbers. A string
// shows its length (a token under field 3 has no name to be masked by); in
// requests only 1-byte varints (enums, booleans) show their value, as a lone
// "code" is masked in requests. A span of printable text is always a
// string, never tried as a message (a 4-digit code parses as one 4% of the
// time, and its bytes would then show as numbers).

const (
	protoMaxDepth = 32
	protoMaxNodes = 4096
	protoMaxOut   = 64 << 10
)

type protoWalk struct {
	request bool
	nodes   int
	out     int  // bytes written, kept or not: one cap for the whole rendering
	budget  int  // bytes it may still scan, trials of sub-messages included: linear in the head
	capped  bool // a cap was reached: what follows is not read
	short   bool // the top level ran out of bytes (a cut head), rather than read wrong
	held    bool // the top level read a string or a whole sub-message: a cut prefix is then protobuf, not chance
}

func (w *protoWalk) printf(b *strings.Builder, format string, a ...any) {
	n, _ := fmt.Fprintf(b, format, a...)
	w.out += n
}

// full: a cap is reached; the rest is not read.
func (w *protoWalk) full() bool {
	if w.nodes++; w.nodes > protoMaxNodes || w.out > protoMaxOut {
		w.capped = true
	}
	return w.capped
}

func protoVarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * i)
		if b[i] < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

// protoNotShown is what a body that does not read as protobuf gives: none of
// it, as what was read before the error could be another format's bytes.
const protoNotShown = "(not protobuf, or not read to its end: not shown)\n"

// renderProtoStructure renders msg; cut says the head ended inside it.
func renderProtoStructure(msg []byte, request, cut bool) string {
	w := &protoWalk{request: request, budget: 32*len(msg) + 1024}
	var b strings.Builder
	ok := w.message(&b, msg, 0)
	switch {
	case !ok && cut && w.short && w.held:
		return b.String() + "… (cut)\n"
	case !ok:
		return protoNotShown
	case w.capped:
		return b.String() + "… (more not read)\n"
	case cut:
		return b.String() + "… (cut)\n"
	}
	return b.String()
}

// message writes msg's fields, one a line at depth's indent; false if it is
// not a whole message.
func (w *protoWalk) message(b *strings.Builder, msg []byte, depth int) bool {
	indent := strings.Repeat("  ", depth)
	short := func() bool {
		if depth == 0 {
			w.short = true
		}
		return false
	}
	for i := 0; i < len(msg); {
		if w.full() {
			return true
		}
		tag, n := protoVarint(msg[i:])
		if n == 0 {
			return short()
		}
		if tag>>3 == 0 || tag>>3 > 1<<29-1 {
			return false
		}
		i += n
		num, typ := tag>>3, tag&7
		switch typ {
		case 0:
			v, n := protoVarint(msg[i:])
			if n == 0 {
				return short()
			}
			if w.request && n > 1 {
				w.printf(b, "%s%d: varint(%d bytes)\n", indent, num, n)
			} else {
				w.printf(b, "%s%d: %d\n", indent, num, v)
			}
			i += n
		case 1, 5:
			size := 8
			if typ == 5 {
				size = 4
			}
			if len(msg)-i < size {
				return short()
			}
			switch {
			case w.request:
				w.printf(b, "%s%d: fixed%d\n", indent, num, size*8)
			case size == 8:
				w.printf(b, "%s%d: fixed64 %d\n", indent, num, binary.LittleEndian.Uint64(msg[i:]))
			default:
				w.printf(b, "%s%d: fixed32 %d\n", indent, num, binary.LittleEndian.Uint32(msg[i:]))
			}
			i += size
		case 2:
			l, n := protoVarint(msg[i:])
			if n == 0 || l > uint64(len(msg)-i-n) {
				return short()
			}
			i += n
			span := msg[i : i+int(l)]
			i += int(l)
			w.span(b, num, span, depth)
		default: // groups (3, 4) and wire types protobuf does not have
			return false
		}
	}
	return true
}

// span writes a length-delimited field: text as its length, a whole
// sub-message as its fields, other bytes as their length. A trial that a cap
// stopped is not a whole message.
func (w *protoWalk) span(b *strings.Builder, num uint64, span []byte, depth int) {
	indent := strings.Repeat("  ", depth)
	switch {
	case len(span) > 0 && utf8.Valid(span) && strictText(span):
		w.printf(b, "%s%d: string(%d)\n", indent, num, len(span))
		w.held = w.held || depth == 0
		return
	case len(span) > 0 && depth+1 < protoMaxDepth && w.budget >= len(span) && !w.capped:
		w.budget -= len(span)
		var sub strings.Builder
		nodes := w.nodes
		if w.message(&sub, span, depth+1) && (!w.capped || protoWhole(span)) {
			w.printf(b, "%s%d {\n%s%s}\n", indent, num, sub.String(), indent)
			w.held = w.held || depth == 0
			return
		}
		w.nodes = nodes // a trial that failed counts for nothing shown
	}
	w.printf(b, "%s%d: bytes(%d)\n", indent, num, len(span))
}

// protoWhole: span reads as one level of fields to its end (tags, varints
// and lengths in bounds), not looking inside: whether a trial a cap stopped
// was a message all the same.
func protoWhole(span []byte) bool {
	for i := 0; i < len(span); {
		tag, n := protoVarint(span[i:])
		if n == 0 || tag>>3 == 0 || tag>>3 > 1<<29-1 {
			return false
		}
		i += n
		switch tag & 7 {
		case 0:
			if _, n = protoVarint(span[i:]); n == 0 {
				return false
			}
			i += n
		case 1:
			i += 8
		case 5:
			i += 4
		case 2:
			l, n := protoVarint(span[i:])
			if n == 0 || l > uint64(len(span)-i-n) {
				return false
			}
			i += n + int(l)
		default:
			return false
		}
		if i > len(span) {
			return false
		}
	}
	return true
}

// isProtobuf: a content type of protobuf bodies (one message, not framed).
func isProtobuf(ct string) bool {
	ct, _, _ = strings.Cut(strings.ToLower(ct), ";")
	switch strings.TrimSpace(ct) {
	case "application/x-protobuf", "application/protobuf", "application/vnd.google.protobuf", "application/x-google-protobuf", "application/proto":
		return true
	}
	return false
}

// renderProto renders a protobuf message: with --proto and its type known,
// as JSON masked by name; else its structure only.
func renderProto(msg []byte, ct, path string, request, cut bool) ([]byte, string) {
	if len(msg) > 0 && utf8.Valid(trimCutRune(msg)) && strictText(trimCutRune(msg)) {
		return []byte(protoNotShown), "protobuf structure: none, the body is text" // text under a protobuf type: its bytes would read as numbers
	}
	if md := protoMessageType(ct, path, request); md != nil {
		return []byte(renderProtoJSON(msg, md, request, cut)), "protobuf as " + string(md.FullName()) + " (--proto)"
	}
	return []byte(renderProtoStructure(msg, request, cut)), "protobuf structure: field numbers, types, lengths; strings by length"
}
