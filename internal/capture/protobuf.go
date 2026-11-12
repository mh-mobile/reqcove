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
	budget  int // bytes it may still scan, trials of sub-messages included: linear in the head
	b       strings.Builder
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

// renderProtoStructure renders msg; cut says the head ended inside it.
func renderProtoStructure(msg []byte, request, cut bool) string {
	w := &protoWalk{request: request, budget: 32*len(msg) + 1024}
	var b strings.Builder
	ok := w.message(&b, msg, 0)
	out := b.String()
	if !ok {
		out += "… (not protobuf from here, or cut)\n"
	} else if cut {
		out += "… (cut)\n"
	}
	return out
}

// message writes msg's fields, one a line at depth's indent; false if it is
// not a whole message (it then wrote what it could read).
func (w *protoWalk) message(b *strings.Builder, msg []byte, depth int) bool {
	indent := strings.Repeat("  ", depth)
	for i := 0; i < len(msg); {
		if w.nodes++; w.nodes > protoMaxNodes || b.Len() > protoMaxOut {
			b.WriteString(indent + "… (more not read)\n")
			return true
		}
		tag, n := protoVarint(msg[i:])
		if n == 0 || tag>>3 == 0 || tag>>3 > 1<<29-1 {
			return false
		}
		i += n
		num, typ := tag>>3, tag&7
		switch typ {
		case 0:
			v, n := protoVarint(msg[i:])
			if n == 0 {
				return false
			}
			if w.request && n > 1 {
				fmt.Fprintf(b, "%s%d: varint(%d bytes)\n", indent, num, n)
			} else {
				fmt.Fprintf(b, "%s%d: %d\n", indent, num, v)
			}
			i += n
		case 1, 5:
			size := 8
			if typ == 5 {
				size = 4
			}
			if len(msg)-i < size {
				return false
			}
			switch {
			case w.request:
				fmt.Fprintf(b, "%s%d: fixed%d\n", indent, num, size*8)
			case size == 8:
				fmt.Fprintf(b, "%s%d: fixed64 %d\n", indent, num, binary.LittleEndian.Uint64(msg[i:]))
			default:
				fmt.Fprintf(b, "%s%d: fixed32 %d\n", indent, num, binary.LittleEndian.Uint32(msg[i:]))
			}
			i += size
		case 2:
			l, n := protoVarint(msg[i:])
			if n == 0 || l > uint64(len(msg)-i-n) {
				return false
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
// sub-message as its fields, other bytes as their length.
func (w *protoWalk) span(b *strings.Builder, num uint64, span []byte, depth int) {
	indent := strings.Repeat("  ", depth)
	switch {
	case len(span) > 0 && utf8.Valid(span) && strictText(span):
		fmt.Fprintf(b, "%s%d: string(%d)\n", indent, num, len(span))
		return
	case len(span) > 0 && depth+1 < protoMaxDepth && w.budget >= len(span):
		w.budget -= len(span)
		var sub strings.Builder
		if nodes := w.nodes; w.message(&sub, span, depth+1) {
			fmt.Fprintf(b, "%s%d {\n%s%s}\n", indent, num, sub.String(), indent)
			return
		} else {
			w.nodes = nodes // a trial that failed counts for nothing shown
		}
	}
	fmt.Fprintf(b, "%s%d: bytes(%d)\n", indent, num, len(span))
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
	if md := protoMessageType(ct, path, request); md != nil {
		return []byte(renderProtoJSON(msg, md, request, cut)), "protobuf as " + string(md.FullName()) + " (--proto)"
	}
	return []byte(renderProtoStructure(msg, request, cut)), "protobuf structure: field numbers, types, lengths; strings by length"
}
