package capture

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// --proto FILE: a compiled FileDescriptorSet (protoc --descriptor_set_out,
// with --include_imports). With it, a message whose type is known (a gRPC,
// gRPC-Web, Connect or Twirp method by its path; a messageType in the
// content type) is read with its field names, as JSON, and masked by name as
// JSON is. Fields the schema does not know are read as structure only.
var protoSchema atomic.Pointer[protoregistry.Files]

// LoadProtoSchema reads the --proto file. Errors give at most the names of
// the schema's own types (the user's file), never message data.
func LoadProtoSchema(path string) (messages int, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(b, &set); err != nil || len(set.File) == 0 {
		return 0, errors.New("not a FileDescriptorSet (protoc --descriptor_set_out=FILE --include_imports)")
	}
	files, err := protodesc.NewFiles(&set)
	if err != nil {
		return 0, fmt.Errorf("its files do not resolve (protoc --include_imports puts the imports in): %w", err)
	}
	files.RangeFiles(func(f protoreflect.FileDescriptor) bool {
		messages += f.Messages().Len()
		return true
	})
	protoSchema.Store(files)
	return messages, nil
}

// protoMessageType finds the message type a body carries: the content type's
// messageType, else the method its path names (the last two segments, as
// gRPC, gRPC-Web, Connect and Twirp write it), the input in a request, the
// output in a response.
func protoMessageType(ct, path string, request bool) protoreflect.MessageDescriptor {
	files := protoSchema.Load()
	if files == nil {
		return nil
	}
	for _, p := range strings.Split(ct, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok && strings.EqualFold(k, "messagetype") {
			if d, err := files.FindDescriptorByName(protoreflect.FullName(strings.Trim(v, `"`))); err == nil {
				if md, ok := d.(protoreflect.MessageDescriptor); ok {
					return md
				}
			}
		}
	}
	path, _, _ = strings.Cut(path, "?")
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) < 2 {
		return nil
	}
	d, err := files.FindDescriptorByName(protoreflect.FullName(segs[len(segs)-2]))
	if err != nil {
		return nil
	}
	sd, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil
	}
	m := sd.Methods().ByName(protoreflect.Name(segs[len(segs)-1]))
	if m == nil {
		return nil
	}
	if request {
		return m.Input()
	}
	return m.Output()
}

// renderProtoJSON reads msg as md, as JSON with the proto field names (never
// json_name: a field password with json_name "p" would pass), then masks it
// as JSON. bytes show their length; an Any the schema cannot resolve, its
// length; unknown fields their structure under their numbers.
func renderProtoJSON(msg []byte, md protoreflect.MessageDescriptor, request, cut bool) string {
	w := &protoWalk{request: request, budget: 32*len(msg) + 1024}
	var b strings.Builder
	ok := w.named(&b, msg, md, 0)
	out := b.String()
	if !ok || cut {
		out += "\n… (cut, or not this message from here)"
	}
	return string(maskBody([]byte(out), "application/json", request))
}

type protoField struct {
	key    string
	values []string
	list   bool // repeated: a JSON array
}

// named writes msg as a JSON object; false if it is not a whole message.
func (w *protoWalk) named(b *strings.Builder, msg []byte, md protoreflect.MessageDescriptor, depth int) bool {
	var fields []*protoField
	byKey := map[string]*protoField{}
	add := func(key, v string, list bool) {
		f := byKey[key]
		if f == nil {
			f = &protoField{key: key, list: list}
			byKey[key] = f
			fields = append(fields, f)
		}
		if f.list || len(f.values) == 0 {
			f.values = append(f.values, v)
		} else {
			f.values[0] = v // a repeated scalar field written twice: the last wins, as protobuf reads it
		}
	}
	ok := true
	for i := 0; i < len(msg); {
		if w.nodes++; w.nodes > protoMaxNodes || b.Len() > protoMaxOut {
			add("…", `"more not read"`, false)
			break
		}
		tag, n := protoVarint(msg[i:])
		if n == 0 || tag>>3 == 0 || tag>>3 > 1<<29-1 {
			ok = false
			break
		}
		i += n
		num, typ := protowireNumber(tag), tag&7
		var raw []byte // the field's value bytes
		switch typ {
		case 0:
			_, n := protoVarint(msg[i:])
			if n == 0 {
				ok = false
			}
			raw, i = msg[i:i+n], i+n
		case 1, 5:
			size := 8
			if typ == 5 {
				size = 4
			}
			if len(msg)-i < size {
				ok = false
				break
			}
			raw, i = msg[i:i+size], i+size
		case 2:
			l, n := protoVarint(msg[i:])
			if n == 0 || l > uint64(len(msg)-i-n) {
				ok = false
				break
			}
			raw, i = msg[i+n:i+n+int(l)], i+n+int(l)
		default:
			ok = false
		}
		if !ok {
			break
		}
		fd := md.Fields().ByNumber(num)
		if fd == nil {
			add(strconv.Itoa(int(num)), jsonString(strings.TrimSpace(w.unknown(num, typ, raw, depth))), false)
			continue
		}
		key := string(fd.Name())
		list := fd.IsList() || fd.IsMap()
		if fd.IsMap() && typ == 2 {
			k, v, good := w.mapEntry(raw, fd, depth)
			if !good {
				add(key, `"[not read]":null`, true)
				continue
			}
			add(key, k+":"+v, true)
			continue
		}
		if typ == 2 && fd.Kind() != protoreflect.StringKind && fd.Kind() != protoreflect.BytesKind && fd.Kind() != protoreflect.MessageKind && fd.Kind() != protoreflect.GroupKind {
			for _, v := range w.packed(raw, fd) { // packed repeated scalars
				add(key, v, true)
			}
			continue
		}
		add(key, w.value(raw, typ, fd, depth), list)
	}
	b.WriteString("{")
	for k, f := range fields {
		if k > 0 {
			b.WriteString(",")
		}
		b.WriteString(jsonString(f.key) + ":")
		switch {
		case isMapKey(md, f.key): // entries "key":value, an object
			b.WriteString("{" + strings.Join(f.values, ",") + "}")
		case f.list:
			b.WriteString("[" + strings.Join(f.values, ",") + "]")
		default:
			b.WriteString(f.values[0])
		}
	}
	b.WriteString("}")
	return ok
}

func isMapKey(md protoreflect.MessageDescriptor, key string) bool {
	fd := md.Fields().ByName(protoreflect.Name(key))
	return fd != nil && fd.IsMap()
}

func protowireNumber(tag uint64) protoreflect.FieldNumber { return protoreflect.FieldNumber(tag >> 3) }

// unknown renders a field the schema does not have as structure only.
func (w *protoWalk) unknown(num protoreflect.FieldNumber, typ uint64, raw []byte, depth int) string {
	var b strings.Builder
	switch typ {
	case 2:
		w.span(&b, uint64(num), raw, 0)
	case 0:
		v, n := protoVarint(raw)
		if w.request && n > 1 {
			fmt.Fprintf(&b, "varint(%d bytes)", n)
		} else {
			fmt.Fprintf(&b, "%d", v)
		}
	default:
		fmt.Fprintf(&b, "fixed%d", len(raw)*8)
	}
	return b.String()
}

// value renders one field's value as JSON.
func (w *protoWalk) value(raw []byte, typ uint64, fd protoreflect.FieldDescriptor, depth int) string {
	switch fd.Kind() {
	case protoreflect.StringKind:
		if typ != 2 {
			return `"[wire type mismatch]"`
		}
		if !utf8.Valid(raw) {
			return fmt.Sprintf(`"string(%d), not UTF-8"`, len(raw))
		}
		return jsonString(string(raw))
	case protoreflect.BytesKind:
		return fmt.Sprintf(`"bytes(%d)"`, len(raw))
	case protoreflect.MessageKind, protoreflect.GroupKind:
		if typ != 2 || depth+1 >= protoMaxDepth {
			return fmt.Sprintf(`"bytes(%d)"`, len(raw))
		}
		md := fd.Message()
		if md.FullName() == "google.protobuf.Any" {
			return w.any(raw, depth)
		}
		var sub strings.Builder
		if !w.named(&sub, raw, md, depth+1) {
			return fmt.Sprintf(`"bytes(%d), not a %s"`, len(raw), md.Name())
		}
		return sub.String()
	}
	return w.scalar(raw, typ, fd)
}

// scalar renders a number, a bool or an enum.
func (w *protoWalk) scalar(raw []byte, typ uint64, fd protoreflect.FieldDescriptor) string {
	var v uint64
	switch typ {
	case 0:
		v, _ = protoVarint(raw)
	case 1:
		v = binary.LittleEndian.Uint64(raw)
	case 5:
		v = uint64(binary.LittleEndian.Uint32(raw))
	default:
		return `"[wire type mismatch]"`
	}
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return strconv.FormatBool(v != 0)
	case protoreflect.EnumKind:
		if ev := fd.Enum().Values().ByNumber(protoreflect.EnumNumber(int32(v))); ev != nil {
			return jsonString(string(ev.Name()))
		}
		return strconv.FormatInt(int64(int32(v)), 10)
	case protoreflect.Int32Kind:
		return strconv.FormatInt(int64(int32(v)), 10)
	case protoreflect.Int64Kind, protoreflect.Sfixed64Kind:
		return strconv.FormatInt(int64(v), 10)
	case protoreflect.Sint32Kind, protoreflect.Sint64Kind:
		return strconv.FormatInt(int64(v>>1)^-int64(v&1), 10)
	case protoreflect.Sfixed32Kind:
		return strconv.FormatInt(int64(int32(uint32(v))), 10)
	case protoreflect.FloatKind:
		f := math.Float32frombits(uint32(v))
		if math.IsInf(float64(f), 0) || math.IsNaN(float64(f)) {
			return jsonString(fmt.Sprint(f))
		}
		return strconv.FormatFloat(float64(f), 'g', -1, 32)
	case protoreflect.DoubleKind:
		f := math.Float64frombits(v)
		if math.IsInf(f, 0) || math.IsNaN(f) {
			return jsonString(fmt.Sprint(f))
		}
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
	return strconv.FormatUint(v, 10)
}

// packed renders a packed repeated scalar field's values.
func (w *protoWalk) packed(raw []byte, fd protoreflect.FieldDescriptor) []string {
	var out []string
	size := 0
	switch fd.Kind() {
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		size = 8
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		size = 4
	}
	for i := 0; i < len(raw) && len(out) < protoMaxNodes; {
		if w.nodes++; w.nodes > protoMaxNodes {
			break
		}
		if size == 0 {
			_, n := protoVarint(raw[i:])
			if n == 0 {
				break
			}
			out = append(out, w.scalar(raw[i:i+n], 0, fd))
			i += n
			continue
		}
		if len(raw)-i < size {
			break
		}
		typ := uint64(1)
		if size == 4 {
			typ = 5
		}
		out = append(out, w.scalar(raw[i:i+size], typ, fd))
		i += size
	}
	return out
}

// mapEntry renders a map field's entry as a JSON key and value: an object's
// key is then masked by name as any JSON key (an "authorization" entry).
func (w *protoWalk) mapEntry(raw []byte, fd protoreflect.FieldDescriptor, depth int) (k, v string, ok bool) {
	var sub strings.Builder
	if !w.named(&sub, raw, fd.Message(), depth+1) {
		return "", "", false
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal([]byte(sub.String()), &obj) != nil {
		return "", "", false
	}
	key, val := string(obj["key"]), string(obj["value"])
	if key == "" {
		key = `""`
	}
	if !strings.HasPrefix(key, `"`) {
		key = jsonString(key)
	}
	if val == "" {
		val = "null"
	}
	return key, val, true
}

// any renders a google.protobuf.Any: its value read as the type its URL
// names, when the schema has it; else its length.
func (w *protoWalk) any(raw []byte, depth int) string {
	var typeURL string
	var value []byte
	for i := 0; i < len(raw); {
		tag, n := protoVarint(raw[i:])
		if n == 0 || tag&7 != 2 {
			return fmt.Sprintf(`"bytes(%d)"`, len(raw))
		}
		i += n
		l, n := protoVarint(raw[i:])
		if n == 0 || l > uint64(len(raw)-i-n) {
			return fmt.Sprintf(`"bytes(%d)"`, len(raw))
		}
		span := raw[i+n : i+n+int(l)]
		i += n + int(l)
		switch tag >> 3 {
		case 1:
			typeURL = string(span)
		case 2:
			value = span
		}
	}
	name := typeURL[strings.LastIndexByte(typeURL, '/')+1:]
	if files := protoSchema.Load(); files != nil && name != "" {
		if d, err := files.FindDescriptorByName(protoreflect.FullName(name)); err == nil {
			if md, ok := d.(protoreflect.MessageDescriptor); ok {
				var sub strings.Builder
				if w.named(&sub, value, md, depth+1) {
					return `{"@type":` + jsonString(typeURL) + `,"value":` + sub.String() + `}`
				}
			}
		}
	}
	return fmt.Sprintf(`{"@type":%s,"value":"bytes(%d)"}`, jsonString(typeURL), len(value))
}
