package capture

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"
)

// pb appends a field: tag, then the value's bytes (varints already encoded).
func pbTag(num, typ int) []byte { return protoAppendVarint(nil, uint64(num<<3|typ)) }

func protoAppendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func pbBytes(num int, v []byte) []byte {
	return append(protoAppendVarint(pbTag(num, 2), uint64(len(v))), v...)
}

func pbVarint(num int, v uint64) []byte { return protoAppendVarint(pbTag(num, 0), v) }

// TestProtoStructure: field numbers, types and lengths; strings by length,
// never tried as messages; numbers in responses, 1-byte ones in requests.
func TestProtoStructure(t *testing.T) {
	inner := append(pbBytes(1, []byte("abc")), pbVarint(2, 7)...)
	msg := append(append(append(pbVarint(1, 150), pbBytes(2, []byte(fuzzSecret))...), pbBytes(3, inner)...), pbBytes(4, []byte("0808"))...)
	msg = append(msg, pbBytes(5, []byte{0x00, 0xff, 0x10, 0x80})...)
	msg = append(msg, pbVarint(6, 1)...)
	msg = append(append(msg, pbTag(7, 1)...), []byte{1, 0, 0, 0, 0, 0, 0, 0}...)
	resp := renderProtoStructure(msg, false, false)
	want := "1: 150\n2: string(14)\n3 {\n  1: string(3)\n  2: 7\n}\n4: string(4)\n5: bytes(4)\n6: 1\n7: fixed64 1\n"
	if resp != want {
		t.Errorf("response:\n%s\nwant:\n%s", resp, want)
	}
	req := renderProtoStructure(msg, true, false)
	if !strings.Contains(req, "1: varint(2 bytes)\n") || !strings.Contains(req, "6: 1\n") || !strings.Contains(req, "7: fixed64\n") || strings.Contains(req, "150") {
		t.Errorf("request:\n%s", req)
	}
	if leak(resp+req, fuzzSecret) != "" {
		t.Errorf("a string's contents shown")
	}
	if got := renderProtoStructure(msg[:len(msg)-3], false, true); !strings.HasSuffix(got, "… (not protobuf from here, or cut)\n") {
		t.Errorf("cut:\n%s", got)
	}
	if got := renderProtoStructure([]byte("not protobuf at all"), false, false); !strings.Contains(got, "not protobuf") {
		t.Errorf("text: %q", got)
	}
	// Cost on shapes a site can send, 64 KiB each.
	deep := []byte("x")
	for len(deep) < 64<<10 {
		deep = pbBytes(1, deep)
	}
	for name, b := range map[string][]byte{
		"varints":   []byte(strings.Repeat("\x08\xff\xff\xff\xff\xff\xff\xff\xff\x01", 64<<10/10)),
		"nesting":   deep,
		"two bytes": []byte(strings.Repeat("\x08\x01", 32<<10)),
		"lengths":   []byte(strings.Repeat("\x0a\x05\x0a\x03\x08\x01\x00", 64<<10/7)),
		"past head": append(pbTag(1, 2), 0xff, 0xff, 0xff, 0xff, 0x0f),
	} {
		start := time.Now()
		out := renderProtoStructure(b, false, false)
		if d := time.Since(start); d > 200*time.Millisecond || len(out) > protoMaxOut+4096 {
			t.Errorf("%s: %v, %d bytes", name, d, len(out))
		}
	}
}

// FuzzProtoStructure: never panics, and a printable string's bytes never
// show, wherever it sits.
func FuzzProtoStructure(f *testing.F) {
	f.Add([]byte("\x08\x96\x01\x12\x03abc"), true)
	f.Fuzz(func(t *testing.T, b []byte, request bool) {
		renderProtoStructure(b, request, false)
		msg := append(append([]byte(nil), b...), pbBytes(15, []byte(fuzzSecret))...)
		if out := renderProtoStructure(msg, request, false); leak(out, fuzzSecret) != "" {
			t.Errorf("%q -> %q", msg, out)
		}
	})
}

// protoTestSchema: a schema built in Go (no protoc), written as --proto reads it.
func protoTestSchema(t *testing.T) (path string, login protoreflect.MessageDescriptor) {
	t.Helper()
	str := func(s string) *string { return &s }
	i32 := func(i int32) *int32 { return &i }
	lbl := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	rep := descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	typ := func(t descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto_Type { return &t }
	field := func(name string, num int32, ty descriptorpb.FieldDescriptorProto_Type, l *descriptorpb.FieldDescriptorProto_Label, msg string) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{Name: str(name), Number: i32(num), Type: typ(ty), Label: l}
		if msg != "" {
			f.TypeName = str(msg)
		}
		return f
	}
	T := descriptorpb.FieldDescriptorProto_TYPE_STRING
	pw := field("password", 2, T, lbl, "")
	pw.JsonName = str("p") // the proto name is what counts
	file := &descriptorpb.FileDescriptorProto{
		Name: str("t.proto"), Package: str("t"), Syntax: str("proto3"), Dependency: []string{"google/protobuf/any.proto"},
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: str("Inner"), Field: []*descriptorpb.FieldDescriptorProto{field("token", 1, T, lbl, ""), field("note", 2, T, lbl, "")}},
			{Name: str("Login"), Field: []*descriptorpb.FieldDescriptorProto{
				field("user", 1, T, lbl, ""), pw,
				field("avatar", 3, descriptorpb.FieldDescriptorProto_TYPE_BYTES, lbl, ""),
				field("pin", 4, descriptorpb.FieldDescriptorProto_TYPE_INT32, lbl, ""),
				field("inner", 5, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, lbl, ".t.Inner"),
				field("tags", 6, T, rep, ""),
				field("meta", 7, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, rep, ".t.Login.MetaEntry"),
				field("status", 8, descriptorpb.FieldDescriptorProto_TYPE_ENUM, lbl, ".t.Status"),
				field("delta", 9, descriptorpb.FieldDescriptorProto_TYPE_SINT32, lbl, ""),
				field("nums", 10, descriptorpb.FieldDescriptorProto_TYPE_INT32, rep, ""),
				field("extra", 11, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, lbl, ".google.protobuf.Any"),
			}, NestedType: []*descriptorpb.DescriptorProto{{Name: str("MetaEntry"), Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
				Field: []*descriptorpb.FieldDescriptorProto{field("key", 1, T, lbl, ""), field("value", 2, T, lbl, "")}}}},
		},
		EnumType: []*descriptorpb.EnumDescriptorProto{{Name: str("Status"), Value: []*descriptorpb.EnumValueDescriptorProto{{Name: str("UNKNOWN"), Number: i32(0)}, {Name: str("ACTIVE"), Number: i32(1)}}}},
		Service:  []*descriptorpb.ServiceDescriptorProto{{Name: str("S"), Method: []*descriptorpb.MethodDescriptorProto{{Name: str("Do"), InputType: str(".t.Login"), OutputType: str(".t.Inner")}}}},
	}
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{protodesc.ToFileDescriptorProto(anypb.File_google_protobuf_any_proto), file}}
	b, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "schema.pb")
	os.WriteFile(path, b, 0o600)
	files, err := protodesc.NewFiles(set)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := files.FindDescriptorByName("t.Login")
	return path, d.(protoreflect.MessageDescriptor)
}

// TestProtoSchema: --proto reads a message by its names, as JSON, masked by
// name; unknown fields by structure; errors quote nothing of the file.
func TestProtoSchema(t *testing.T) {
	path, login := protoTestSchema(t)
	defer protoSchema.Store(nil)
	if n, err := LoadProtoSchema(path); err != nil || n != 3 {
		t.Fatalf("load: %d %v", n, err)
	}
	m := dynamicpb.NewMessage(login)
	set := func(name string, v protoreflect.Value) { m.Set(login.Fields().ByName(protoreflect.Name(name)), v) }
	set("user", protoreflect.ValueOfString("alice"))
	set("password", protoreflect.ValueOfString("PBsecret01x"))
	set("avatar", protoreflect.ValueOfBytes([]byte("PBsecretBytes")))
	set("pin", protoreflect.ValueOfInt32(424242))
	in := dynamicpb.NewMessage(login.Fields().ByName("inner").Message())
	in.Set(in.Descriptor().Fields().ByName("token"), protoreflect.ValueOfString("PBsecret02x"))
	in.Set(in.Descriptor().Fields().ByName("note"), protoreflect.ValueOfString("hi"))
	set("inner", protoreflect.ValueOfMessage(in))
	tags := m.Mutable(login.Fields().ByName("tags")).List()
	tags.Append(protoreflect.ValueOfString("a"))
	tags.Append(protoreflect.ValueOfString("b"))
	meta := m.Mutable(login.Fields().ByName("meta")).Map()
	meta.Set(protoreflect.ValueOfString("authorization").MapKey(), protoreflect.ValueOfString("PBsecret03x"))
	meta.Set(protoreflect.ValueOfString("x").MapKey(), protoreflect.ValueOfString("y"))
	set("status", protoreflect.ValueOfEnum(1))
	set("delta", protoreflect.ValueOfInt32(-5))
	nums := m.Mutable(login.Fields().ByName("nums")).List()
	nums.Append(protoreflect.ValueOfInt32(1))
	nums.Append(protoreflect.ValueOfInt32(300))
	inner2, _ := anypb.New(&descriptorpb.FileOptions{GoPackage: proto.String("PBanyValue")})
	set("extra", protoreflect.ValueOfMessage(inner2.ProtoReflect()))
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	b = append(b, pbBytes(99, []byte(fuzzSecret))...) // a field the schema does not have
	out, view := renderProto(b, "application/grpc", "/t.S/Do", true, false)
	got := string(out)
	for _, s := range []string{"PBsecret01", "PBsecret02", "PBsecret03", "PBsecretBytes", "424242", fuzzSecret[:6]} {
		if strings.Contains(got, s) {
			t.Errorf("%s left in %s", s, got)
		}
	}
	for _, s := range []string{`"user":"alice"`, `"avatar":"bytes(13)"`, `"note":"hi"`, `"tags":["a","b"]`, `"meta":{"authorization":"[redacted]","x":"y"}`, `"status":"ACTIVE"`, `"delta":-5`, `"nums":[1,300]`, `"99":"99: string(14)"`, `"password":"[redacted]"`, `"@type":"type.googleapis.com/google.protobuf.FileOptions"`} {
		if !strings.Contains(got, s) {
			t.Errorf("%s missing in %s", s, got)
		}
	}
	if view != "protobuf as t.Login (--proto)" {
		t.Errorf("view %q", view)
	}
	// The response type, and messageType in the content type.
	if _, view := renderProto(nil, "application/grpc", "/t.S/Do", false, false); view != "protobuf as t.Inner (--proto)" {
		t.Errorf("response view %q", view)
	}
	if _, view := renderProto(nil, `application/x-protobuf; messageType="t.Inner"`, "/v1/whatever", false, false); view != "protobuf as t.Inner (--proto)" {
		t.Errorf("messageType view %q", view)
	}
	if _, view := renderProto(nil, "application/x-protobuf", "/v1/whatever", false, false); !strings.HasPrefix(view, "protobuf structure") {
		t.Errorf("no type: %q", view)
	}
	// Errors name no contents.
	bad := filepath.Join(t.TempDir(), "bad")
	os.WriteFile(bad, []byte("PBsecretFile not a descriptor"), 0o600)
	if _, err := LoadProtoSchema(bad); err == nil || strings.Contains(err.Error(), "PBsecretFile") {
		t.Errorf("a bad file: %v", err)
	}
}

// TestProtoReview: the item review (Fable): two --proto bodies that differ
// only behind bytes(N) are never "same".
func TestProtoReview(t *testing.T) {
	path, login := protoTestSchema(t)
	defer protoSchema.Store(nil)
	if _, err := LoadProtoSchema(path); err != nil {
		t.Fatal(err)
	}
	s := NewStore(10, 1<<20)
	for i, avatar := range []string{"0123456789abcdef", "fedcba9876543210"} {
		m := dynamicpb.NewMessage(login)
		m.Set(login.Fields().ByName("user"), protoreflect.ValueOfString("alice"))
		m.Set(login.Fields().ByName("avatar"), protoreflect.ValueOfBytes([]byte(avatar)))
		b, _ := proto.Marshal(m)
		id := []string{"a", "b"}[i]
		grpcApply(s, map[string]any{"ev": "request", "id": id, "method": "POST", "url": "https://api.example/t.S/Do", "host": "api.example", "path": "/t.S/Do", "headers": [][2]string{{"Content-Type", "application/x-protobuf"}}})
		grpcApply(s, map[string]any{"ev": "body", "id": id, "dir": "request", "decoded": true, "final": true, "size": len(b), "head": base64.StdEncoding.EncodeToString(b)})
	}
	if d, _ := s.DiffFlows("a", "b"); d.RequestBody.Result == "same" {
		t.Errorf("bytes(16) on both sides read as the same: %+v", d.RequestBody)
	}
}
