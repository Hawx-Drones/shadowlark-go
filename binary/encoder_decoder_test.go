package binary

import "testing"

func TestU32Roundtrip(t *testing.T) {
	enc := NewEncoder()
	enc.WriteU32(123456)
	data := enc.Bytes()

	dec := NewDecoder(data)
	got, err := dec.ReadU32()
	if err != nil {
		t.Fatalf("read u32: %v", err)
	}
	if got != 123456 {
		t.Fatalf("want 123456 got %d", got)
	}
}

func TestStringRoundtrip(t *testing.T) {
	enc := NewEncoder()
	enc.WriteString("shadowlark")
	data := enc.Bytes()

	dec := NewDecoder(data)
	got, err := dec.ReadString()
	if err != nil {
		t.Fatalf("read string: %v", err)
	}
	if got != "shadowlark" {
		t.Fatalf("want shadowlark got %s", got)
	}
}
