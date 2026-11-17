package protocol

import (
	"errors"
	"testing"
)

func TestCanonicalizeRFC8785Example(t *testing.T) {
	// RFC 8785, section 3.2.2 / 3.2.3
	in := `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestCanonicalizeKeyOrderUTF16(t *testing.T) {
	// RFC 8785, section 3.2.3: sorting by UTF-16 code units puts the emoji (surrogate pair) before U+FB33.
	in := `{"\u20ac":"Euro","\r":"CR","\ufb33":"Hebrew","1":"One","\ud83d\ude00":"Emoji","\u0080":"Control","\u00f6":"Latin"}`
	want := "{\"\\r\":\"CR\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin\",\"€\":\"Euro\",\"😀\":\"Emoji\",\"\ufb33\":\"Hebrew\"}"
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestFormatNumber(t *testing.T) {
	cases := map[string]string{
		"0": "0", "-0": "0", "1": "1", "-1": "-1", "4.50": "4.5", "1e21": "1e+21", "1e20": "100000000000000000000",
		"0.000001": "0.000001", "0.0000001": "1e-7", "123e-20": "1.23e-18", "9007199254740992": "9007199254740992",
		"1.5e300": "1.5e+300", "-0.5": "-0.5", "18234": "18234",
	}
	for in, want := range cases {
		got, err := formatNumber(in)
		if err != nil || got != want {
			t.Errorf("formatNumber(%s) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestCanonicalizeRejects(t *testing.T) {
	for name, in := range map[string]string{
		"duplicate key": `{"a":1,"a":2}`,
		"nested dup":    `{"x":{"b":1,"b":1}}`,
		"number range":  `{"n":1e400}`,
		"trailing data": `{"a":1} {"b":2}`,
		"invalid utf8":  "{\"a\":\"\xff\"}",
		"truncated":     `{"a":`,
	} {
		if _, err := Canonicalize([]byte(in)); !errors.Is(err, ErrNotCanonicalizable) {
			t.Errorf("%s: err = %v, want ErrNotCanonicalizable", name, err)
		}
	}
}

func TestCanonicalizeIdempotent(t *testing.T) {
	in := `{"b":[1,2,{"z":true,"a":null}],"a":"x<y>&\u2028"}`
	once, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	twice, err := Canonicalize(once)
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Fatalf("not idempotent:\n%s\n%s", once, twice)
	}
	if want := "{\"a\":\"x<y>&\u2028\",\"b\":[1,2,{\"a\":null,\"z\":true}]}"; string(once) != want {
		t.Fatalf("got %s", once)
	}
}
