package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrNotCanonicalizable is returned for input that has no RFC 8785 canonical form
// (invalid UTF-8, duplicate object keys, numbers outside IEEE 754 double range, trailing data).
var ErrNotCanonicalizable = errors.New("protocol: input cannot be canonicalized")

// Canonicalize returns the JSON Canonicalization Scheme (RFC 8785) form of data.
// Signatures are always computed over this form, so the agent (Go) and CONTIX (TypeScript)
// produce identical bytes for the same message.
func Canonicalize(data []byte) ([]byte, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: invalid UTF-8", ErrNotCanonicalizable)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrNotCanonicalizable)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// parseValue reads one JSON value token by token so duplicate keys can be rejected
// (encoding/json would silently keep the last one).
func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotCanonicalizable, err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("%w: %v", ErrNotCanonicalizable, err)
				}
				key, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("%w: object key is not a string", ErrNotCanonicalizable)
				}
				if _, dup := obj[key]; dup {
					return nil, fmt.Errorf("%w: duplicate key %q", ErrNotCanonicalizable, key)
				}
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			if _, err := dec.Token(); err != nil { // closing '}'
				return nil, fmt.Errorf("%w: %v", ErrNotCanonicalizable, err)
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil { // closing ']'
				return nil, fmt.Errorf("%w: %v", ErrNotCanonicalizable, err)
			}
			return arr, nil
		}
		return nil, fmt.Errorf("%w: unexpected %q", ErrNotCanonicalizable, t)
	default:
		return t, nil // nil, bool, string, json.Number
	}
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		s, err := formatNumber(string(t))
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case string:
		writeString(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("%w: unsupported type %T", ErrNotCanonicalizable, v)
	}
	return nil
}

// lessUTF16 orders object keys by their UTF-16 code units, as RFC 8785 requires.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeString escapes like ECMAScript JSON.stringify: only the mandatory escapes,
// control characters as lower-case \u00xx, everything else as literal UTF-8.
func writeString(buf *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hex[r>>4])
				buf.WriteByte(hex[r&0xf])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// formatNumber serializes a JSON number as ECMAScript Number.prototype.toString does
// (shortest round-trip digits, exponent form outside 1e-7 .. 1e21).
func formatNumber(lit string) (string, error) {
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return "", fmt.Errorf("%w: number %s out of range", ErrNotCanonicalizable, lit)
	}
	if f == 0 {
		return "0", nil // also -0
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±xx
	mant, expPart, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expPart)
	k, n := len(digits), exp+1

	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k), nil
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:], nil
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits, nil
	}
	es := "+"
	if n-1 < 0 {
		es = "-"
	}
	ev := n - 1
	if ev < 0 {
		ev = -ev
	}
	m := digits[:1]
	if k > 1 {
		m += "." + digits[1:]
	}
	return sign + m + "e" + es + strconv.Itoa(ev), nil
}
