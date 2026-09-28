// Package sqlcomment reads SQLCommenter comments (https://google.github.io/sqlcommenter/)
// that applications append to their SQL, most importantly the W3C trace
// context that links a query to the application's trace.
package sqlcomment

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	MaxAttrs = 10  // most non-trace-context keys kept
	MaxValue = 256 // most bytes of one value
)

// Comment is a parsed trailing SQLCommenter comment.
type Comment struct {
	TraceParent string            // valid W3C traceparent, or "" if absent/invalid
	TraceState  string            // tracestate, only with a valid traceparent
	Attrs       map[string]string // other keys
	Valid       bool              // TraceParent is present and well-formed
	HadContext  bool              // a traceparent key was present (valid or not)
}

var (
	keyRE         = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)
	traceparentRE = regexp.MustCompile(`^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)
)

// Parse returns the comment at the very end of sql (after trailing whitespace
// and semicolons). ok is false if there is none.
func Parse(sql string) (c Comment, ok bool) {
	s := strings.TrimRight(sql, " \t\r\n;")
	if !strings.HasSuffix(s, "*/") {
		return c, false
	}
	start := strings.LastIndex(s[:len(s)-2], "/*")
	if start < 0 {
		return c, false
	}
	pairs, ok := parsePairs(s[start+2 : len(s)-2])
	if !ok {
		return c, false
	}
	c.Attrs = map[string]string{}
	for _, kv := range pairs {
		switch kv[0] {
		case "traceparent":
			c.HadContext = true
			if validTraceparent(kv[1]) {
				c.TraceParent, c.Valid = kv[1], true
			}
		case "tracestate":
			c.TraceState = kv[1]
		default:
			if keyRE.MatchString(kv[0]) && len(c.Attrs) < MaxAttrs {
				c.Attrs[kv[0]] = clean(kv[1])
			}
		}
	}
	if !c.Valid {
		c.TraceState = ""
	}
	return c, true
}

// parsePairs splits `key='value',key='value'`, URL-decoding both and
// unescaping \' in values.
func parsePairs(body string) ([][2]string, bool) {
	var out [][2]string
	s := strings.TrimSpace(body)
	for len(s) > 0 {
		eq := strings.IndexByte(s, '=')
		if eq <= 0 || eq+1 >= len(s) || s[eq+1] != '\'' {
			return nil, false
		}
		key := strings.TrimSpace(s[:eq])
		var val strings.Builder
		i := eq + 2
		for ; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) && s[i+1] == '\'' {
				val.WriteByte('\'')
				i++
				continue
			}
			if s[i] == '\'' {
				break
			}
			val.WriteByte(s[i])
		}
		if i >= len(s) {
			return nil, false // unterminated value
		}
		k, err1 := url.PathUnescape(key)
		v, err2 := url.PathUnescape(val.String())
		if err1 != nil || err2 != nil {
			return nil, false
		}
		out = append(out, [2]string{k, v})
		s = strings.TrimSpace(s[i+1:])
		if strings.HasPrefix(s, ",") {
			s = strings.TrimSpace(s[1:])
		} else if s != "" {
			return nil, false
		}
	}
	return out, len(out) > 0
}

func validTraceparent(v string) bool {
	m := traceparentRE.FindStringSubmatch(v)
	if m == nil || m[1] == "ff" {
		return false
	}
	return strings.Trim(m[2], "0") != "" && strings.Trim(m[3], "0") != ""
}

// clean bounds a value to MaxValue bytes on a rune boundary, valid UTF-8.
func clean(s string) string {
	if len(s) > MaxValue {
		cut := MaxValue
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return strings.ToValidUTF8(s, "�")
}
