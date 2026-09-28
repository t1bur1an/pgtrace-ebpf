package sqlcomment

import (
	"fmt"
	"strings"
	"testing"
)

const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func TestParseValid(t *testing.T) {
	sql := "SELECT * FROM orders WHERE id = $1 /*application='shop',route='%2Forders%2F%3Aid',traceparent='" + tp + "',tracestate='congo%3Dt61rcWkgMzE'*/ ;\n"
	c, ok := Parse(sql)
	if !ok || !c.Valid || c.TraceParent != tp || c.TraceState != "congo=t61rcWkgMzE" {
		t.Fatalf("got %+v ok=%v", c, ok)
	}
	if c.Attrs["application"] != "shop" || c.Attrs["route"] != "/orders/:id" {
		t.Fatalf("attrs %v", c.Attrs)
	}
	if _, has := c.Attrs["traceparent"]; has {
		t.Fatal("traceparent must not be an attribute")
	}
}

func TestEscapedQuote(t *testing.T) {
	c, ok := Parse(`select 1 /*controller='it\'s',traceparent='` + tp + `'*/`)
	if !ok || c.Attrs["controller"] != "it's" || !c.Valid {
		t.Fatalf("got %+v", c)
	}
}

func TestNoTrailingComment(t *testing.T) {
	for _, sql := range []string{
		"select 1",
		"/*traceparent='" + tp + "'*/ select 1",               // leading, not trailing
		"select '/*traceparent=''" + tp + "''*/' from t",      // inside a string literal
		"select 1 /*traceparent='" + tp + "'*/ and more text", // comment not at the end
		"select 1 /* unterminated",
	} {
		if c, ok := Parse(sql); ok && c.Valid {
			t.Errorf("Parse(%q) = %+v, want no trace context", sql, c)
		}
	}
}

func TestMalformedTraceparent(t *testing.T) {
	for _, bad := range []string{
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",    // missing flags
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", // uppercase
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // version ff
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", // zero trace id
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", // zero span id
		"00-4bf92f3577b34da6a3ce929d0e0e473-600f067aa0ba902b7-01", // wrong lengths
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902bz-01", // not hex
	} {
		c, ok := Parse("select 1 /*traceparent='" + bad + "'*/")
		if !ok || c.Valid {
			t.Errorf("%s: ok=%v valid=%v", bad, ok, c.Valid)
		}
	}
}

func TestAttributeLimits(t *testing.T) {
	var kv []string
	for i := 0; i < 15; i++ {
		kv = append(kv, fmt.Sprintf("k%d='v'", i))
	}
	kv = append(kv, "Bad Key='x'", "ok_key='"+strings.Repeat("é", 300)+"'")
	c, ok := Parse("select 1 /*" + strings.Join(kv, ",") + "*/")
	if !ok || len(c.Attrs) > MaxAttrs {
		t.Fatalf("%d attrs", len(c.Attrs))
	}
	if _, has := c.Attrs["Bad Key"]; has {
		t.Fatal("invalid key accepted")
	}
	for _, v := range c.Attrs {
		if len(v) > MaxValue {
			t.Fatalf("value %d bytes", len(v))
		}
	}
}
