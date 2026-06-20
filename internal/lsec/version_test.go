package lsec

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommandPrintsSingleBinaryMetadata(t *testing.T) {
	var out bytes.Buffer
	t.Setenv("LSEC_HOME", t.TempDir())

	err := Run([]string{"version"}, strings.NewReader(""), &out, &out)
	if err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "lsec ") {
		t.Fatalf("version output = %q, want lsec prefix", got)
	}
	if !strings.Contains(got, "commit=") || !strings.Contains(got, "date=") {
		t.Fatalf("version output = %q, want commit/date metadata", got)
	}
}
