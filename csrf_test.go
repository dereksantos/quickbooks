package quickbooks

import (
	"testing"
)

func TestCSRF(t *testing.T) {
	csrf, err := CSRF(32)
	if err != nil {
		t.Error(err)
		return
	}

	t.Logf("CSRF: %s", csrf)
	if len(csrf) != 32 {
		t.Error("Generated CSRF was not correct length")
	}
}
