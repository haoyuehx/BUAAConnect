package easyconnect

import (
	"strings"
	"testing"
)

func TestRedactSecretHidesCredentialValue(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	redacted := redactSecret("TWFID", secret)
	if strings.Contains(redacted, secret) {
		t.Fatalf("redacted value leaks the secret: %q", redacted)
	}
	if !strings.Contains(redacted, "TWFID") || !strings.Contains(redacted, "redacted") {
		t.Fatalf("redacted value = %q, want label and redaction marker", redacted)
	}

	if got := redactSecret("Token", ""); strings.Contains(got, "<unset>") == false {
		t.Fatalf("empty secret redaction = %q, want unset marker", got)
	}
}
