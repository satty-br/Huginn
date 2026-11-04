package main

import (
	"os"
	"path/filepath"
	"testing"
)

// --- Regression tests for bugs fixed in this change -----------------------

// IsResponseSuccessful used to dereference response.StatusCode directly,
// which panicked whenever Get/Post/GetAuth returned nil (a network error,
// timeout, or malformed request) -- a routine occurrence given this package
// probes dozens of third-party APIs. It must now return false instead.
func TestIsResponseSuccessful_NilResponse(t *testing.T) {
	v := &Validator{}
	if v.IsResponseSuccessful(nil) {
		t.Error("IsResponseSuccessful(nil) = true, want false")
	}
}

// FindAWSRegion used to compile a regex with a lookbehind assertion
// ("(?<=AWS_REGIOn=)"), which Go's RE2-based regexp engine does not support.
// regexp.MustCompile panics on it, which crashed the whole program the
// moment an aws-access-token secret was processed. It must compile and
// correctly extract the region now.
func TestFindAWSRegion(t *testing.T) {
	v := &Validator{}

	t.Run("finds a region", func(t *testing.T) {
		path := writeTempFile(t, "AWS_REGION=us-east-1\nAWS_ACCESS_KEY_ID=AKIAEXAMPLE\n")
		if got := v.FindAWSRegion(path); got != "us-east-1" {
			t.Errorf("FindAWSRegion() = %q, want %q", got, "us-east-1")
		}
	})

	t.Run("finds a quoted region", func(t *testing.T) {
		path := writeTempFile(t, `AWS_REGION="eu-west-2"`)
		if got := v.FindAWSRegion(path); got != "eu-west-2" {
			t.Errorf("FindAWSRegion() = %q, want %q", got, "eu-west-2")
		}
	})

	t.Run("no region present", func(t *testing.T) {
		path := writeTempFile(t, "NOTHING_HERE=1")
		if got := v.FindAWSRegion(path); got != "" {
			t.Errorf("FindAWSRegion() = %q, want empty string", got)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if got := v.FindAWSRegion(filepath.Join(t.TempDir(), "missing.env")); got != "" {
			t.Errorf("FindAWSRegion() = %q, want empty string", got)
		}
	})
}

// AWSTokenTest used to return false whenever a paired "generic-api-key"
// secret WAS found in the same file ("if len(keys) > 0 { return false }"),
// the exact opposite of what it needs to actually run the signed request.
func TestAWSTokenTest_RequiresPairedKeyAndRegion(t *testing.T) {
	path := writeTempFile(t, "AWS_REGION=us-east-1\n")
	awsSecret := Secret{File: path, RuleID: "aws-access-token", Secret: "AKIAEXAMPLE"}

	t.Run("no paired generic-api-key secret", func(t *testing.T) {
		v := &Validator{Secrets: []Secret{awsSecret}}
		if v.AWSTokenTest(awsSecret) {
			t.Error("AWSTokenTest() = true, want false (no paired secret key available)")
		}
	})

	t.Run("no region in file", func(t *testing.T) {
		noRegionPath := writeTempFile(t, "NOTHING_HERE=1")
		secret := Secret{File: noRegionPath, RuleID: "aws-access-token", Secret: "AKIAEXAMPLE"}
		pair := Secret{File: noRegionPath, RuleID: "generic-api-key", Secret: "sekritsekritsekritsekritsekrit1"}
		v := &Validator{Secrets: []Secret{secret, pair}}
		if v.AWSTokenTest(secret) {
			t.Error("AWSTokenTest() = true, want false (no AWS_REGION in file)")
		}
	})
}

// --- Helper / utility coverage ---------------------------------------------

func TestFindSecretInFile(t *testing.T) {
	secrets := []Secret{
		{File: "a.env", RuleID: "linkedin-client-id", Secret: "id-123"},
		{File: "a.env", RuleID: "linkedin-client-secret", Secret: "secret-456"},
		{File: "b.env", RuleID: "linkedin-client-secret", Secret: "other-file-secret"},
	}
	v := &Validator{Secrets: secrets}

	if got := v.FindSecretInFile("a.env", "linkedin-client-secret"); got != "secret-456" {
		t.Errorf("FindSecretInFile() = %q, want %q", got, "secret-456")
	}
	if got := v.FindSecretInFile("a.env", "looker-client-id"); got != "" {
		t.Errorf("FindSecretInFile() = %q, want empty string for an absent rule id", got)
	}
	if got := v.FindSecretInFile("missing-file.env", "linkedin-client-secret"); got != "" {
		t.Errorf("FindSecretInFile() = %q, want empty string for an absent file", got)
	}
}

func TestGenericAuth(t *testing.T) {
	v := &Validator{}
	got := v.GenericAuth("Bearer", "abc123")
	want := "Bearer abc123"
	if got["Authorization"] != want {
		t.Errorf("GenericAuth() Authorization = %q, want %q", got["Authorization"], want)
	}

	if got := v.DefaultBearer("abc123")["Authorization"]; got != "Bearer abc123" {
		t.Errorf("DefaultBearer() = %q, want %q", got, "Bearer abc123")
	}
	if got := v.DefaultBasic("abc123")["Authorization"]; got != "Basic abc123" {
		t.Errorf("DefaultBasic() = %q, want %q", got, "Basic abc123")
	}
}

func TestFileSearch(t *testing.T) {
	v := &Validator{}
	path := writeTempFile(t, "line one\nhttps://my-shop.myshopify.com/admin\nline three\n")
	secret := Secret{File: path}

	got := v.FileSearch(secret, `[a-z0-9-]+\.myshopify\.com`)
	if got != "my-shop.myshopify.com" {
		t.Errorf("FileSearch() = %q, want %q", got, "my-shop.myshopify.com")
	}

	if got := v.FileSearch(secret, `not-present-anywhere`); got != "" {
		t.Errorf("FileSearch() = %q, want empty string for no match", got)
	}

	missing := Secret{File: filepath.Join(t.TempDir(), "missing.txt")}
	if got := v.FileSearch(missing, `.*`); got != "" {
		t.Errorf("FileSearch() = %q, want empty string for a missing file", got)
	}
}

func TestMailchimpAPIKey_DatacenterParsing(t *testing.T) {
	v := &Validator{}
	// No dash, no datacenter suffix to parse: must not panic and must fail closed.
	if v.MailchimpAPIKey(Secret{Secret: "nodatacenterkey"}) {
		t.Error("MailchimpAPIKey() = true, want false when the key has no datacenter suffix")
	}
}

func TestValidate_UnknownRuleIDReturnsFalse(t *testing.T) {
	v := &Validator{}
	if v.Validate(Secret{RuleID: "some-rule-id-with-no-validator", Secret: "x"}) {
		t.Error("Validate() = true, want false for a RuleID with no registered validator")
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret.env")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}
