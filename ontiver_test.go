package ontiver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticationEnvelopeAndResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sb_test" {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.Header.Get("X-Ontiver-API-Secret"); got != "sec_test" {
			t.Fatalf("secret = %q", got)
		}
		if r.URL.Path != "/api/v1/banking/api-keys/validate/current" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"valid":true}}`))
	}))
	defer server.Close()
	client, err := New("sb_test", WithAPISecret("sec_test"), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.APIKeys.ValidateCurrent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result["valid"] != true {
		t.Fatalf("result = %#v", result)
	}
}

func TestAPIErrorAndWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", "req_1")
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"detail":{"code":"invalid_key","message":"Denied"}}`))
	}))
	defer server.Close()
	client, _ := New("bad", WithBaseURL(server.URL), WithMaxRetries(0))
	_, err := client.APIKeys.ValidateCurrent(context.Background())
	apiError, ok := err.(*APIError)
	if !ok || apiError.StatusCode != 401 || apiError.Code != "invalid_key" || apiError.RequestID != "req_1" {
		t.Fatalf("error = %#v", err)
	}
	payload := []byte(`{"eventType":"verification.completed"}`)
	mac := hmac.New(sha256.New, []byte("whsec_test"))
	_, _ = mac.Write(payload)
	if !VerifyWebhook(payload, "sha256="+hex.EncodeToString(mac.Sum(nil)), "whsec_test") {
		t.Fatal("valid signature rejected")
	}
	if VerifyWebhook(payload, "sha256=00", "whsec_test") {
		t.Fatal("invalid signature accepted")
	}
}

func TestRejectsInsecureRemoteBaseURL(t *testing.T) {
	if _, err := New("key", WithBaseURL("http://api.example.com")); err == nil {
		t.Fatal("expected HTTPS validation error")
	}
}
