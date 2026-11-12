package ontiver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPhoneVerificationPublicV1Contract(t *testing.T) {
	type observed struct {
		method, path, idempotency, body string
	}
	seen := make([]observed, 0, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		seen = append(seen, observed{r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"), string(raw)})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"verificationId":"phone_123","status":"otp_sent","channel":"sms","expiresAt":"2026-09-09T10:10:00Z","resendAfter":"2026-09-09T10:01:00Z","attemptsRemaining":5,"verifiedAt":null,"phoneLast4":"5678"}}`))
	}))
	defer server.Close()

	client, err := New("sb_test", WithBaseURL(server.URL), WithMaxRetries(0))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	created, err := client.PhoneVerifications.Create(ctx, PhoneVerificationRequest{
		Phone: "+2348012345678", Country: "NG", UserID: "user_123", DeviceID: "device_123", WhatsAppConsent: true,
	}, SecurityOptions{IdempotencyKey: "phone-create-123"})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = client.PhoneVerifications.Get(ctx, "phone_123")
	_, _ = client.PhoneVerifications.Verify(ctx, "phone_123", "123456", SecurityOptions{IdempotencyKey: "phone-verify-123"})
	_, _ = client.PhoneVerifications.Resend(ctx, "phone_123", SecurityOptions{IdempotencyKey: "phone-resend-123"})

	if created.VerificationID != "phone_123" {
		t.Fatalf("created = %#v", created)
	}
	wantPaths := []string{
		"/v1/verifications/phone",
		"/v1/verifications/phone/phone_123",
		"/v1/verifications/phone/phone_123/verify",
		"/v1/verifications/phone/phone_123/resend",
	}
	if len(seen) != len(wantPaths) {
		t.Fatalf("requests = %#v", seen)
	}
	for index, want := range wantPaths {
		if seen[index].path != want {
			t.Fatalf("request %d path = %q", index, seen[index].path)
		}
	}
	if !strings.Contains(seen[0].body, `"purpose":"signup"`) || !strings.Contains(seen[0].body, `"whatsappConsent":true`) {
		t.Fatalf("create body = %s", seen[0].body)
	}
	if seen[0].idempotency != "phone-create-123" || seen[2].idempotency != "phone-verify-123" || seen[3].idempotency != "phone-resend-123" {
		t.Fatalf("idempotency headers = %#v", seen)
	}
}

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

func TestIdentityBatchFileValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/banking/enterprise/identity-batches/validate" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatal(err)
		}
		if got := r.FormValue("applicationId"); got != "app_123" {
			t.Fatalf("applicationId = %q", got)
		}
		if got := r.FormValue("requestedFields"); got != `["verificationStatus"]` {
			t.Fatalf("requestedFields = %q", got)
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		raw, err := io.ReadAll(file)
		if err != nil {
			t.Fatal(err)
		}
		if header.Filename != "users.csv" || string(raw) != "externalUserId,email\nC-1,user@example.com\n" {
			t.Fatalf("file = %q %#v", header.Filename, string(raw))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"batchId":"idb_123","status":"validated"}}`))
	}))
	defer server.Close()
	client, err := New("sb_test", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.IdentityBatches.ValidateFile(
		context.Background(),
		"users.csv",
		"text/csv",
		strings.NewReader("externalUserId,email\nC-1,user@example.com\n"),
		IdentityBatchFileOptions{
			ApplicationID:        "app_123",
			Mode:                 "fresh_verification",
			VerificationType:     "nin",
			Purpose:              "Employee verification",
			RequestedFields:      []string{"verificationStatus"},
			NotificationChannels: []string{"email"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result["batchId"] != "idb_123" {
		t.Fatalf("result = %#v", result)
	}
}

func TestIdentityBatchErrorReportDownload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/banking/enterprise/identity-batches/idb_123/errors.csv" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Accept"); got != "text/csv" {
			t.Fatalf("Accept = %q", got)
		}
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("rowNumber,code,message\n2,required,External user ID is required\n"))
	}))
	defer server.Close()
	client, err := New("sb_test", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	report, err := client.IdentityBatches.DownloadErrors(context.Background(), "idb_123", SecurityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "External user ID is required") {
		t.Fatalf("report = %q", string(report))
	}
}

func TestVerifyWebhookSignedDelivery(t *testing.T) {
	// Exactly what the API sends: t=<seconds>,v1=<HMAC-SHA256 of "<t>.<raw body>">.
	payload := []byte(`{"event":"verification.completed","data":{"verificationId":"ver_1"}}`)
	secret := "whsec_test"
	const ts = int64(1800000000)
	sign := func(body []byte, stamp int64) string {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(strconv.FormatInt(stamp, 10) + "."))
		mac.Write(body)
		return hex.EncodeToString(mac.Sum(nil))
	}
	header := "t=" + strconv.FormatInt(ts, 10) + ",v1=" + sign(payload, ts)
	at := time.Unix(ts+30, 0)
	if !VerifyWebhookAt(payload, header, secret, at, DefaultWebhookTolerance) {
		t.Fatal("a valid signed delivery was refused")
	}
	if VerifyWebhookAt(payload, header, secret, time.Unix(ts+301, 0), DefaultWebhookTolerance) {
		t.Fatal("an old delivery was accepted")
	}
	if !VerifyWebhookAt(payload, header, secret, time.Unix(ts+9999, 0), 0) {
		t.Fatal("tolerance 0 should skip the timestamp check")
	}
	if VerifyWebhookAt(append(payload, ' '), header, secret, at, DefaultWebhookTolerance) {
		t.Fatal("a changed body was accepted")
	}
	if VerifyWebhookAt(payload, header, "whsec_other", at, DefaultWebhookTolerance) {
		t.Fatal("the wrong secret was accepted")
	}
	rotating := "t=" + strconv.FormatInt(ts, 10) + ",v1=" + strings.Repeat("0", 64) + ",v1=" + sign(payload, ts)
	if !VerifyWebhookAt(payload, rotating, secret, at, DefaultWebhookTolerance) {
		t.Fatal("any matching v1 should pass")
	}
}
