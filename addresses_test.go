package ontiver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAddressesRoutesAndPayloads(t *testing.T) {
	type observed struct {
		method, path, rawQuery, idempotency string
		body                                map[string]any
	}
	seen := make([]observed, 0, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		seen = append(seen, observed{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Get("Idempotency-Key"), body})
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/addresses/verifications" && r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"success":true,"data":{"verificationId":"adv_1","status":"verified","score":100,"reasonCodes":[],"checks":[],"postcode":null,"declaredAddress":{"line1":"NTA Road"},"source":"sandbox","createdAt":"2026-10-04T10:00:00Z"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"data":{"postcode":"EK-01-A03-FK-01","items":[]}}`))
	}))
	defer server.Close()

	client, err := New("sb_test", WithBaseURL(server.URL), WithMaxRetries(0))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	point := Coordinates{Lat: 7.6233, Lng: 5.2209}
	record, err := client.Addresses.LookupPostcode(ctx, "EK 01 A03 FK 01", PostcodeDetailBuilding)
	if err != nil || record.Postcode != "EK-01-A03-FK-01" {
		t.Fatalf("lookup = %#v, %v", record, err)
	}
	_, _ = client.Addresses.AutocompletePostcode(ctx, "EK 01 A")
	_, _ = client.Addresses.ReverseGeocode(ctx, point, 0)
	_, _ = client.Addresses.NearbyPostcodes(ctx, point, 200)
	result, err := client.Addresses.Verify(ctx, AddressVerificationRequest{
		Address:     DeclaredAddress{Line1: "NTA Road", State: "Ekiti", Postcode: "EK-01-A03-FK-01"},
		Coordinates: &point,
		Reference:   "cust_42",
	}, SecurityOptions{IdempotencyKey: "addr-verify-42"})
	if err != nil || result.Status != AddressVerified {
		t.Fatalf("verify = %#v, %v", result, err)
	}
	_, _ = client.Addresses.GetVerification(ctx, "adv_1")
	_, _ = client.Addresses.ListVerifications(ctx, AddressVerificationListOptions{Limit: 10, Reference: "cust_42"})
	_, _ = client.Addresses.Usage(ctx, 7)

	want := []struct{ method, path, query string }{
		{"GET", "/v1/addresses/postcodes/EK%2001%20A03%20FK%2001", "detail=building"},
		{"GET", "/v1/addresses/postcodes/autocomplete", "q=EK+01+A"},
		{"GET", "/v1/addresses/postcodes/reverse", "lat=7.6233&lng=5.2209"},
		{"GET", "/v1/addresses/postcodes/nearby", "lat=7.6233&lng=5.2209&radius=200"},
		{"POST", "/v1/addresses/verifications", ""},
		{"GET", "/v1/addresses/verifications/adv_1", ""},
		{"GET", "/v1/addresses/verifications", "limit=10&reference=cust_42"},
		{"GET", "/v1/addresses/usage", "days=7"},
	}
	if len(seen) != len(want) {
		t.Fatalf("requests = %#v", seen)
	}
	for index, expected := range want {
		got := seen[index]
		if got.method != expected.method || got.path != expected.path || got.rawQuery != expected.query {
			t.Fatalf("request %d = %s %s?%s, want %s %s?%s", index, got.method, got.path, got.rawQuery, expected.method, expected.path, expected.query)
		}
	}
	if seen[4].idempotency != "addr-verify-42" {
		t.Fatalf("idempotency = %q", seen[4].idempotency)
	}
	address := seen[4].body["address"].(map[string]any)
	if address["country"] != "NG" || address["postcode"] != "EK-01-A03-FK-01" || seen[4].body["reference"] != "cust_42" {
		t.Fatalf("verify body = %#v", seen[4].body)
	}
}
