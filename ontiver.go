package ontiver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	APIKey  string
	BaseURL string
	HTTP    *http.Client
}

func New(apiKey string) (*Client, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("ontiver: API key is required")
	}
	return &Client{APIKey: apiKey, BaseURL: "https://api.ontiver.com/api/v1/banking", HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (c *Client) Request(ctx context.Context, method, path string, input any, output any) error {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil { return err }
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+"/"+strings.TrimLeft(path, "/"), body)
	if err != nil { return err }
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.APIKey)
	res, err := c.HTTP.Do(req)
	if err != nil { return err }
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 10<<20))
	if err != nil { return err }
	if res.StatusCode < 200 || res.StatusCode >= 300 { return fmt.Errorf("ontiver: HTTP %d: %s", res.StatusCode, string(raw)) }
	var envelope struct { Data json.RawMessage `json:"data"` }
	if err := json.Unmarshal(raw, &envelope); err == nil && len(envelope.Data) > 0 { raw = envelope.Data }
	if output == nil { return nil }
	return json.Unmarshal(raw, output)
}

func VerifyWebhook(payload []byte, signature, secret string) bool {
	signature = strings.TrimPrefix(strings.TrimSpace(signature), "sha256=")
	provided, err := hex.DecodeString(signature)
	if err != nil { return false }
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return hmac.Equal(mac.Sum(nil), provided)
}
