// Package ontiver provides the official server-side Go client for Ontiver.
package ontiver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://api.ontiver.com"
	userAgent      = "ontiver-go/0.1.2"
)

// Client is safe for concurrent use. APIKey and APISecret must only be used in
// trusted server-side code.
type Client struct {
	APIKey      string
	APISecret   string
	BaseURL     string
	HTTP        *http.Client
	MaxRetries  int
	Environment string

	Verifications            *VerificationsService
	PhoneVerifications       *PhoneVerificationsService
	Addresses                *AddressesService
	Screening                *ScreeningService
	Proofs                   *ProofsService
	Webhooks                 *WebhooksService
	AML                      *AMLService
	Ongoing                  *OngoingService
	APIKeys                  *APIKeysService
	APISettings              *APISettingsService
	Diagnostics              *DiagnosticsService
	EnterpriseApplications   *EnterpriseApplicationsService
	IdentityBatches          *IdentityBatchesService
	DisclosureRequests       *DisclosureRequestsService
	Compliance               *ComplianceService
	Approvals                *ApprovalsService
	VerifyWithOntiver        *VerifyWithOntiverService
	VerificationIntelligence *VerificationIntelligenceService
	OIDCClients              *OIDCClientsService
	Workflows                *WorkflowsService
}

// Option customizes a client.
type Option func(*Client) error

func WithAPISecret(secret string) Option {
	return func(c *Client) error { c.APISecret = strings.TrimSpace(secret); return nil }
}
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) error {
		if client == nil {
			return errors.New("ontiver: HTTP client cannot be nil")
		}
		c.HTTP = client
		return nil
	}
}
func WithMaxRetries(value int) Option {
	return func(c *Client) error {
		if value < 0 {
			return errors.New("ontiver: max retries cannot be negative")
		}
		c.MaxRetries = value
		return nil
	}
}
func WithBaseURL(value string) Option {
	return func(c *Client) error {
		normalized, err := normalizeBaseURL(value)
		if err != nil {
			return err
		}
		c.BaseURL = normalized
		return nil
	}
}
func WithEnvironment(value string) Option {
	return func(c *Client) error {
		environment := strings.ToLower(strings.TrimSpace(value))
		if environment != "production" && environment != "sandbox" {
			return errors.New("ontiver: environment must be production or sandbox")
		}
		c.Environment = environment
		return nil
	}
}

// New creates an authenticated client.
func New(apiKey string, options ...Option) (*Client, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("ontiver: API key is required")
	}
	key := strings.TrimSpace(apiKey)
	environment := "production"
	if strings.HasPrefix(key, "sb_") {
		environment = "sandbox"
	}
	c := &Client{APIKey: key, BaseURL: defaultBaseURL, HTTP: &http.Client{Timeout: 30 * time.Second}, MaxRetries: 2, Environment: environment}
	for _, option := range options {
		if err := option(c); err != nil {
			return nil, err
		}
	}
	if (strings.HasPrefix(c.APIKey, "sb_") && c.Environment == "production") ||
		(strings.HasPrefix(c.APIKey, "prod_") && c.Environment == "sandbox") {
		return nil, errors.New("ontiver: API key prefix does not match the configured environment")
	}
	c.initServices()
	return c, nil
}

// NewFromEnv reads ONTIVER_API_KEY, ONTIVER_API_SECRET, ONTIVER_ENVIRONMENT,
// and ONTIVER_BASE_URL.
func NewFromEnv(options ...Option) (*Client, error) {
	baseOptions := []Option{WithAPISecret(os.Getenv("ONTIVER_API_SECRET"))}
	if value := strings.TrimSpace(os.Getenv("ONTIVER_BASE_URL")); value != "" {
		baseOptions = append(baseOptions, WithBaseURL(value))
	}
	if value := strings.TrimSpace(os.Getenv("ONTIVER_ENVIRONMENT")); value != "" {
		baseOptions = append(baseOptions, WithEnvironment(value))
	}
	return New(os.Getenv("ONTIVER_API_KEY"), append(baseOptions, options...)...)
}

func (c *Client) initServices() {
	c.Verifications = &VerificationsService{client: c}
	c.PhoneVerifications = &PhoneVerificationsService{client: c}
	c.Addresses = &AddressesService{client: c}
	c.Screening = &ScreeningService{client: c}
	c.Proofs = &ProofsService{client: c}
	c.Webhooks = &WebhooksService{client: c}
	c.AML = &AMLService{client: c}
	c.Ongoing = &OngoingService{client: c}
	c.APIKeys = &APIKeysService{client: c}
	c.APISettings = &APISettingsService{client: c}
	c.Diagnostics = &DiagnosticsService{client: c}
	c.EnterpriseApplications = &EnterpriseApplicationsService{client: c}
	c.IdentityBatches = &IdentityBatchesService{client: c}
	c.DisclosureRequests = &DisclosureRequestsService{client: c}
	c.Compliance = &ComplianceService{client: c}
	c.Approvals = &ApprovalsService{client: c}
	c.VerifyWithOntiver = &VerifyWithOntiverService{client: c}
	c.VerificationIntelligence = &VerificationIntelligenceService{client: c}
	c.OIDCClients = &OIDCClientsService{client: c}
	c.Workflows = &WorkflowsService{client: c}
}

// RequestOptions controls an API request.
type RequestOptions struct {
	Body               any
	RawBody            []byte
	ContentType        string
	Query              url.Values
	Headers            http.Header
	IdempotencyKey     string
	Nonce              string
	Timestamp          int64
	AdminStepUpToken   string
	ImpersonationToken string
	Authenticated      bool
	Unwrap             bool
}

// APIError contains the stable API error details returned by Ontiver.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("ontiver: %s (status=%d, code=%s, request_id=%s)", redact(e.Message), e.StatusCode, e.Code, e.RequestID)
}
func (e *APIError) Is(target error) bool {
	other, ok := target.(*APIError)
	return ok && (other.StatusCode == 0 || other.StatusCode == e.StatusCode)
}

// Request preserves the original SDK API and sends an authenticated JSON request.
func (c *Client) Request(ctx context.Context, method, path string, input any, output any) error {
	return c.RequestWithOptions(ctx, method, path, RequestOptions{Body: input, Authenticated: true, Unwrap: true}, output)
}

// RequestWithOptions sends a request and decodes its JSON response.
func (c *Client) RequestWithOptions(ctx context.Context, method, path string, options RequestOptions, output any) error {
	if c == nil || c.HTTP == nil {
		return errors.New("ontiver: client is not initialized")
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return errors.New("ontiver: HTTP method is required")
	}
	requestURL, err := c.resolveURL(path, options.Query)
	if err != nil {
		return err
	}
	body, err := marshalBody(options.Body)
	if err != nil {
		return err
	}
	if options.RawBody != nil {
		body = options.RawBody
	}
	mutating := method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
	if mutating && options.IdempotencyKey == "" {
		options.IdempotencyKey, err = randomID("ontiver-go-")
		if err != nil {
			return err
		}
	}
	attempts := 1
	if !mutating || options.IdempotencyKey != "" {
		attempts += c.MaxRetries
	}
	for attempt := 0; attempt < attempts; attempt++ {
		req, reqErr := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(body))
		if reqErr != nil {
			return reqErr
		}
		c.setHeaders(req, options)
		res, doErr := c.HTTP.Do(req)
		if doErr != nil {
			if attempt+1 < attempts {
				if err := waitRetry(ctx, attempt, 0); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("ontiver: network request failed: %w", doErr)
		}
		raw, readErr := io.ReadAll(io.LimitReader(res.Body, 10<<20))
		res.Body.Close()
		if readErr != nil {
			return readErr
		}
		if retryable(res.StatusCode) && attempt+1 < attempts {
			if err := waitRetry(ctx, attempt, retryAfter(res.Header)); err != nil {
				return err
			}
			continue
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return decodeAPIError(res, raw)
		}
		if output == nil || res.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(raw)) == 0 {
			return nil
		}
		if options.Unwrap {
			raw = unwrapData(raw)
		}
		if err := json.Unmarshal(raw, output); err != nil {
			return fmt.Errorf("ontiver: decode response: %w", err)
		}
		return nil
	}
	return errors.New("ontiver: request failed")
}

func (c *Client) setHeaders(req *http.Request, options RequestOptions) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if options.Body != nil || options.RawBody != nil {
		contentType := options.ContentType
		if contentType == "" {
			contentType = "application/json"
		}
		req.Header.Set("Content-Type", contentType)
	}
	for key, values := range options.Headers {
		if strings.EqualFold(key, "Authorization") {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if options.Authenticated {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
		if c.APISecret != "" {
			req.Header.Set("X-Ontiver-API-Secret", c.APISecret)
		}
	}
	if options.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", options.IdempotencyKey)
	}
	if options.Nonce != "" {
		req.Header.Set("X-Ontiver-Nonce", options.Nonce)
	}
	if options.Timestamp != 0 {
		req.Header.Set("X-Ontiver-Timestamp", strconv.FormatInt(options.Timestamp, 10))
	}
	if options.AdminStepUpToken != "" {
		req.Header.Set("X-Ontiver-Admin-Step-Up-Token", options.AdminStepUpToken)
	}
	if options.ImpersonationToken != "" {
		req.Header.Set("X-Ontiver-Impersonation-Token", options.ImpersonationToken)
	}
}

func (c *Client) resolveURL(path string, query url.Values) (string, error) {
	if !strings.HasPrefix(path, "/") {
		return "", errors.New("ontiver: API path must start with '/'")
	}
	if !strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/v1/") {
		path = "/api/v1/banking" + path
	}
	u, err := url.Parse(strings.TrimRight(c.BaseURL, "/") + path)
	if err != nil {
		return "", err
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func normalizeBaseURL(value string) (string, error) {
	value = strings.TrimRight(strings.TrimSpace(value), "/")
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", errors.New("ontiver: base URL must be an absolute HTTP(S) URL")
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "0.0.0.0"
	if u.Scheme != "https" && !local {
		return "", errors.New("ontiver: HTTPS is required for non-local base URLs")
	}
	return value, nil
}

func marshalBody(value any) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("ontiver: encode request: %w", err)
	}
	return raw, nil
}
func unwrapData(raw []byte) []byte {
	var envelope struct {
		Data    json.RawMessage `json:"data"`
		Success *bool           `json:"success"`
	}
	if json.Unmarshal(raw, &envelope) == nil && envelope.Success != nil && len(envelope.Data) > 0 {
		return envelope.Data
	}
	return raw
}
func retryable(code int) bool {
	return code == 408 || code == 429 || code == 500 || code == 502 || code == 503 || code == 504
}
func retryAfter(header http.Header) time.Duration {
	value := header.Get("Retry-After")
	seconds, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	if seconds > 5 {
		seconds = 5
	}
	return time.Duration(seconds) * time.Second
}
func waitRetry(ctx context.Context, attempt int, requested time.Duration) error {
	delay := requested
	if delay == 0 {
		delay = time.Duration(250*(1<<attempt)) * time.Millisecond
		if delay > 2*time.Second {
			delay = 2 * time.Second
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func randomID(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw), nil
}

func decodeAPIError(res *http.Response, raw []byte) error {
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	detail := body["detail"]
	if detail == nil {
		detail = body["error"]
	}
	if detail == nil {
		detail = body["message"]
	}
	message := "Ontiver API request failed"
	code := ""
	if record, ok := detail.(map[string]any); ok {
		if value, ok := record["message"].(string); ok {
			message = value
		}
		if value, ok := record["detail"].(string); ok {
			message = value
		}
		if value, ok := record["code"].(string); ok {
			code = value
		}
	} else if value, ok := detail.(string); ok {
		message = value
	}
	return &APIError{StatusCode: res.StatusCode, Code: code, Message: message, RequestID: res.Header.Get("X-Request-Id")}
}

func redact(value string) string {
	for _, prefix := range []string{"Bearer ", "prod_", "sb_", "sec_", "whsec_"} {
		if index := strings.Index(value, prefix); index >= 0 {
			end := index + len(prefix)
			for end < len(value) && !strings.ContainsRune(" \t\r\n,;\"'", rune(value[end])) {
				end++
			}
			value = value[:index] + "[REDACTED]" + value[end:]
		}
	}
	return value
}

// VerifyWebhook verifies an HMAC-SHA256 webhook signature over the raw body.
func VerifyWebhook(payload []byte, signature, secret string) bool {
	if secret == "" {
		return false
	}
	signature = strings.TrimPrefix(strings.TrimSpace(signature), "sha256=")
	provided, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return hmac.Equal(mac.Sum(nil), provided)
}
