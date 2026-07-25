package ontiver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type JSON = map[string]any
type SecurityOptions struct {
	IdempotencyKey, Nonce, AdminStepUpToken, ImpersonationToken string
	Timestamp                                                   int64
}

func secure(body any, value SecurityOptions) RequestOptions {
	return RequestOptions{Body: body, IdempotencyKey: value.IdempotencyKey, Nonce: value.Nonce, Timestamp: value.Timestamp, AdminStepUpToken: value.AdminStepUpToken, ImpersonationToken: value.ImpersonationToken, Authenticated: true, Unwrap: true}
}
func read(value SecurityOptions) RequestOptions {
	return RequestOptions{ImpersonationToken: value.ImpersonationToken, Authenticated: true, Unwrap: true}
}
func call[T any](ctx context.Context, client *Client, method, path string, options RequestOptions) (T, error) {
	var output T
	err := client.RequestWithOptions(ctx, method, path, options, &output)
	return output, err
}

type VerificationsService struct{ client *Client }

func (s *VerificationsService) Create(ctx context.Context, payload JSON, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/kyc/individual/verify", secure(payload, options))
}
func (s *VerificationsService) Get(ctx context.Context, id string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/kyc/individual/"+url.PathEscape(id), read(SecurityOptions{}))
}

type ScreeningService struct{ client *Client }

func (s *ScreeningService) PEP(ctx context.Context, payload JSON, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/screening/pep/check", secure(payload, options))
}
func (s *ScreeningService) Sanctions(ctx context.Context, payload JSON, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/screening/sanctions/check", secure(payload, options))
}
func (s *ScreeningService) AdverseMedia(ctx context.Context, payload JSON, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/screening/adverse-media/check", secure(payload, options))
}

type ProofsService struct{ client *Client }

func (s *ProofsService) Generate(ctx context.Context, payload JSON, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/zk-proof/generate", secure(payload, options))
}
func (s *ProofsService) GetForVerification(ctx context.Context, id string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/zk-proof/verification/"+url.PathEscape(id), read(SecurityOptions{}))
}
func (s *ProofsService) Verify(ctx context.Context, payload JSON, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/zk-proof/verify", secure(payload, options))
}
func (s *ProofsService) Disclose(ctx context.Context, payload JSON, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/zk-proof/disclose", secure(payload, options))
}
func (s *ProofsService) Circuits(ctx context.Context) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/zk-proof/circuits", read(SecurityOptions{}))
}
func (s *ProofsService) NoirToolchain(ctx context.Context) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/zk-proof/noir/toolchain", read(SecurityOptions{}))
}
func (s *ProofsService) GenerateNoir(ctx context.Context, payload JSON, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/zk-proof/noir/generate", secure(payload, options))
}
func (s *ProofsService) VerifyNoir(ctx context.Context, payload JSON, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/zk-proof/noir/verify", secure(payload, options))
}

type WebhooksService struct{ client *Client }

func (s *WebhooksService) Register(ctx context.Context, endpoint string, events []string, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/webhooks/register", secure(JSON{"url": endpoint, "events": events, "active": true}, withNonce(options)))
}
func (s *WebhooksService) List(ctx context.Context, active *bool) (JSON, error) {
	q := url.Values{}
	if active != nil {
		q.Set("active", strconv.FormatBool(*active))
	}
	o := read(SecurityOptions{})
	o.Query = q
	return call[JSON](ctx, s.client, http.MethodGet, "/webhooks", o)
}
func (s *WebhooksService) Delete(ctx context.Context, id string, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodDelete, "/webhooks/"+url.PathEscape(id), secure(nil, withNonce(options)))
}
func (s *WebhooksService) Test(ctx context.Context, payload JSON, options SecurityOptions) (JSON, error) {
	path := "/webhooks/test"
	if id, ok := payload["webhookId"].(string); ok && id != "" {
		path = "/webhooks/" + url.PathEscape(id) + "/test"
	}
	return call[JSON](ctx, s.client, http.MethodPost, path, secure(payload, withNonce(options)))
}
func (s *WebhooksService) RotateSecret(ctx context.Context, id string, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/webhooks/"+url.PathEscape(id)+"/rotate-secret", secure(nil, withNonce(options)))
}
func (s *WebhooksService) Retries(ctx context.Context) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/webhooks/retries", read(SecurityOptions{}))
}
func (s *WebhooksService) Deliveries(ctx context.Context, query url.Values) (JSON, error) {
	o := read(SecurityOptions{})
	o.Query = query
	return call[JSON](ctx, s.client, http.MethodGet, "/webhooks/deliveries", o)
}

type AMLService struct{ client *Client }

func (s *AMLService) CreateSmileCheck(ctx context.Context, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/aml/smile-checks", secure(p, o))
}
func (s *AMLService) GetSmileCheck(ctx context.Context, id string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/aml/smile-checks/"+url.PathEscape(id), read(SecurityOptions{}))
}
func (s *AMLService) CreateSmileNews(ctx context.Context, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/aml/smile-news", secure(p, o))
}
func (s *AMLService) GetSmileNews(ctx context.Context, id string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/aml/smile-news/"+url.PathEscape(id), read(SecurityOptions{}))
}
func (s *AMLService) RiskScore(ctx context.Context, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/aml/risk-score", secure(p, o))
}
func (s *AMLService) TransactionMonitoring(ctx context.Context, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/aml/transaction-monitoring", secure(p, o))
}

type OngoingService struct{ client *Client }

func (s *OngoingService) Enable(ctx context.Context, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/ongoing/enable", secure(p, o))
}
func (s *OngoingService) Disable(ctx context.Context, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/ongoing/disable", secure(p, o))
}
func (s *OngoingService) Status(ctx context.Context, id string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/ongoing/"+url.PathEscape(id)+"/status", read(SecurityOptions{}))
}
func (s *OngoingService) Changes(ctx context.Context, id string, limit int) (JSON, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	o := read(SecurityOptions{})
	o.Query = q
	return call[JSON](ctx, s.client, http.MethodGet, "/ongoing/"+url.PathEscape(id)+"/changes", o)
}
func (s *OngoingService) DueReviews(ctx context.Context, limit int) (JSON, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	o := read(SecurityOptions{})
	o.Query = q
	return call[JSON](ctx, s.client, http.MethodGet, "/ongoing/due-reviews", o)
}

type APIKeysService struct{ client *Client }

func (s *APIKeysService) ValidateCurrent(ctx context.Context) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/api-keys/validate/current", read(SecurityOptions{}))
}
func (s *APIKeysService) List(ctx context.Context, q url.Values) (JSON, error) {
	o := read(SecurityOptions{})
	o.Query = q
	return call[JSON](ctx, s.client, http.MethodGet, "/api-keys", o)
}
func (s *APIKeysService) Create(ctx context.Context, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/api-keys/create", secure(p, o))
}
func (s *APIKeysService) Revoke(ctx context.Context, id string, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodDelete, "/api-keys/"+url.PathEscape(id), secure(nil, o))
}

type APISettingsService struct{ client *Client }

func (s *APISettingsService) Get(ctx context.Context) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/api/settings", read(SecurityOptions{}))
}
func (s *APISettingsService) Update(ctx context.Context, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPatch, "/api/settings", secure(p, o))
}

type OIDCClientsService struct{ client *Client }

func (s *OIDCClientsService) List(ctx context.Context) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/oidc/clients", read(SecurityOptions{}))
}
func (s *OIDCClientsService) Create(ctx context.Context, payload JSON, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/oidc/clients", secure(payload, withNonce(options)))
}
func (s *OIDCClientsService) Update(ctx context.Context, clientID string, payload JSON, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPatch, "/oidc/clients/"+url.PathEscape(clientID), secure(payload, withNonce(options)))
}
func (s *OIDCClientsService) Disable(ctx context.Context, clientID string, options SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodDelete, "/oidc/clients/"+url.PathEscape(clientID), secure(nil, withNonce(options)))
}

type DiagnosticsService struct{ client *Client }

func (s *DiagnosticsService) List(ctx context.Context, q url.Values) (JSON, error) {
	o := read(SecurityOptions{})
	o.Query = q
	return call[JSON](ctx, s.client, http.MethodGet, "/diagnostics/requests", o)
}
func (s *DiagnosticsService) Retry(ctx context.Context, id string, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/diagnostics/requests/"+url.PathEscape(id)+"/retry", secure(p, withNonce(o)))
}
func (s *DiagnosticsService) Cancel(ctx context.Context, id string, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/diagnostics/requests/"+url.PathEscape(id)+"/cancel", secure(p, withNonce(o)))
}

type EnterpriseApplicationsService struct{ client *Client }

func (s *EnterpriseApplicationsService) List(ctx context.Context) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/enterprise/applications", read(SecurityOptions{}))
}
func (s *EnterpriseApplicationsService) Get(ctx context.Context, id string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/enterprise/applications/"+url.PathEscape(id), read(SecurityOptions{}))
}
func (s *EnterpriseApplicationsService) Create(ctx context.Context, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/enterprise/applications", secure(p, o))
}
func (s *EnterpriseApplicationsService) Update(ctx context.Context, id string, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPatch, "/enterprise/applications/"+url.PathEscape(id), secure(p, o))
}
func (s *EnterpriseApplicationsService) UploadLogo(ctx context.Context, id, filename, contentType string, file io.Reader, o SecurityOptions) (JSON, error) {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	header := make(textproto.MIMEHeader)
	safeFilename := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\r", "_", "\n", "_").Replace(filename)
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, safeFilename))
	header.Set("Content-Type", contentType)
	part, err := form.CreatePart(header)
	if err != nil {
		return nil, err
	}
	if _, err = io.Copy(part, file); err != nil {
		return nil, err
	}
	if err = form.Close(); err != nil {
		return nil, err
	}
	options := secure(nil, o)
	options.RawBody = body.Bytes()
	options.ContentType = form.FormDataContentType()
	return call[JSON](ctx, s.client, http.MethodPost, "/enterprise/applications/"+url.PathEscape(id)+"/logo", options)
}
func (s *EnterpriseApplicationsService) Usage(ctx context.Context, id string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/enterprise/applications/"+url.PathEscape(id)+"/usage", read(SecurityOptions{}))
}
func (s *EnterpriseApplicationsService) ImportPartnerKYC(ctx context.Context, id string, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/enterprise/applications/"+url.PathEscape(id)+"/kyc-imports", secure(p, o))
}
func (s *EnterpriseApplicationsService) GetKYCImport(ctx context.Context, id, batch string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/enterprise/applications/"+url.PathEscape(id)+"/kyc-imports/"+url.PathEscape(batch), read(SecurityOptions{}))
}
func (s *EnterpriseApplicationsService) ListKYCImports(ctx context.Context, id string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/enterprise/applications/"+url.PathEscape(id)+"/kyc-imports", read(SecurityOptions{}))
}

type DisclosureRequestsService struct{ client *Client }

func (s *DisclosureRequestsService) List(ctx context.Context, q url.Values) (JSON, error) {
	o := read(SecurityOptions{})
	o.Query = q
	return call[JSON](ctx, s.client, http.MethodGet, "/enterprise/disclosure-requests", o)
}
func (s *DisclosureRequestsService) Create(ctx context.Context, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/enterprise/disclosure-requests", secure(p, o))
}
func (s *DisclosureRequestsService) Get(ctx context.Context, id string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/enterprise/disclosure-requests/"+url.PathEscape(id), read(SecurityOptions{}))
}
func (s *DisclosureRequestsService) GetProof(ctx context.Context, id string, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/enterprise/disclosure-requests/"+url.PathEscape(id)+"/proof", secure(nil, o))
}
func (s *DisclosureRequestsService) VerifyProof(ctx context.Context, token string, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/enterprise/disclosure-requests/proofs/verify", secure(JSON{"proofToken": token}, o))
}
func (s *DisclosureRequestsService) ListTemplates(ctx context.Context) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/enterprise/disclosure-requests/templates", read(SecurityOptions{}))
}
func (s *DisclosureRequestsService) CreateTemplate(ctx context.Context, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/enterprise/disclosure-requests/templates", secure(p, o))
}
func (s *DisclosureRequestsService) DeleteTemplate(ctx context.Context, id string, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodDelete, "/enterprise/disclosure-requests/templates/"+url.PathEscape(id), secure(nil, o))
}

type ComplianceService struct{ client *Client }

func (s *ComplianceService) Overview(ctx context.Context) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/enterprise/compliance/overview", read(SecurityOptions{}))
}
func (s *ComplianceService) Case(ctx context.Context, id string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/enterprise/compliance/cases/"+url.PathEscape(id), read(SecurityOptions{}))
}
func (s *ComplianceService) Packet(ctx context.Context, id string) (JSON, error) {
	o := read(SecurityOptions{})
	o.Query = url.Values{"format": {"json"}}
	return call[JSON](ctx, s.client, http.MethodGet, "/enterprise/compliance/packets/"+url.PathEscape(id), o)
}

type ApprovalsService struct{ client *Client }

func (s *ApprovalsService) List(ctx context.Context, q url.Values) (JSON, error) {
	o := read(SecurityOptions{})
	o.Query = q
	return call[JSON](ctx, s.client, http.MethodGet, "/enterprise/approvals", o)
}
func (s *ApprovalsService) Approve(ctx context.Context, id string, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/enterprise/approvals/"+url.PathEscape(id)+"/approve", secure(p, o))
}
func (s *ApprovalsService) Reject(ctx context.Context, id string, p JSON, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/enterprise/approvals/"+url.PathEscape(id)+"/reject", secure(p, o))
}
func (s *ApprovalsService) Cancel(ctx context.Context, id string, o SecurityOptions) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/enterprise/approvals/"+url.PathEscape(id)+"/cancel", secure(nil, o))
}

type VerificationPolicy struct {
	IntervalMonths          *int     `json:"intervalMonths,omitempty"`
	ReverifyOnRiskChange    bool     `json:"reverifyOnRiskChange"`
	ReverifyOnContactChange bool     `json:"reverifyOnContactChange"`
	ReverifyBeforeHighValue bool     `json:"reverifyBeforeHighValue"`
	HighValueThreshold      *float64 `json:"highValueThreshold,omitempty"`
	HighValueCurrency       string   `json:"highValueCurrency"`
	Active                  bool     `json:"active"`
}
type VerificationIntelligenceService struct{ client *Client }

func (s *VerificationIntelligenceService) Policy(ctx context.Context) (VerificationPolicy, error) {
	return call[VerificationPolicy](ctx, s.client, http.MethodGet, "/verification/policies", read(SecurityOptions{}))
}
func (s *VerificationIntelligenceService) UpdatePolicy(ctx context.Context, p JSON, o SecurityOptions) (VerificationPolicy, error) {
	return call[VerificationPolicy](ctx, s.client, http.MethodPatch, "/verification/policies", secure(p, o))
}
func (s *VerificationIntelligenceService) RiskSummary(ctx context.Context) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/verification-risk/summary", read(SecurityOptions{}))
}
func (s *VerificationIntelligenceService) RiskSignals(ctx context.Context, q url.Values) (JSON, error) {
	o := read(SecurityOptions{})
	o.Query = q
	return call[JSON](ctx, s.client, http.MethodGet, "/verification-risk/signals", o)
}
func (s *VerificationIntelligenceService) CostSavings(ctx context.Context, p JSON) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/analytics/kyc-cost-savings", secure(p, SecurityOptions{}))
}

type VerifyWithOntiverService struct{ client *Client }
type AppBoundOptions struct {
	AppID, APISecret, Nonce string
	Timestamp               int64
}

func (s *VerifyWithOntiverService) CreateSession(ctx context.Context, p JSON, o AppBoundOptions) (JSON, error) {
	path := "/enterprise/verification-sessions"
	return s.signed(ctx, http.MethodPost, path, p, o)
}
func (s *VerifyWithOntiverService) GetProof(ctx context.Context, id string, o AppBoundOptions) (JSON, error) {
	return s.signed(ctx, http.MethodGet, "/enterprise/verification-sessions/"+url.PathEscape(id)+"/proof", nil, o)
}
func (s *VerifyWithOntiverService) VerifyProof(ctx context.Context, token string, o AppBoundOptions) (JSON, error) {
	return s.signed(ctx, http.MethodPost, "/enterprise/verification-sessions/proofs/verify", JSON{"proofToken": token}, o)
}
func (s *VerifyWithOntiverService) ImportPartnerKYC(ctx context.Context, records []JSON, source string, o AppBoundOptions) (JSON, error) {
	if source == "" {
		source = "api"
	}
	return s.signed(ctx, http.MethodPost, "/enterprise/applications/"+url.PathEscape(o.AppID)+"/kyc-imports", JSON{"source": source, "records": records}, o)
}
func (s *VerifyWithOntiverService) signed(ctx context.Context, method, path string, body any, o AppBoundOptions) (JSON, error) {
	headers, err := appHeaders(method, path, body, o)
	if err != nil {
		return nil, err
	}
	return call[JSON](ctx, s.client, method, path, RequestOptions{Body: body, Headers: headers, Authenticated: true, Unwrap: true})
}

func appHeaders(method, path string, body any, o AppBoundOptions) (http.Header, error) {
	if o.Timestamp == 0 {
		o.Timestamp = time.Now().Unix()
	}
	if o.Nonce == "" {
		var err error
		o.Nonce, err = randomID("")
		if err != nil {
			return nil, err
		}
	}
	raw := []byte{}
	if body != nil {
		var err error
		raw, err = stableJSON(body)
		if err != nil {
			return nil, err
		}
	}
	bodyHash := sha256.Sum256(raw)
	canonical := strings.Join([]string{strings.ToUpper(method), "/api/v1/banking" + path, strconv.FormatInt(o.Timestamp, 10), o.Nonce, o.AppID, hex.EncodeToString(bodyHash[:])}, "\n")
	mac := hmac.New(sha256.New, []byte(o.APISecret))
	_, _ = mac.Write([]byte(canonical))
	return http.Header{"X-Ontiver-App-Id": {o.AppID}, "X-Ontiver-Timestamp": {strconv.FormatInt(o.Timestamp, 10)}, "X-Ontiver-Nonce": {o.Nonce}, "X-Ontiver-Signature": {hex.EncodeToString(mac.Sum(nil))}}, nil
}
func stableJSON(value any) ([]byte, error) {
	var normalized any
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &normalized); err != nil {
		return nil, err
	}
	return []byte(stableValue(normalized)), nil
}
func stableValue(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case string:
		raw, _ := json.Marshal(v)
		return string(raw)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "true"
		}
		return "false"
	case []any:
		parts := make([]string, len(v))
		for i, item := range v {
			parts[i] = stableValue(item)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			k, _ := json.Marshal(key)
			parts = append(parts, string(k)+":"+stableValue(v[key]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		raw, _ := json.Marshal(v)
		return string(raw)
	}
}
func withNonce(o SecurityOptions) SecurityOptions {
	if o.Nonce == "" {
		o.Nonce, _ = randomID("")
	}
	if o.Timestamp == 0 {
		o.Timestamp = time.Now().Unix()
	}
	return o
}
