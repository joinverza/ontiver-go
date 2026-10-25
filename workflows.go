package ontiver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// WorkflowsService sends verification requests: a person verifies with consent, each check is
// recorded, and a person at your business always makes the final decision.
type WorkflowsService struct{ client *Client }

// WorkflowCaseQuery filters the request list. Assigned is "unassigned" or a reviewer's email.
type WorkflowCaseQuery struct {
	Status, Cursor, Search, Assigned string
	Limit                            int
}

// CreateWorkflowCase asks one person to verify. With SubjectEmail they are emailed their own
// link; RespondByDays (1-180) sets the deadline, with reminders 3 days and 1 day before.
type CreateWorkflowCase struct {
	TemplateKey      string `json:"templateKey"`
	Purpose          string `json:"purpose"`
	SubjectEmail     string `json:"subjectEmail,omitempty"`
	SubjectID        string `json:"subjectId,omitempty"`
	SubjectReference string `json:"subjectReference,omitempty"`
	RespondByDays    int    `json:"respondByDays,omitempty"`
	IdempotencyKey   string `json:"idempotencyKey"`
}

// WorkflowRecipient is one person in a bulk request.
type WorkflowRecipient struct {
	Email     string `json:"email"`
	Reference string `json:"reference,omitempty"`
}

// CreateWorkflowCases sends the same request to many people; each is decided separately.
type CreateWorkflowCases struct {
	TemplateKey    string              `json:"templateKey"`
	Purpose        string              `json:"purpose"`
	Recipients     []WorkflowRecipient `json:"recipients"`
	RespondByDays  int                 `json:"respondByDays,omitempty"`
	IdempotencyKey string              `json:"idempotencyKey"`
}

// WorkflowStepResult records the outcome of a check your team carried out.
type WorkflowStepResult struct {
	Status            string `json:"status"`
	Provider          string `json:"provider,omitempty"`
	ResultCode        string `json:"resultCode,omitempty"`
	Reason            string `json:"reason,omitempty"`
	EvidenceReference string `json:"evidenceReference,omitempty"`
}

// CustomerImportRow is one existing customer. Lane is attested, request or at_next_login;
// attested rows need AttestedAt (when you verified them yourself).
type CustomerImportRow struct {
	Reference        string `json:"reference,omitempty"`
	Email            string `json:"email,omitempty"`
	Lane             string `json:"lane"`
	AttestedAt       string `json:"attestedAt,omitempty"`
	AttestedProvider string `json:"attestedProvider,omitempty"`
}

// CustomerImport brings in customers you already have.
type CustomerImport struct {
	TemplateKey string              `json:"templateKey"`
	Purpose     string              `json:"purpose"`
	RespondDays int                 `json:"respondDays,omitempty"`
	GraceDays   int                 `json:"graceDays,omitempty"`
	Customers   []CustomerImportRow `json:"customers"`
}

func casePath(caseID, suffix string) string {
	return "/workflow-platform/cases/" + url.PathEscape(caseID) + suffix
}

func withKey(key string) (string, error) {
	if key != "" {
		return key, nil
	}
	return randomID("ontiver-go-")
}

func query(values map[string]string) url.Values {
	q := url.Values{}
	for name, value := range values {
		if value != "" {
			q.Set(name, value)
		}
	}
	return q
}

func (s *WorkflowsService) Templates(ctx context.Context, includeRetired bool) (JSON, error) {
	o := read(SecurityOptions{})
	if includeRetired {
		o.Query = url.Values{"includeRetired": {"true"}}
	}
	return call[JSON](ctx, s.client, http.MethodGet, "/workflow-platform/templates", o)
}
func (s *WorkflowsService) Summary(ctx context.Context) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/workflow-platform/cases/summary", read(SecurityOptions{}))
}
func (s *WorkflowsService) List(ctx context.Context, q WorkflowCaseQuery) (JSON, error) {
	o := read(SecurityOptions{})
	limit := ""
	if q.Limit > 0 {
		limit = strconv.Itoa(q.Limit)
	}
	o.Query = query(map[string]string{"status": q.Status, "cursor": q.Cursor, "search": q.Search, "assigned": q.Assigned, "limit": limit})
	return call[JSON](ctx, s.client, http.MethodGet, "/workflow-platform/cases", o)
}
func (s *WorkflowsService) Get(ctx context.Context, caseID string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, casePath(caseID, ""), read(SecurityOptions{}))
}
func (s *WorkflowsService) Create(ctx context.Context, input CreateWorkflowCase) (JSON, error) {
	key, err := withKey(input.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	input.IdempotencyKey = key
	return call[JSON](ctx, s.client, http.MethodPost, "/workflow-platform/cases", secure(input, SecurityOptions{}))
}
func (s *WorkflowsService) CreateBulk(ctx context.Context, input CreateWorkflowCases) (JSON, error) {
	key, err := withKey(input.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	input.IdempotencyKey = key
	return call[JSON](ctx, s.client, http.MethodPost, "/workflow-platform/cases/bulk", secure(input, SecurityOptions{}))
}

// Review records your decision: decision is approved, rejected or review_required.
func (s *WorkflowsService) Review(ctx context.Context, caseID, decision, reason, riskLevel string) (JSON, error) {
	if riskLevel == "" {
		riskLevel = "low"
	}
	return call[JSON](ctx, s.client, http.MethodPost, casePath(caseID, "/review"), secure(JSON{"decision": decision, "reason": reason, "riskLevel": riskLevel}, SecurityOptions{}))
}
func (s *WorkflowsService) RecordStepResult(ctx context.Context, caseID, stepKey string, result WorkflowStepResult) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, casePath(caseID, "/steps/"+url.PathEscape(stepKey)), secure(result, SecurityOptions{}))
}

// RecordAssistedConsent records consent your operator took from the person (in a branch or on a call).
func (s *WorkflowsService) RecordAssistedConsent(ctx context.Context, caseID string, approved bool, attestation string, scope []string) (JSON, error) {
	if scope == nil {
		scope = []string{}
	}
	return call[JSON](ctx, s.client, http.MethodPost, casePath(caseID, "/consent"), secure(JSON{"approved": approved, "scope": scope, "attestation": attestation}, SecurityOptions{}))
}
func (s *WorkflowsService) Cancel(ctx context.Context, caseID, reason string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, casePath(caseID, "/cancel"), secure(JSON{"reason": reason}, SecurityOptions{}))
}
func (s *WorkflowsService) Revoke(ctx context.Context, caseID, reason string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, casePath(caseID, "/revoke"), secure(JSON{"reason": reason}, SecurityOptions{}))
}
func (s *WorkflowsService) Renew(ctx context.Context, caseID string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, casePath(caseID, "/renew"), secure(nil, SecurityOptions{}))
}

// ResendInvite emails a new link to someone who hasn't approved yet. The old link stops working.
func (s *WorkflowsService) ResendInvite(ctx context.Context, caseID string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, casePath(caseID, "/resend-invite"), secure(nil, SecurityOptions{}))
}

// Assign gives the request to a reviewer on your team; an empty assignee returns it to the shared queue.
func (s *WorkflowsService) Assign(ctx context.Context, caseID, assignee string) (JSON, error) {
	var value any
	if assignee != "" {
		value = assignee
	}
	return call[JSON](ctx, s.client, http.MethodPost, casePath(caseID, "/assign"), secure(JSON{"assignee": value}, SecurityOptions{}))
}
func (s *WorkflowsService) SetDeadline(ctx context.Context, caseID string, respondBy time.Time) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, casePath(caseID, "/deadline"), secure(JSON{"respondBy": respondBy.UTC().Format(time.RFC3339)}, SecurityOptions{}))
}
func (s *WorkflowsService) Reviewers(ctx context.Context) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/workflow-platform/reviewers", read(SecurityOptions{}))
}

// FileLink returns a short-lived link to a document the person uploaded. Opening it is recorded
// and the person sees it. Disposition is view or download.
func (s *WorkflowsService) FileLink(ctx context.Context, caseID, fileID, disposition, reason string) (JSON, error) {
	if disposition == "" {
		disposition = "view"
	}
	body := JSON{"disposition": disposition}
	if reason != "" {
		body["reason"] = reason
	}
	return call[JSON](ctx, s.client, http.MethodPost, casePath(caseID, "/files/"+url.PathEscape(fileID)+"/link"), secure(body, SecurityOptions{}))
}

// ExportCSV returns every request with its decision, as CSV. Status, since and until may be empty.
func (s *WorkflowsService) ExportCSV(ctx context.Context, status, since, until string) ([]byte, error) {
	return s.client.download(ctx, "/workflow-platform/cases/export.csv", query(map[string]string{"status": status, "since": since, "until": until}), "text/csv")
}

// RecordPDF returns a PDF record of one request: consent, every check, the decision and the timeline.
func (s *WorkflowsService) RecordPDF(ctx context.Context, caseID string) ([]byte, error) {
	return s.client.download(ctx, casePath(caseID, "/record.pdf"), nil, "application/pdf")
}
func (s *WorkflowsService) ListBatches(ctx context.Context, limit int) (JSON, error) {
	o := read(SecurityOptions{})
	if limit > 0 {
		o.Query = url.Values{"limit": {strconv.Itoa(limit)}}
	}
	return call[JSON](ctx, s.client, http.MethodGet, "/workflow-platform/batches", o)
}
func (s *WorkflowsService) GetBatch(ctx context.Context, batchID string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/workflow-platform/batches/"+url.PathEscape(batchID), read(SecurityOptions{}))
}

// CancelBatch cancels every request in the batch that is still open. Decided ones are kept.
func (s *WorkflowsService) CancelBatch(ctx context.Context, batchID, reason string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/workflow-platform/batches/"+url.PathEscape(batchID)+"/cancel", secure(JSON{"reason": reason}, SecurityOptions{}))
}

// ResendUnopened emails a fresh link to everyone in the batch who hasn't opened their invite.
func (s *WorkflowsService) ResendUnopened(ctx context.Context, batchID string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/workflow-platform/batches/"+url.PathEscape(batchID)+"/resend-unopened", secure(nil, SecurityOptions{}))
}
func (s *WorkflowsService) ImportCustomers(ctx context.Context, input CustomerImport) (JSON, error) {
	if input.RespondDays == 0 {
		input.RespondDays = 14
	}
	if input.GraceDays == 0 {
		input.GraceDays = 30
	}
	return call[JSON](ctx, s.client, http.MethodPost, "/workflow-platform/customer-imports", secure(input, SecurityOptions{}))
}
func (s *WorkflowsService) ListCustomerImports(ctx context.Context) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/workflow-platform/customer-imports", read(SecurityOptions{}))
}
func (s *WorkflowsService) GetCustomerImport(ctx context.Context, importID, lane string, limit, offset int) (JSON, error) {
	o := read(SecurityOptions{})
	values := map[string]string{"lane": lane}
	if limit > 0 {
		values["limit"] = strconv.Itoa(limit)
	}
	if offset > 0 {
		values["offset"] = strconv.Itoa(offset)
	}
	o.Query = query(values)
	return call[JSON](ctx, s.client, http.MethodGet, "/workflow-platform/customer-imports/"+url.PathEscape(importID), o)
}

// SendCustomerWave sends requests to the next customers in the request lane (up to 500 at a time).
func (s *WorkflowsService) SendCustomerWave(ctx context.Context, importID string, count int) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/workflow-platform/customer-imports/"+url.PathEscape(importID)+"/waves", secure(JSON{"count": count}, SecurityOptions{}))
}

// CustomerStatus tells you, at a customer's sign-in or checkout, whether they need to verify and
// whether it is required yet.
func (s *WorkflowsService) CustomerStatus(ctx context.Context, reference string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/workflow-platform/customers/"+url.PathEscape(reference), read(SecurityOptions{}))
}

// StartCustomerVerification starts (or continues) the customer's request; inviteUrl opens it in the Ontiver app.
func (s *WorkflowsService) StartCustomerVerification(ctx context.Context, reference string) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodPost, "/workflow-platform/customers/"+url.PathEscape(reference)+"/start", secure(nil, SecurityOptions{}))
}

// SandboxPersonas lists test people: invite one of these emails in sandbox to get a known response.
func (s *WorkflowsService) SandboxPersonas(ctx context.Context) (JSON, error) {
	return call[JSON](ctx, s.client, http.MethodGet, "/workflow-platform/sandbox/personas", read(SecurityOptions{}))
}

// download fetches a file the API returns (CSV, PDF) with the client's authentication and retries.
func (c *Client) download(ctx context.Context, path string, q url.Values, accept string) ([]byte, error) {
	requestURL, err := c.resolveURL(path, q)
	if err != nil {
		return nil, err
	}
	options := read(SecurityOptions{})
	attempts := c.MaxRetries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if requestErr != nil {
			return nil, requestErr
		}
		c.setHeaders(req, options)
		req.Header.Set("Accept", accept)
		response, requestErr := c.HTTP.Do(req)
		if requestErr != nil {
			if attempt+1 < attempts {
				if waitErr := waitRetry(ctx, attempt, 0); waitErr != nil {
					return nil, waitErr
				}
				continue
			}
			return nil, fmt.Errorf("ontiver: network request failed: %w", requestErr)
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, 25<<20))
		response.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if retryable(response.StatusCode) && attempt+1 < attempts {
			if waitErr := waitRetry(ctx, attempt, retryAfter(response.Header)); waitErr != nil {
				return nil, waitErr
			}
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil, decodeAPIError(response, raw)
		}
		return raw, nil
	}
	return nil, fmt.Errorf("ontiver: request failed")
}
