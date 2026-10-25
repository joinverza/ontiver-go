package ontiver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkflowsContract(t *testing.T) {
	type observed struct {
		method, path, query, body string
	}
	seen := make([]observed, 0, 6)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		seen = append(seen, observed{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, string(raw)})
		switch {
		case strings.HasSuffix(r.URL.Path, "/export.csv"):
			w.Header().Set("Content-Type", "text/csv")
			_, _ = w.Write([]byte("caseId,status\ncase_1,verified\n"))
		case strings.HasSuffix(r.URL.Path, "/record.pdf"):
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = w.Write([]byte("%PDF-1.4"))
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"data":{"caseId":"case_1","items":[],"nextCursor":null}}`))
		}
	}))
	defer server.Close()

	client, err := New("sb_test", WithBaseURL(server.URL), WithMaxRetries(0))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := client.Workflows.Create(ctx, CreateWorkflowCase{TemplateKey: "ng-financial-onboarding", Purpose: "Loan application", SubjectEmail: "ada@example.com", RespondByDays: 14}); err != nil {
		t.Fatal(err)
	}
	var created map[string]any
	if err := json.Unmarshal([]byte(seen[0].body), &created); err != nil {
		t.Fatal(err)
	}
	if seen[0].path != "/api/v1/banking/workflow-platform/cases" || !strings.HasPrefix(created["idempotencyKey"].(string), "ontiver-go-") || created["respondByDays"].(float64) != 14 {
		t.Fatalf("create sent %+v", seen[0])
	}
	if _, ok := created["subjectId"]; ok {
		t.Fatal("empty fields must be left out")
	}

	if _, err := client.Workflows.List(ctx, WorkflowCaseQuery{Status: "review_required", Assigned: "unassigned"}); err != nil {
		t.Fatal(err)
	}
	if seen[1].query != "assigned=unassigned&status=review_required" {
		t.Fatalf("list query %q", seen[1].query)
	}

	csv, err := client.Workflows.ExportCSV(ctx, "", "", "")
	if err != nil || string(csv) != "caseId,status\ncase_1,verified\n" {
		t.Fatalf("csv %q %v", csv, err)
	}
	pdf, err := client.Workflows.RecordPDF(ctx, "case_1")
	if err != nil || string(pdf) != "%PDF-1.4" {
		t.Fatalf("pdf %q %v", pdf, err)
	}

	if _, err := client.Workflows.Assign(ctx, "case_1", ""); err != nil {
		t.Fatal(err)
	}
	if last := seen[len(seen)-1]; last.body != `{"assignee":null}` {
		t.Fatalf("unassign body %q", last.body)
	}

	if _, err := client.Workflows.CustomerStatus(ctx, "CUST 1/2"); err != nil {
		t.Fatal(err)
	}
	if last := seen[len(seen)-1]; last.path != "/api/v1/banking/workflow-platform/customers/CUST%201%2F2" {
		t.Fatalf("customer path %q", last.path)
	}
}
