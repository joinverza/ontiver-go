# Ontiver Go SDK

Official server-side SDK for Go 1.22 and later. It covers identity verification, enterprise CSV/XLSX identity batches, SmileID-backed AML, screening, proofs, disclosure requests, registered applications, webhooks, diagnostics, approvals, API security settings, and Verify with Ontiver sessions.

```bash
go get github.com/joinverza/ontiver-go@latest
```

```go
package main

import (
    "context"
    "log"

    ontiver "github.com/joinverza/ontiver-go"
)

func main() {
    client, err := ontiver.NewFromEnv()
    if err != nil { log.Fatal(err) }

    result, err := client.Verifications.Create(context.Background(), ontiver.JSON{
        "customerId": "cust_123",
        "firstName": "Ada",
        "lastName": "Okafor",
        "country": "NG",
    }, ontiver.SecurityOptions{IdempotencyKey: "verify-cust-123"})
    if err != nil { log.Fatal(err) }
    log.Println(result["verificationId"])

    phone, err := client.PhoneVerifications.Create(context.Background(), ontiver.PhoneVerificationRequest{
        Phone: "+2348012345678",
        Country: "NG",
        Purpose: ontiver.PhoneVerificationSignup,
        UserID: "user_123",
    }, ontiver.SecurityOptions{IdempotencyKey: "phone-signup-user-123"})
    if err != nil { log.Fatal(err) }

    verified, err := client.PhoneVerifications.Verify(context.Background(), phone.VerificationID, "123456", ontiver.SecurityOptions{
        IdempotencyKey: "phone-confirm-user-123",
    })
    if err != nil { log.Fatal(err) }
    log.Println(verified.Status)
}
```

Required server environment:

```bash
ONTIVER_API_KEY=sb_xxx
ONTIVER_API_SECRET=sec_xxx
ONTIVER_BASE_URL=https://api.ontiver.com
```

The client sends bearer authentication, supports idempotent retries, redacts secrets from API errors, rejects non-local HTTP base URLs, verifies webhook HMAC signatures, and signs app-bound Verify with Ontiver requests. Never embed these credentials in browser or mobile applications.

## Verification Requests

Ask a person to verify with consent; Ontiver emails their link and reminds them before the deadline. A person at your business makes the final decision.

```go
request, err := client.Workflows.Create(ctx, ontiver.CreateWorkflowCase{
    TemplateKey:   "ng-financial-onboarding",
    Purpose:       "Loan application LOAN-2026-0193",
    SubjectEmail:  "ada@example.com",
    RespondByDays: 14,
})
if err != nil { log.Fatal(err) }

caseID := request["caseId"].(string)
_, err = client.Workflows.Review(ctx, caseID, "approved", "Identity and address confirmed", "low")
pdf, err := client.Workflows.RecordPDF(ctx, caseID)
```

Also available: `CreateBulk`, `CancelBatch`, `ResendUnopened`, `ImportCustomers`, `SendCustomerWave`, `CustomerStatus` and `ExportCSV`.
