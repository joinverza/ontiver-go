package ontiver

import (
	"context"
	"net/http"
)

type VerificationPolicy struct {
	IntervalMonths *int `json:"intervalMonths,omitempty"`
	ReverifyOnRiskChange bool `json:"reverifyOnRiskChange"`
	ReverifyOnContactChange bool `json:"reverifyOnContactChange"`
	ReverifyBeforeHighValue bool `json:"reverifyBeforeHighValue"`
	HighValueThreshold *float64 `json:"highValueThreshold,omitempty"`
	HighValueCurrency string `json:"highValueCurrency"`
	Active bool `json:"active"`
}

func (c *Client) VerificationPolicy(ctx context.Context) (VerificationPolicy, error) {
	var output VerificationPolicy
	err := c.Request(ctx, http.MethodGet, "/verification/policies", nil, &output)
	return output, err
}

func (c *Client) RiskSummary(ctx context.Context) (map[string]any, error) {
	var output map[string]any
	err := c.Request(ctx, http.MethodGet, "/verification-risk/summary", nil, &output)
	return output, err
}

func (c *Client) CostSavings(ctx context.Context, scenario map[string]any) (map[string]any, error) {
	var output map[string]any
	err := c.Request(ctx, http.MethodPost, "/analytics/kyc-cost-savings", scenario, &output)
	return output, err
}
