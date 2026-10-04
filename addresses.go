package ontiver

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// PostcodeDetail selects how much of the NIPOST record a lookup returns.
type PostcodeDetail string

const (
	// PostcodeDetailValidation reports whether the postcode is registered. Free.
	PostcodeDetailValidation PostcodeDetail = "validation"
	// PostcodeDetailAddress adds the administrative area and the most recent address on record.
	PostcodeDetailAddress PostcodeDetail = "address"
	// PostcodeDetailBuilding adds the building's recorded use.
	PostcodeDetailBuilding PostcodeDetail = "building"
)

type AddressVerificationStatus string

const (
	AddressVerified        AddressVerificationStatus = "verified"
	AddressNeedsReview     AddressVerificationStatus = "needs_review"
	AddressNotMatched      AddressVerificationStatus = "not_matched"
	AddressInvalidPostcode AddressVerificationStatus = "invalid_postcode"
)

type PostcodeSegments struct {
	State    string `json:"state"`
	LGA      string `json:"lga"`
	District string `json:"district"`
	Area     string `json:"area"`
	Unit     string `json:"unit"`
}

type AdministrativeArea struct {
	State            *string `json:"state"`
	LGA              *string `json:"lga"`
	Locality         *string `json:"locality"`
	GeopoliticalZone *string `json:"geopoliticalZone,omitempty"`
}

type PostcodeRecord struct {
	Postcode           string              `json:"postcode"`
	Display            string              `json:"display"`
	Compact            string              `json:"compact"`
	Segments           PostcodeSegments    `json:"segments"`
	Valid              bool                `json:"valid"`
	Detail             PostcodeDetail      `json:"detail"`
	Source             string              `json:"source"`
	AdministrativeArea *AdministrativeArea `json:"administrativeArea,omitempty"`
	Address            *string             `json:"address,omitempty"`
	BuildingUse        *string             `json:"buildingUse,omitempty"`
	LookupID           string              `json:"lookupId,omitempty"`
	CreatedAt          string              `json:"createdAt,omitempty"`
}

type PostcodeSuggestions struct {
	Query       string  `json:"query"`
	Segment     *string `json:"segment"`
	Suggestions []struct {
		Postcode string `json:"postcode"`
		Label    string `json:"label"`
	} `json:"suggestions"`
}

type Coordinates struct {
	Lat float64 `json:"lat"`
	Lng float64 `json:"lng"`
}

type PostcodeUnit struct {
	Postcode           string             `json:"postcode"`
	Display            string             `json:"display"`
	DistanceMeters     *float64           `json:"distanceMeters"`
	Confidence         *string            `json:"confidence"`
	AdministrativeArea AdministrativeArea `json:"administrativeArea"`
	Address            *string            `json:"address"`
}

type ReverseGeocodeResult struct {
	Found       bool          `json:"found"`
	Coordinates Coordinates   `json:"coordinates"`
	Unit        *PostcodeUnit `json:"unit"`
}

type NearbyPostcodes struct {
	Coordinates  Coordinates    `json:"coordinates"`
	RadiusMeters int            `json:"radiusMeters"`
	Items        []PostcodeUnit `json:"items"`
}

type DeclaredAddress struct {
	Line1    string `json:"line1"`
	Line2    string `json:"line2,omitempty"`
	City     string `json:"city,omitempty"`
	LGA      string `json:"lga,omitempty"`
	State    string `json:"state,omitempty"`
	Postcode string `json:"postcode,omitempty"`
	Country  string `json:"country,omitempty"`
}

type AddressVerificationRequest struct {
	Address     DeclaredAddress `json:"address"`
	Coordinates *Coordinates    `json:"coordinates,omitempty"`
	Reference   string          `json:"reference,omitempty"`
}

type AddressVerificationCheck struct {
	Check           string   `json:"check"`
	Result          string   `json:"result"`
	ReasonCode      *string  `json:"reasonCode"`
	Message         string   `json:"message"`
	Similarity      *float64 `json:"similarity,omitempty"`
	DistanceMeters  *float64 `json:"distanceMeters,omitempty"`
	NearestPostcode string   `json:"nearestPostcode,omitempty"`
}

type AddressVerification struct {
	VerificationID  string                     `json:"verificationId"`
	Status          AddressVerificationStatus  `json:"status"`
	Score           *int                       `json:"score"`
	ReasonCodes     []string                   `json:"reasonCodes"`
	Checks          []AddressVerificationCheck `json:"checks"`
	Postcode        *PostcodeRecord            `json:"postcode"`
	DeclaredAddress DeclaredAddress            `json:"declaredAddress"`
	Reference       *string                    `json:"reference"`
	Source          string                     `json:"source"`
	CreatedAt       string                     `json:"createdAt"`
}

type AddressVerificationList struct {
	Items []AddressVerification `json:"items"`
}

type AddressVerificationListOptions struct {
	Limit     int
	Reference string
	Status    AddressVerificationStatus
}

type AddressUsage struct {
	PeriodDays            int            `json:"periodDays"`
	Environment           string         `json:"environment"`
	Totals                map[string]int `json:"totals"`
	LookupsByDetail       map[string]int `json:"lookupsByDetail"`
	VerificationsByStatus map[string]int `json:"verificationsByStatus"`
	MaximumDetail         PostcodeDetail `json:"maximumDetail"`
}

// AddressesService looks up Nigerian postcodes and verifies declared addresses against the NIPOST register.
type AddressesService struct{ client *Client }

func readQuery(query url.Values) RequestOptions {
	options := read(SecurityOptions{})
	options.Query = query
	return options
}

func coordinateQuery(point Coordinates) url.Values {
	return url.Values{
		"lat": {strconv.FormatFloat(point.Lat, 'f', -1, 64)},
		"lng": {strconv.FormatFloat(point.Lng, 'f', -1, 64)},
	}
}

// LookupPostcode accepts any spelling: "EK-01-A03-FK-01", "EK 01 A03 FK 01" or "EK01A03FK01".
func (s *AddressesService) LookupPostcode(ctx context.Context, postcode string, detail PostcodeDetail) (PostcodeRecord, error) {
	if detail == "" {
		detail = PostcodeDetailValidation
	}
	path := "/v1/addresses/postcodes/" + url.PathEscape(strings.TrimSpace(postcode))
	return call[PostcodeRecord](ctx, s.client, http.MethodGet, path, readQuery(url.Values{"detail": {string(detail)}}))
}

func (s *AddressesService) AutocompletePostcode(ctx context.Context, query string) (PostcodeSuggestions, error) {
	return call[PostcodeSuggestions](ctx, s.client, http.MethodGet, "/v1/addresses/postcodes/autocomplete", readQuery(url.Values{"q": {query}}))
}

// ReverseGeocode finds the postcode unit at a location. maxDistance is in metres (0 uses the default of 25).
func (s *AddressesService) ReverseGeocode(ctx context.Context, point Coordinates, maxDistance int) (ReverseGeocodeResult, error) {
	query := coordinateQuery(point)
	if maxDistance > 0 {
		query.Set("maxDistance", strconv.Itoa(maxDistance))
	}
	return call[ReverseGeocodeResult](ctx, s.client, http.MethodGet, "/v1/addresses/postcodes/reverse", readQuery(query))
}

// NearbyPostcodes lists units within radius metres (0 uses the default and maximum of 300).
func (s *AddressesService) NearbyPostcodes(ctx context.Context, point Coordinates, radius int) (NearbyPostcodes, error) {
	query := coordinateQuery(point)
	if radius > 0 {
		query.Set("radius", strconv.Itoa(radius))
	}
	return call[NearbyPostcodes](ctx, s.client, http.MethodGet, "/v1/addresses/postcodes/nearby", readQuery(query))
}

// Verify checks a declared address against the postcode register. Provide Address.Postcode or Coordinates.
func (s *AddressesService) Verify(ctx context.Context, payload AddressVerificationRequest, options SecurityOptions) (AddressVerification, error) {
	if payload.Address.Country == "" {
		payload.Address.Country = "NG"
	}
	return call[AddressVerification](ctx, s.client, http.MethodPost, "/v1/addresses/verifications", secure(payload, options))
}

func (s *AddressesService) GetVerification(ctx context.Context, id string) (AddressVerification, error) {
	return call[AddressVerification](ctx, s.client, http.MethodGet, "/v1/addresses/verifications/"+url.PathEscape(id), read(SecurityOptions{}))
}

func (s *AddressesService) ListVerifications(ctx context.Context, options AddressVerificationListOptions) (AddressVerificationList, error) {
	query := url.Values{}
	if options.Limit > 0 {
		query.Set("limit", strconv.Itoa(options.Limit))
	}
	if options.Reference != "" {
		query.Set("reference", options.Reference)
	}
	if options.Status != "" {
		query.Set("status", string(options.Status))
	}
	return call[AddressVerificationList](ctx, s.client, http.MethodGet, "/v1/addresses/verifications", readQuery(query))
}

func (s *AddressesService) Usage(ctx context.Context, days int) (AddressUsage, error) {
	query := url.Values{}
	if days > 0 {
		query.Set("days", strconv.Itoa(days))
	}
	return call[AddressUsage](ctx, s.client, http.MethodGet, "/v1/addresses/usage", readQuery(query))
}
