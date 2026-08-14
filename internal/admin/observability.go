package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxObservabilityResponseBytes = 4 << 20
	maxSeriesRange                = 7 * 24 * time.Hour
	maxSeriesPoints               = int64(2000)
)

var metricQueries = map[string]string{
	"pow_verify_total":    `sum(rate(mirrors_waf_pow_verify_total[5m]))`,
	"pow_allowed_total":   `sum(rate(mirrors_waf_pow_verify_total{result="allow"}[5m]))`,
	"pow_denied_total":    `sum(rate(mirrors_waf_pow_verify_total{result="deny"}[5m]))`,
	"risk_decision_total": `sum(rate(mirrors_waf_risk_decision_total[5m]))`,
	"active_signatures":   `mirrors_waf_storage_active_signatures`,
}

type prometheusClient struct {
	baseURL string
	client  *http.Client
}

func newPrometheusClient(baseURL string, timeout time.Duration) *prometheusClient {
	if strings.TrimSpace(baseURL) == "" {
		return nil
	}
	return &prometheusClient{baseURL: strings.TrimRight(baseURL, "/"), client: &http.Client{Timeout: timeout}}
}

func (c *prometheusClient) queryRange(ctx context.Context, req DashboardSeriesRequest) ([]MetricPointDTO, error) {
	query, ok := metricQueries[req.Metric]
	if !ok {
		return nil, fmt.Errorf("unsupported metric %q", req.Metric)
	}
	from, to, step, err := normalizeSeriesRange(req.From, req.To, req.Step)
	if err != nil {
		return nil, err
	}
	u, err := appendEndpoint(c.baseURL, "/api/v1/query_range")
	if err != nil {
		return nil, err
	}
	values := u.Query()
	values.Set("query", query)
	values.Set("start", strconv.FormatInt(from, 10))
	values.Set("end", strconv.FormatInt(to, 10))
	values.Set("step", strconv.FormatInt(step, 10))
	u.RawQuery = values.Encode()

	var response struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Values [][]json.RawMessage `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := c.getJSON(ctx, u.String(), &response); err != nil {
		return nil, err
	}
	if response.Status != "success" {
		return nil, errors.New("prometheus query failed")
	}

	byTimestamp := make(map[int64]float64)
	for _, series := range response.Data.Result {
		for _, pair := range series.Values {
			if len(pair) != 2 {
				continue
			}
			ts, err := rawFloat(pair[0])
			if err != nil {
				continue
			}
			value, err := rawFloat(pair[1])
			if err != nil {
				continue
			}
			byTimestamp[int64(ts)] += value
		}
	}
	points := make([]MetricPointDTO, 0, len(byTimestamp))
	for ts, value := range byTimestamp {
		points = append(points, MetricPointDTO{Timestamp: ts, Value: value})
	}
	sort.Slice(points, func(i, j int) bool { return points[i].Timestamp < points[j].Timestamp })
	return points, nil
}

func (c *prometheusClient) health(ctx context.Context) error {
	u, err := appendEndpoint(c.baseURL, "/-/ready")
	if err != nil {
		return err
	}
	return c.getStatus(ctx, u.String())
}

func (c *prometheusClient) getJSON(ctx context.Context, rawURL string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	res, err := c.client.Do(req)
	if err != nil {
		return errors.New("prometheus unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New("prometheus unavailable")
	}
	reader := io.LimitReader(res.Body, maxObservabilityResponseBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return errors.New("prometheus response unreadable")
	}
	if len(data) > maxObservabilityResponseBytes {
		return errors.New("prometheus response too large")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("prometheus response invalid")
	}
	return nil
}

func (c *prometheusClient) getStatus(ctx context.Context, rawURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	res, err := c.client.Do(req)
	if err != nil {
		return errors.New("prometheus unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return errors.New("prometheus unavailable")
	}
	return nil
}

type lokiClient struct {
	baseURL string
	query   string
	client  *http.Client
}

func newLokiClient(baseURL, query string, timeout time.Duration) *lokiClient {
	if strings.TrimSpace(baseURL) == "" {
		return nil
	}
	return &lokiClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		query:   query,
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *lokiClient) queryAudit(ctx context.Context, req AuditListRequest) ([]AuditEventDTO, error) {
	from, to, limit, err := normalizeAuditRange(req.From, req.To, req.Limit)
	if err != nil {
		return nil, err
	}
	u, err := appendEndpoint(c.baseURL, "/loki/api/v1/query_range")
	if err != nil {
		return nil, err
	}
	values := u.Query()
	values.Set("query", c.query)
	values.Set("start", strconv.FormatInt(from*int64(time.Second), 10))
	values.Set("end", strconv.FormatInt(to*int64(time.Second), 10))
	values.Set("limit", strconv.Itoa(limit))
	values.Set("direction", "backward")
	u.RawQuery = values.Encode()

	var response struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Values [][]string `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := c.getJSON(ctx, u.String(), &response); err != nil {
		return nil, err
	}
	if response.Status != "success" {
		return nil, errors.New("loki query failed")
	}
	events := make([]AuditEventDTO, 0)
	for _, stream := range response.Data.Result {
		for _, pair := range stream.Values {
			if len(pair) != 2 {
				continue
			}
			event, ok := parseAuditLine(pair[0], pair[1])
			if ok {
				events = append(events, event)
			}
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Timestamp > events[j].Timestamp })
	if len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

func (c *lokiClient) health(ctx context.Context) error {
	u, err := appendEndpoint(c.baseURL, "/ready")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	res, err := c.client.Do(req)
	if err != nil {
		return errors.New("loki unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return errors.New("loki unavailable")
	}
	return nil
}

func (c *lokiClient) getJSON(ctx context.Context, rawURL string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	res, err := c.client.Do(req)
	if err != nil {
		return errors.New("loki unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New("loki unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxObservabilityResponseBytes+1))
	if err != nil {
		return errors.New("loki response unreadable")
	}
	if len(data) > maxObservabilityResponseBytes {
		return errors.New("loki response too large")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("loki response invalid")
	}
	return nil
}

func appendEndpoint(baseURL, endpoint string) (*url.URL, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	u.Path = strings.TrimRight(u.Path, "/") + endpoint
	u.RawQuery = ""
	u.Fragment = ""
	return u, nil
}

func normalizeSeriesRange(from, to, step int64) (int64, int64, int64, error) {
	now := time.Now().Unix()
	if to == 0 {
		to = now
	}
	if from == 0 {
		from = to - int64(time.Hour/time.Second)
	}
	if from >= to {
		return 0, 0, 0, errors.New("from must be before to")
	}
	span := time.Duration(to-from) * time.Second
	if span > maxSeriesRange {
		return 0, 0, 0, errors.New("time range exceeds 7 days")
	}
	if step == 0 {
		step = 60
	}
	if step < 15 {
		step = 15
	}
	minStep := (to - from + maxSeriesPoints - 1) / maxSeriesPoints
	if step < minStep {
		step = minStep
	}
	if step > 3600 {
		return 0, 0, 0, errors.New("step must not exceed 3600 seconds")
	}
	return from, to, step, nil
}

func normalizeAuditRange(from, to int64, limit int) (int64, int64, int, error) {
	now := time.Now().Unix()
	if to == 0 {
		to = now
	}
	if from == 0 {
		from = to - int64(24*time.Hour/time.Second)
	}
	if from >= to {
		return 0, 0, 0, errors.New("from must be before to")
	}
	if time.Duration(to-from)*time.Second > maxSeriesRange {
		return 0, 0, 0, errors.New("time range exceeds 7 days")
	}
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 500 {
		return 0, 0, 0, errors.New("limit must be between 1 and 500")
	}
	return from, to, limit, nil
}

func rawFloat(raw json.RawMessage) (float64, error) {
	var number float64
	if err := json.Unmarshal(raw, &number); err == nil {
		return number, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return 0, err
	}
	return strconv.ParseFloat(text, 64)
}

func parseAuditLine(timestampNS, line string) (AuditEventDTO, bool) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return AuditEventDTO{}, false
	}
	if stringValue(raw["event"]) != "admin_audit" {
		return AuditEventDTO{}, false
	}
	ns, err := strconv.ParseInt(timestampNS, 10, 64)
	if err != nil {
		return AuditEventDTO{}, false
	}
	return AuditEventDTO{
		Timestamp:       ns / int64(time.Second),
		Action:          stringValue(raw["action"]),
		Actor:           stringValue(raw["actor"]),
		RequestID:       stringValue(raw["request_id"]),
		IP:              stringValue(raw["ip"]),
		Target:          stringValue(raw["target_ip_hash"]),
		Source:          stringValue(raw["source"]),
		Reason:          stringValue(raw["reason"]),
		Code:            stringValue(raw["code"]),
		TTLSeconds:      jsonInt64Value(raw["ttl_seconds"]),
		Revision:        uint64(jsonInt64Value(raw["revision"])),
		ChangeCount:     int(jsonInt64Value(raw["change_count"])),
		Danger:          stringValue(raw["danger"]),
		RestartRequired: jsonBoolValue(raw["restart_required"]),
		OK:              jsonBoolValue(raw["ok"]),
		Detail:          stringValue(raw["detail"]),
	}, true
}

func stringValue(v interface{}) string {
	s, _ := v.(string)
	return s
}

func jsonBoolValue(v interface{}) bool {
	b, _ := v.(bool)
	return b
}

func jsonInt64Value(v interface{}) int64 {
	switch value := v.(type) {
	case float64:
		return int64(value)
	case string:
		parsed, _ := strconv.ParseInt(value, 10, 64)
		return parsed
	}
	return 0
}
