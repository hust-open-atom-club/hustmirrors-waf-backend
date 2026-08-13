package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	promdto "github.com/prometheus/client_model/go"
)

// Snapshot is the small, stable metric surface consumed by the admin API.
type Snapshot struct {
	PowVerifyTotal    float64
	PowAllowedTotal   float64
	PowDeniedTotal    float64
	RiskDecisionTotal float64
	ActiveSignatures  float64
}

// Snapshot returns current process counters without exposing arbitrary
// Prometheus queries. It reads this container directly, so it remains correct
// even when another container was already registered in the default registry.
func (c *Container) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	var out Snapshot
	collect(c.PowVerifyTotal, func(m *promdto.Metric) {
		value := m.GetCounter().GetValue()
		out.PowVerifyTotal += value
		for _, label := range m.GetLabel() {
			if label.GetName() != "result" {
				continue
			}
			switch label.GetValue() {
			case "allow":
				out.PowAllowedTotal += value
			case "deny":
				out.PowDeniedTotal += value
			}
		}
	})
	collect(c.RiskDecisionTotal, func(m *promdto.Metric) {
		out.RiskDecisionTotal += m.GetCounter().GetValue()
	})
	collect(c.ActiveSignatures, func(m *promdto.Metric) {
		out.ActiveSignatures = m.GetGauge().GetValue()
	})
	return out
}

func collect(collector prometheus.Collector, visit func(*promdto.Metric)) {
	if collector == nil {
		return
	}
	ch := make(chan prometheus.Metric)
	go func() {
		collector.Collect(ch)
		close(ch)
	}()
	for metric := range ch {
		var dto promdto.Metric
		if err := metric.Write(&dto); err == nil {
			visit(&dto)
		}
	}
}
