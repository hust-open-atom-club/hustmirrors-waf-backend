package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Container bundles every metric the application emits. All fields are
// read-only after construction.
type Container struct {
	PowVerifyTotal          *prometheus.CounterVec
	PowVerifyLatencySeconds *prometheus.HistogramVec
	RiskDecisionTotal       *prometheus.CounterVec
	StorageOperations       *prometheus.CounterVec
	StorageLatencySeconds   *prometheus.HistogramVec
	ActiveSignatures        prometheus.Gauge
	// PendingAutoBlocks counts automatic temporary blocks triggered by the
	// per-IP pending limit.
	PendingAutoBlocks prometheus.Counter
	// PowFlags exposes runtime switches (enabled, dry_run, bypass_all) as
	// 0/1 gauges so dashboards and alerts do not have to infer them.
	PowFlags *prometheus.GaugeVec
}

func New() *Container {
	return &Container{
		PowVerifyTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "mirrors_waf",
			Subsystem: "pow",
			Name:      "verify_total",
			Help:      "Total number of /verify_pow calls by result/reason/mode/protected.",
		}, []string{"result", "reason", "mode", "protected"}),

		PowVerifyLatencySeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "mirrors_waf",
			Subsystem: "pow",
			Name:      "verify_latency_seconds",
			Help:      "Wall-clock latency of /verify_pow calls.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"mode"}),

		RiskDecisionTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "mirrors_waf",
			Subsystem: "risk",
			Name:      "decision_total",
			Help:      "Total risk-engine decisions by target/reason.",
		}, []string{"target", "reason"}),

		StorageOperations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "mirrors_waf",
			Subsystem: "storage",
			Name:      "operations_total",
			Help:      "Storage-layer operations by driver/operation/outcome.",
		}, []string{"driver", "operation", "outcome"}),

		StorageLatencySeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "mirrors_waf",
			Subsystem: "storage",
			Name:      "latency_seconds",
			Help:      "Storage-layer latency by driver/operation.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"driver", "operation"}),

		ActiveSignatures: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "mirrors_waf",
			Subsystem: "storage",
			Name:      "active_signatures",
			Help:      "Current count of active generic-mode sign usage records.",
		}),

		PendingAutoBlocks: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "mirrors_waf",
			Subsystem: "pending",
			Name:      "auto_blocks_total",
			Help:      "Automatic temporary blocks triggered by the per-IP pending limit.",
		}),

		PowFlags: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "mirrors_waf",
			Subsystem: "pow",
			Name:      "flags",
			Help:      "Runtime PoW switches as 0/1 gauges, keyed by flag name.",
		}, []string{"flag"}),
	}
}

// BoolValue renders a boolean as a 0/1 gauge value.
func BoolValue(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

// Register attaches the container to the default Prometheus registry.
// Already-registered collectors are silently skipped (useful during re-init).
func (c *Container) Register() error {
	collectors := []prometheus.Collector{
		c.PowVerifyTotal,
		c.PowVerifyLatencySeconds,
		c.RiskDecisionTotal,
		c.StorageOperations,
		c.StorageLatencySeconds,
		c.ActiveSignatures,
		c.PendingAutoBlocks,
		c.PowFlags,
	}
	for _, col := range collectors {
		if err := prometheus.Register(col); err != nil {
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
				return err
			}
		}
	}
	return nil
}
