package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Container bundles every metric the application emits. All fields are
// read-only after construction.
type Container struct {
	PowVerifyTotal         *prometheus.CounterVec
	PowVerifyLatencySeconds *prometheus.HistogramVec
	RiskDecisionTotal      *prometheus.CounterVec
	StorageOperations      *prometheus.CounterVec
	StorageLatencySeconds  *prometheus.HistogramVec
	AdminActions           *prometheus.CounterVec
	ActiveSignatures       prometheus.Gauge
}

func New() *Container {
	return &Container{
		PowVerifyTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "mirrors_waf",
			Subsystem: "pow",
			Name:      "verify_total",
			Help:      "Total number of /verify_pow calls by result/reason/mode.",
		}, []string{"result", "reason", "mode"}),

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

		AdminActions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "mirrors_waf",
			Subsystem: "admin",
			Name:      "actions_total",
			Help:      "Admin-API action counts by action code (ok or err).",
		}, []string{"action", "outcome"}),

		ActiveSignatures: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "mirrors_waf",
			Subsystem: "storage",
			Name:      "active_signatures",
			Help:      "Current count of active generic-mode sign usage records.",
		}),
	}
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
		c.AdminActions,
		c.ActiveSignatures,
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
