package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	reg        *prometheus.Registry
	Clients    prometheus.Gauge
	Tunnels    prometheus.Gauge
	Requests   prometheus.Counter
	BytesIn    prometheus.Counter
	BytesOut   prometheus.Counter
	Enroll     prometheus.Counter
	Reconnects prometheus.Counter
}

func New() *Metrics {
	r := prometheus.NewRegistry()
	m := &Metrics{
		reg: r,
		Clients: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "passerelle_clients_connected",
			Help: "Connected Passerelle clients",
		}),
		Tunnels: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "passerelle_tunnels_open",
			Help: "Open tunnels",
		}),
		Requests: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "passerelle_public_requests_total",
			Help: "Public HTTP requests",
		}),
		BytesIn: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "passerelle_bytes_in_total",
			Help: "Bytes from visitors to origins",
		}),
		BytesOut: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "passerelle_bytes_out_total",
			Help: "Bytes from origins to visitors",
		}),
		Enroll: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "passerelle_enroll_total",
			Help: "Enrollment attempts",
		}),
		Reconnects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "passerelle_client_reconnects_total",
			Help: "Client session replacements",
		}),
	}
	r.MustRegister(m.Clients, m.Tunnels, m.Requests, m.BytesIn, m.BytesOut, m.Enroll, m.Reconnects)
	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{EnableOpenMetrics: true})
}
