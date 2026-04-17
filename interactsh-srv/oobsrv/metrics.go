package oobsrv

import (
	"net/http"
	"runtime"

	units "github.com/docker/go-units"
	"github.com/mackerelio/go-osstat/cpu"
	"github.com/mackerelio/go-osstat/network"
)

// metricsResponse is the GET /metrics JSON response.
type metricsResponse struct {
	DNS           uint64         `json:"dns"`
	DNSMatched    uint64         `json:"dns-matched"`
	FTP           uint64         `json:"ftp"`
	HTTP          uint64         `json:"http"`
	HTTPMatched   uint64         `json:"http-matched"`
	LDAP          uint64         `json:"ldap"`
	SMTP          uint64         `json:"smtp"`
	SMTPMatched   uint64         `json:"smtp-matched"`
	Sessions      uint64         `json:"sessions"`
	SessionsTotal uint64         `json:"sessions_total"`
	Cache         metricsCache   `json:"cache"`
	Memory        metricsMemory  `json:"memory"`
	CPU           metricsCPU     `json:"cpu"`
	Network       metricsNetwork `json:"network"`
}

type metricsCache struct {
	HitCount      uint64 `json:"hit-count"`
	MissCount     uint64 `json:"miss-count"`
	EvictionCount uint64 `json:"eviction-count"`
}

type metricsMemory struct {
	Alloc        string `json:"alloc"`
	TotalAlloc   string `json:"total_alloc"`
	Sys          string `json:"sys"`
	Lookups      uint64 `json:"lookups"`
	Mallocs      uint64 `json:"mallocs"`
	Frees        uint64 `json:"frees"`
	HeapAlloc    string `json:"heap_alloc"`
	HeapSys      string `json:"heap_sys"`
	HeapIdle     string `json:"heap_idle"`
	HeapInUse    string `json:"heap_in_use"`
	HeapReleased string `json:"heap_released"`
	HeapObjects  uint64 `json:"heap_objects"`
	StackInUse   string `json:"stack_in_use"`
	StackSys     string `json:"stack_sys"`
	MSpanInUse   string `json:"mspan_in_use"`
	MSpanSys     string `json:"mspan_sys"`
	MCacheInUse  string `json:"mcache_in_use"`
	MCacheSys    string `json:"mcache_sys"`
}

type metricsCPU struct {
	User   uint64 `json:"user"`
	System uint64 `json:"system"`
	Idle   uint64 `json:"idle"`
	Nice   uint64 `json:"nice"`
	Total  uint64 `json:"total"`
	Steal  uint64 `json:"steal"`
	Iowait uint64 `json:"iowait"`
}

type metricsNetwork struct {
	Received    string `json:"received"`
	Transmitted string `json:"transmitted"`
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	var cpuStats metricsCPU
	if stats, err := cpu.Get(); err != nil {
		s.logger.Error("failed to get CPU stats", "error", err)
	} else {
		cpuStats = metricsCPU{
			User:   stats.User,
			System: stats.System,
			Idle:   stats.Idle,
			Nice:   stats.Nice,
			Total:  stats.Total,
			Steal:  stats.Steal,
			Iowait: stats.Iowait,
		}
	}

	var netStats metricsNetwork
	if ifaces, err := network.Get(); err != nil {
		s.logger.Error("failed to get network stats", "error", err)
		netStats = metricsNetwork{Received: "0B", Transmitted: "0B"}
	} else {
		var rxTotal, txTotal uint64
		for _, iface := range ifaces {
			rxTotal += iface.RxBytes
			txTotal += iface.TxBytes
		}
		netStats = metricsNetwork{
			Received:    units.HumanSize(float64(rxTotal)),
			Transmitted: units.HumanSize(float64(txTotal)),
		}
	}

	resp := metricsResponse{
		DNS:           s.dnsCount.Load(),
		DNSMatched:    s.dnsMatched.Load(),
		FTP:           s.ftpCount.Load(),
		HTTP:          s.httpCount.Load(),
		HTTPMatched:   s.httpMatched.Load(),
		LDAP:          s.ldapCount.Load(),
		SMTP:          s.smtpCount.Load(),
		SMTPMatched:   s.smtpMatched.Load(),
		Sessions:      s.storage.SessionCount(),
		SessionsTotal: s.storage.SessionsTotal(),
		Cache: metricsCache{
			HitCount:      s.storage.HitCount(),
			MissCount:     s.storage.MissCount(),
			EvictionCount: s.storage.EvictionCount(),
		},
		Memory: metricsMemory{
			Alloc:        units.HumanSize(float64(ms.Alloc)),
			TotalAlloc:   units.HumanSize(float64(ms.TotalAlloc)),
			Sys:          units.HumanSize(float64(ms.Sys)),
			Lookups:      ms.Lookups,
			Mallocs:      ms.Mallocs,
			Frees:        ms.Frees,
			HeapAlloc:    units.HumanSize(float64(ms.HeapAlloc)),
			HeapSys:      units.HumanSize(float64(ms.HeapSys)),
			HeapIdle:     units.HumanSize(float64(ms.HeapIdle)),
			HeapInUse:    units.HumanSize(float64(ms.HeapInuse)),
			HeapReleased: units.HumanSize(float64(ms.HeapReleased)),
			HeapObjects:  ms.HeapObjects,
			StackInUse:   units.HumanSize(float64(ms.StackInuse)),
			StackSys:     units.HumanSize(float64(ms.StackSys)),
			MSpanInUse:   units.HumanSize(float64(ms.MSpanInuse)),
			MSpanSys:     units.HumanSize(float64(ms.MSpanSys)),
			MCacheInUse:  units.HumanSize(float64(ms.MCacheInuse)),
			MCacheSys:    units.HumanSize(float64(ms.MCacheSys)),
		},
		CPU:     cpuStats,
		Network: netStats,
	}

	s.writeJSON(w, http.StatusOK, resp)
}
