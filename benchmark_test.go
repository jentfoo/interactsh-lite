package main

import (
	"io"
	"testing"
	"time"

	"github.com/go-appsec/interactsh-lite/oobclient"
)

func BenchmarkFormatOutput(b *testing.B) {
	now := time.Now()
	interactions := []*oobclient.Interaction{
		{
			Protocol:      "dns",
			FullId:        "abc123xyz",
			QType:         "A",
			RemoteAddress: "172.253.226.100",
			Timestamp:     now,
		},
		{
			Protocol:      "http",
			FullId:        "verbose123",
			RemoteAddress: "10.0.0.1",
			Timestamp:     now,
			RawRequest:    "GET / HTTP/1.1\nHost: test.com",
			RawResponse:   "HTTP/1.1 200 OK",
		},
		{
			Protocol:  "smb",
			FullId:    "smb123",
			Timestamp: now,
		},
	}

	b.Run("standard", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, interaction := range interactions {
				_ = formatStandard(io.Discard, interaction, false)
			}
		}
	})

	b.Run("verbose", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, interaction := range interactions {
				_ = formatStandard(io.Discard, interaction, true)
			}
		}
	})

	b.Run("json", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, interaction := range interactions {
				_ = formatJSON(io.Discard, interaction)
			}
		}
	})
}
