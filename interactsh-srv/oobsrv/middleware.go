package oobsrv

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
)

// InteractionCallback receives captured HTTP data from logger middleware.
// hostname/domain are pre-computed by the handler and cached on the recorder.
type InteractionCallback func(r *http.Request, rawReq, rawResp, remoteAddr, hostname, domain string)

var respBufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

var httpRespPrefixMap = make(map[int]string, 100) // cache of response lines for performance

func init() {
	for status := 100; status < 600; status++ {
		if text := http.StatusText(status); text != "" {
			httpRespPrefixMap[status] = fmt.Sprintf("HTTP/1.1 %d %s\r\n", status, text)
		}
	}
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{
		statusCode: http.StatusOK,
		header:     make(http.Header),
	}
}

// responseRecorder buffers an HTTP response for later inspection and forwarding.
type responseRecorder struct {
	statusCode  int
	header      http.Header
	body        bytes.Buffer
	wroteHeader bool
	hostname    string // set by handler, read by middleware callback
	domain      string
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.statusCode = code
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.body.Write(b)
}

// CORSMiddleware adds CORS headers for API endpoints and short-circuits
// OPTIONS with 204. Uses the configured Access-Control-Allow-Origin value.
func CORSMiddleware(acaoURL string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", acaoURL)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// InteractionCORSMiddleware sets maximally permissive CORS headers for
// interaction capture responses. It reflects the request Origin (or "*" when
// absent) and enables credentials so preflighted cross-origin requests from
// XSS/SSRF payloads fire and get captured.
func InteractionCORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Vary", "Origin")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware rejects requests without a valid token. Passes all through when disabled.
func AuthMiddleware(enabled bool, token string, next http.Handler) http.Handler {
	if !enabled {
		return next
	}
	tokenBytes := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), tokenBytes) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// LoggerMiddleware captures HTTP request/response data for interaction storage.
// Wraps the handler with a response recorder and calls the callback before forwarding.
func LoggerMiddleware(originIPHeader string, onInteraction InteractionCallback, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dump request before handler to preserve body
		rawReq, _ := httputil.DumpRequest(r, true)

		rec := newResponseRecorder()
		next.ServeHTTP(rec, r)

		if onInteraction != nil {
			// Build response dump directly, avoiding http.Response + header.Clone()
			respBuf := respBufPool.Get().(*bytes.Buffer)
			respBuf.Reset()
			respPrefix := httpRespPrefixMap[rec.statusCode]
			if respPrefix == "" { // unknown status code
				respPrefix = fmt.Sprintf("HTTP/1.1 %d OK\r\n", rec.statusCode)
			}
			respBuf.WriteString(respPrefix)
			_ = rec.header.Write(respBuf)
			respBuf.WriteString("\r\n")
			respBuf.Write(rec.body.Bytes())

			remoteAddr := ExtractRemoteAddr(r, originIPHeader)

			onInteraction(r, string(rawReq), respBuf.String(), remoteAddr, rec.hostname, rec.domain)
			respBufPool.Put(respBuf)
		}

		// Forward buffered response to client
		maps.Copy(w.Header(), rec.header)
		w.WriteHeader(rec.statusCode)
		_, _ = w.Write(rec.body.Bytes())
	})
}

// ResponseHeadersMiddleware sets Server and X-Interactsh-Version headers on all
// responses. API endpoints additionally get Content-Type and X-Content-Type-Options headers.
func ResponseHeadersMiddleware(serverHeader, version string, disableVersion, isAPI bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", serverHeader)
		if !disableVersion {
			w.Header().Set("X-Interactsh-Version", version)
		}
		if isAPI {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
		}
		next.ServeHTTP(w, r)
	})
}

// MaxRequestSizeMiddleware limits request body to maxMB megabytes. Zero or negative disables.
func MaxRequestSizeMiddleware(maxMB int, next http.Handler) http.Handler {
	if maxMB <= 0 {
		return next
	}
	maxBytes := int64(maxMB) * 1024 * 1024
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = io.NopCloser(io.LimitReader(r.Body, maxBytes))
		}
		next.ServeHTTP(w, r)
	})
}

// ExtractRemoteAddr returns the client IP, preferring originIPHeader if set.
func ExtractRemoteAddr(r *http.Request, originIPHeader string) string {
	if originIPHeader != "" {
		if val := r.Header.Get(originIPHeader); val != "" {
			return val
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
