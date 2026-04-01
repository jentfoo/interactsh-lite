package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-appsec/interactsh-lite/oobclient"
)

const (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiDim     = "\033[2m"
	ansiBlack   = "\033[30m"
	ansiRed     = "\033[31m"
	ansiGreen   = "\033[32m"
	ansiYellow  = "\033[33m"
	ansiBlue    = "\033[34m"
	ansiMagenta = "\033[35m"
	ansiCyan    = "\033[36m"
	ansiWhite   = "\033[37m"
)

// tag prefixes for log messages, plain by default
var (
	tagINF   = "[INF]"
	tagWRN   = "[WRN]"
	tagERR   = "[ERR]"
	useColor = false
)

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func enableColors() {
	useColor = true
	tagINF = "[" + ansiBlue + "INF" + ansiReset + "]"
	tagWRN = "[" + ansiYellow + "WRN" + ansiReset + "]"
	tagERR = "[" + ansiRed + "ERR" + ansiReset + "]"
}

func styleWrap(code, s string) string {
	if useColor {
		return code + s + ansiReset
	}
	return s
}

func styleAppend(sb *bytes.Buffer, code, s string) {
	if useColor {
		sb.WriteString(code)
		sb.WriteString(s)
		sb.WriteString(ansiReset)
	} else {
		sb.WriteString(s)
	}
}

func formatStandard(w io.Writer, i *oobclient.Interaction, verbose bool) error {
	protocol := styleWrap(ansiBold, strings.ToUpper(i.Protocol))

	var b bytes.Buffer

	b.WriteByte('[')
	styleAppend(&b, ansiCyan, i.FullId)
	b.WriteString("] ")
	b.WriteString(protocol)

	switch strings.ToLower(i.Protocol) {
	case "dns":
		b.WriteByte(' ')
		styleAppend(&b, ansiBold, "("+i.QType+")")
		b.WriteString(" from ")
		styleAppend(&b, ansiBold, i.RemoteAddress)
	case "smb", "responder":
		// no remote address
	default:
		b.WriteString(" from ")
		styleAppend(&b, ansiBold, i.RemoteAddress)
	}

	b.WriteString(" at ")
	b.WriteString(i.Timestamp.Format(time.DateTime))
	b.WriteByte('\n')

	if _, err := w.Write(b.Bytes()); err != nil {
		return err
	}

	if verbose {
		if i.RawRequest != "" {
			_, _ = fmt.Fprintf(w, "-----------\n%s Request\n-----------\n\n%s\n", protocol, i.RawRequest)
		}
		if i.RawResponse != "" {
			_, _ = fmt.Fprintf(w, "------------\n%s Response\n------------\n\n%s\n", protocol, i.RawResponse)
		}
	}
	return nil
}

type jsonInteraction struct {
	Protocol      string    `json:"protocol"`
	UniqueID      string    `json:"unique-id"`
	FullId        string    `json:"full-id"`
	QType         string    `json:"q-type,omitempty"`
	RawRequest    string    `json:"raw-request,omitempty"`
	RawResponse   string    `json:"raw-response,omitempty"`
	SMTPFrom      string    `json:"smtp-from,omitempty"`
	RemoteAddress string    `json:"remote-address"`
	Timestamp     time.Time `json:"timestamp"`
}

func formatJSON(w io.Writer, i *oobclient.Interaction) error {
	ji := jsonInteraction{
		Protocol:      strings.ToLower(i.Protocol),
		UniqueID:      i.UniqueID,
		FullId:        i.FullId,
		QType:         i.QType,
		RawRequest:    i.RawRequest,
		RawResponse:   i.RawResponse,
		SMTPFrom:      i.SMTPFrom,
		RemoteAddress: i.RemoteAddress,
		Timestamp:     i.Timestamp.UTC(),
	}

	data, err := json.Marshal(ji)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// expandPatterns expands pattern values that may be files or comma-separated patterns.
func expandPatterns(values []string) ([]string, error) {
	var result []string
	for _, v := range values {
		if info, err := os.Stat(v); err == nil && !info.IsDir() {
			f, err := os.Open(v)
			if err != nil {
				return nil, err
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					result = append(result, line)
				}
			}
			if err := scanner.Err(); err != nil {
				_ = f.Close()
				return nil, err
			}
			_ = f.Close()
		} else {
			result = append(result, ParseCommaSeparated(v)...)
		}
	}
	return result, nil
}

func compilePatterns(patterns []string, kind string) ([]*regexp.Regexp, error) {
	regexes := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid %s pattern %q: %w", kind, p, err)
		}
		regexes = append(regexes, re)
	}
	return regexes, nil
}

// shouldDisplay checks protocol filters (OR behavior) and regex patterns.
func shouldDisplay(i *oobclient.Interaction, dnsOnly, httpOnly, smtpOnly, ftpOnly, ldapOnly bool, matchRegexes, filterRegexes []*regexp.Regexp) bool {
	noFilter := !dnsOnly && !httpOnly && !smtpOnly && !ftpOnly && !ldapOnly

	// Protocol filters use OR logic: show if no filter set, or if matching filter is set
	switch strings.ToLower(i.Protocol) {
	case "dns":
		if !noFilter && !dnsOnly {
			return false
		}
	case "http", "https":
		if !noFilter && !httpOnly {
			return false
		}
	case "smtp":
		if !noFilter && !smtpOnly {
			return false
		}
	case "ftp":
		if !noFilter && !ftpOnly {
			return false
		}
	case "ldap":
		if !noFilter && !ldapOnly {
			return false
		}
	default:
		// SMB, responder, etc. only show when no protocol filter is active
		if !noFilter {
			return false
		}
	}

	matchesInteraction := func(re *regexp.Regexp, i *oobclient.Interaction) bool {
		return re.MatchString(i.FullId) || re.MatchString(i.RawRequest) ||
			re.MatchString(i.RawResponse) || re.MatchString(i.RemoteAddress)
	}

	// Match patterns: at least one must match if specified
	if len(matchRegexes) > 0 {
		var matched bool
		for _, re := range matchRegexes {
			if matchesInteraction(re, i) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Filter patterns: none must match
	for _, re := range filterRegexes {
		if matchesInteraction(re, i) {
			return false
		}
	}

	return true
}
