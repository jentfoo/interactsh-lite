package oobsrv

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// smtpBackend implements smtp.Backend for OOB interaction capture.
type smtpBackend struct {
	server *Server
}

// Compiler check that smtpBackend implements smtp.Backend.
var _ smtp.Backend = (*smtpBackend)(nil)

func (b *smtpBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &smtpSession{
		server:     b.server,
		remoteAddr: c.Conn().RemoteAddr().String(),
	}, nil
}

type smtpSession struct {
	server     *Server
	remoteAddr string
	from       string
	recipients []string
}

// Compiler check that smtpSession implements smtp.AuthSession.
var _ smtp.AuthSession = (*smtpSession)(nil)

func (s *smtpSession) AuthMechanisms() []string {
	return []string{"PLAIN", "LOGIN", "CRAM-MD5"}
}

func (s *smtpSession) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case "PLAIN":
		return sasl.NewPlainServer(func(_, _, _ string) error {
			return nil
		}), nil
	case "LOGIN":
		return &loginServer{}, nil
	case "CRAM-MD5":
		return &cramMD5Server{}, nil
	default:
		return nil, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

func (s *smtpSession) Mail(from string, opts *smtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *smtpSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.recipients = append(s.recipients, to)
	return nil
}

func (s *smtpSession) Data(r io.Reader) error {
	// Limit what we store but accept the full message (SIZE 0 advertised)
	orig := r
	if s.server.cfg.MaxRequestSize > 0 {
		r = io.LimitReader(r, int64(s.server.cfg.MaxRequestSize)*1024*1024)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	// Drain any excess so the SMTP transaction completes successfully
	_, _ = io.Copy(io.Discard, orig)
	s.server.onSMTPData(s.from, s.recipients, body, s.remoteAddr)
	return nil
}

func (s *smtpSession) Reset() {
	s.from = ""
	s.recipients = nil
}

func (s *smtpSession) Logout() error {
	return nil
}

// loginServer implements sasl.Server for the LOGIN mechanism.
type loginServer struct {
	gotUsername bool
}

// Compiler check that loginServer implements sasl.Server.
var _ sasl.Server = (*loginServer)(nil)

func (s *loginServer) Next(response []byte) ([]byte, bool, error) {
	if !s.gotUsername {
		if len(response) == 0 {
			return []byte("Username:"), false, nil
		}
		s.gotUsername = true
		return []byte("Password:"), false, nil
	}
	return nil, true, nil
}

// cramMD5Server implements sasl.Server for the CRAM-MD5 mechanism.
type cramMD5Server struct {
	challenged bool
}

// Compiler check that cramMD5Server implements sasl.Server.
var _ sasl.Server = (*cramMD5Server)(nil)

func (s *cramMD5Server) Next(response []byte) ([]byte, bool, error) {
	if !s.challenged {
		s.challenged = true
		challenge := fmt.Sprintf("<%d@interactsh>", time.Now().UnixNano())
		return []byte(challenge), false, nil
	}
	return nil, true, nil
}

// onSMTPData processes a completed SMTP message, matching each recipient against registered correlation IDs.
func (s *Server) onSMTPData(from string, recipients []string, body []byte, remoteAddr string) {
	s.smtpCount.Add(1)

	remoteIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteIP = remoteAddr
	}

	bodyStr := string(body)
	now := time.Now().UTC()

	for _, rcpt := range recipients {
		s.captureSMTPInteraction(from, rcpt, bodyStr, remoteIP, now)
	}
}

func (s *Server) captureSMTPInteraction(from, rcpt, body, remoteIP string, now time.Time) {
	_, recipientDomain, ok := strings.Cut(rcpt, "@")
	if !ok {
		return
	}
	recipientDomain = strings.ToLower(recipientDomain)

	domain, domainOk := s.matchedDomain(recipientDomain)
	if !domainOk {
		return
	}

	s.captureInteraction(domain, recipientDomain, "", InteractionType{
		Protocol:      "smtp",
		UniqueID:      recipientDomain,
		FullId:        recipientDomain,
		RawRequest:    body,
		SMTPFrom:      from,
		SMTPTo:        rcpt,
		RemoteAddress: remoteIP,
		Timestamp:     now,
	}, InteractionType{
		Protocol:      "smtp",
		RawRequest:    body,
		SMTPFrom:      from,
		SMTPTo:        rcpt,
		RemoteAddress: remoteIP,
		Timestamp:     now,
	})
}

// smtpService wraps a go-smtp Server and its listener as a Service.
type smtpService struct {
	name     string
	logger   *slog.Logger
	server   *smtp.Server
	listener net.Listener
}

// Compiler check that smtpService implements Service.
var _ Service = (*smtpService)(nil)

// slogSMTPLogger adapts *slog.Logger to go-smtp's Logger interface,
// routing connection-level errors to debug (normal internet noise).
type slogSMTPLogger struct {
	logger *slog.Logger
}

func (l *slogSMTPLogger) Printf(format string, v ...interface{}) {
	l.logger.Debug(fmt.Sprintf(format, v...))
}

func (l *slogSMTPLogger) Println(v ...interface{}) {
	l.logger.Debug(fmt.Sprint(v...))
}

func (s *smtpService) Name() string { return s.name }

func (s *smtpService) Start() error {
	go func() {
		s.logger.Info(fmt.Sprintf("[%s] Listening on TCP %s", s.name, s.listener.Addr()))
		if err := s.server.Serve(s.listener); err != nil {
			s.logger.Debug("smtp service stopped", "name", s.name, "error", err)
		}
	}()
	return nil
}

func (s *smtpService) Close() error {
	return s.server.Close()
}

func (s *Server) startSMTP() {
	backend := &smtpBackend{server: s}
	hostname := s.cfg.Domains[0]

	// Port 25: plain SMTP
	s.startSMTPPort(backend, hostname, s.cfg.SMTPPort, "SMTP", nil, false)

	// Port 587: STARTTLS (plaintext with optional TLS upgrade)
	s.startSMTPPort(backend, hostname, s.cfg.SMTPSPort, "SMTP-STARTTLS", s.tlsConfig, false)

	// Port 465: implicit TLS (only if TLS available)
	if s.tlsConfig != nil {
		s.startSMTPPort(backend, hostname, s.cfg.SMTPAutoTLSPort, "SMTPS", s.tlsConfig, true)
	} else {
		s.logger.Info("SMTPS (implicit TLS) disabled, no TLS config")
	}
}

// startSMTPPort binds and starts a single SMTP listener. Non-fatal on bind failure.
func (s *Server) startSMTPPort(backend smtp.Backend, hostname string, port int, name string, tlsCfg *tls.Config, implicitTLS bool) {
	addr := net.JoinHostPort(s.cfg.ListenIP, strconv.Itoa(port))

	smtpSrv := smtp.NewServer(backend)
	smtpSrv.Domain = hostname
	smtpSrv.AllowInsecureAuth = true
	// Do not set MaxMessageBytes: advertise SIZE 0 (unlimited) so clients never refuse to send
	// Body truncation is handled in Data()
	smtpSrv.ErrorLog = &slogSMTPLogger{logger: s.logger}

	// STARTTLS: set TLSConfig so the server advertises STARTTLS in EHLO
	if tlsCfg != nil && !implicitTLS {
		smtpSrv.TLSConfig = tlsCfg
	}

	var ln net.Listener
	var err error
	if implicitTLS {
		ln, err = tls.Listen("tcp", addr, tlsCfg)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		s.logger.Warn(fmt.Sprintf("[%s] bind failed, skipping", name), "addr", addr, "error", err)
		return
	}

	svc := &smtpService{
		name:     name,
		logger:   s.logger,
		server:   smtpSrv,
		listener: ln,
	}
	if err := svc.Start(); err != nil {
		s.logger.Warn(fmt.Sprintf("[%s] start failed, skipping", name), "error", err)
		_ = ln.Close()
		return
	}
	s.addService(svc)
}
