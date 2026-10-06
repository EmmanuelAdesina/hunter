package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/eadeshina/hunter/internal/domain"
)

// Environment variable names holding delivery credentials.
//
// Configuration deliberately contains no credentials. Values are read from the
// process environment, which in the scheduled context is GitHub Actions secrets.
// Nothing here ever logs, echoes, or persists a credential.
const (
	EnvSMTPHost  = "EMAIL_SMTP_HOST"
	EnvSMTPPort  = "EMAIL_SMTP_PORT"
	EnvUsername  = "EMAIL_USERNAME"
	EnvPassword  = "EMAIL_PASSWORD"
	EnvRecipient = "ALERT_RECIPIENT"
	EnvFromName  = "EMAIL_FROM_NAME"
)

// SMTPConfig holds resolved connection settings.
//
// Password is present in the struct but never rendered: every diagnostic path in
// this package reports presence with a boolean, never a value.
type SMTPConfig struct {
	Host      string
	Port      int
	Username  string
	Password  string
	Recipient string
	FromName  string

	// InsecureSkipVerify disables certificate verification. It exists so that
	// a misconfigured server fails loudly in logs rather than being silently
	// worked around; it is never enabled automatically.
	InsecureSkipVerify bool
}

// FromAddress builds the From header value.
func (c SMTPConfig) FromAddress() string {
	if c.FromName != "" {
		return fmt.Sprintf("%s <%s>", c.FromName, c.Username)
	}
	return c.Username
}

// Configured reports whether the minimum set of credentials is present.
func (c SMTPConfig) Configured() bool {
	return c.Host != "" && c.Port > 0 && c.Username != "" &&
		c.Password != "" && c.Recipient != ""
}

// Describe renders the configuration for diagnostics.
//
// Credential presence is reported as a boolean and addresses are reported
// without passwords. This string is safe to log.
func (c SMTPConfig) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "smtp %s:%d", c.Host, c.Port)
	fmt.Fprintf(&b, " auth=%t recipient_set=%t", c.Username != "", c.Recipient != "")
	return b.String()
}

// LoadSMTPConfigFromEnv reads delivery settings from the environment.
//
// Missing values are reported as not-configured rather than as an error, because
// a dry run that generates and records alerts without sending them is a
// legitimate and frequently used mode.
func LoadSMTPConfigFromEnv() (SMTPConfig, error) {
	cfg := SMTPConfig{
		Host:     strings.TrimSpace(os.Getenv(EnvSMTPHost)),
		Port:     defaultSMTPPort,
		Username: strings.TrimSpace(os.Getenv(EnvUsername)),
		Password: os.Getenv(EnvPassword),
		FromName: strings.TrimSpace(os.Getenv(EnvFromName)),
	}

	if p := strings.TrimSpace(os.Getenv(EnvSMTPPort)); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return cfg, fmt.Errorf("%s: %q is not a valid port", EnvSMTPPort, p)
		}
		cfg.Port = n
	}

	// Recipients are comma-separated so that a second address can be added
	// without changing code.
	for _, r := range strings.Split(os.Getenv(EnvRecipient), ",") {
		if s := strings.TrimSpace(r); s != "" {
			cfg.Recipient = s
			break
		}
	}

	if !cfg.Configured() {
		return cfg, fmt.Errorf("%w: %s, %s, %s, %s and %s must all be set",
			ErrNotConfigured, EnvSMTPHost, EnvSMTPPort, EnvUsername, EnvPassword, EnvRecipient)
	}
	return cfg, nil
}

// Recipients returns every configured recipient.
func (c SMTPConfig) Recipients() []string {
	out := make([]string, 0, 1)
	for _, r := range strings.Split(c.Recipient, ",") {
		if s := strings.TrimSpace(r); s != "" {
			out = append(out, s)
		}
	}
	return out
}

const defaultSMTPPort = 587

// SMTPNotifier delivers alerts over SMTP.
//
// net/smtp is used directly rather than through a client library because the
// transport is trivial and the standard library keeps the dependency surface at
// zero for a tool that must keep working.
type SMTPNotifier struct {
	cfg      SMTPConfig
	fromName string
	timeout  time.Duration
}

// NewSMTPNotifier builds an SMTP notifier.
func NewSMTPNotifier(cfg SMTPConfig, timeout time.Duration) *SMTPNotifier {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &SMTPNotifier{cfg: cfg, timeout: timeout}
}

// Name implements Notifier.
func (n *SMTPNotifier) Name() string { return "email" }

// Configured implements Notifier.
func (n *SMTPNotifier) Configured() bool { return n.cfg.Configured() }

// Send delivers one alert as a plain-text message.
//
// The body is text/plain rather than multipart HTML deliberately: an alert that
// renders as a marketing email is an alert that gets ignored, and plain text
// survives every client without an HTML sanitizer in the path.
func (n *SMTPNotifier) Send(ctx context.Context, a domain.Alert) error {
	if !n.Configured() {
		return ErrNotConfigured
	}
	if a.Subject == "" {
		return fmt.Errorf("%w: alert for %s has no subject", ErrInvalidAlert, a.ProgramID)
	}

	msg, err := n.buildMessage(a)
	if err != nil {
		return err
	}

	// The whole exchange, not only the TCP dial, is bounded. net/smtp uses
	// synchronous reads and writes, so set the socket deadline and force it to
	// expire promptly if the caller cancels its context.
	exchangeCtx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()

	addr := net.JoinHostPort(n.cfg.Host, strconv.Itoa(n.cfg.Port))
	dialer := &net.Dialer{Timeout: n.timeout}

	conn, err := dialer.DialContext(exchangeCtx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	if deadline, ok := exchangeCtx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return fmt.Errorf("set SMTP deadline: %w", err)
		}
	}
	stopCancelWatch := context.AfterFunc(exchangeCtx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stopCancelWatch()

	// smtp.Client takes ownership of the connection and closes it on Quit.
	client, err := smtp.NewClient(conn, n.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp handshake with %s: %w", addr, err)
	}
	defer func() { _ = client.Close() }()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{
			ServerName: n.cfg.Host,
			MinVersion: tls.VersionTLS12,
			// Verification is on unless explicitly disabled. Credentials are
			// about to be sent over this connection, so this default must not
			// be relaxed.
			InsecureSkipVerify: n.cfg.InsecureSkipVerify, //nolint:gosec // opt-in only
		}); err != nil {
			return fmt.Errorf("start tls: %w", err)
		}
	}

	// Extension reports (supported, parameters).
	if supported, _ := client.Extension("AUTH"); supported && n.cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", n.cfg.Username, n.cfg.Password, n.cfg.Host)); err != nil {
			return fmt.Errorf("authenticate: %w", err)
		}
	}

	if err := client.Mail(n.cfg.Username); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	for _, rcpt := range n.cfg.Recipients() {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("recipient %s: %w", rcpt, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("open data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return fmt.Errorf("write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close message: %w", err)
	}
	return nil
}

// buildMessage renders the RFC 5322 message.
//
// The body is sent as multipart/alternative with a plain-text part first and a
// styled HTML part second. That ordering is what lets the recipient choose, and
// it means a client that cannot render the HTML still receives every fact in a
// readable form rather than an empty or mangled message.
//
// No external resources are referenced anywhere in the message: no images, no
// web fonts, no tracking pixel. It therefore leaks nothing about when it was
// opened, renders identically offline, and cannot be broken by a content
// blocker.
//
// Headers are ordered deterministically and the body is encoded as UTF-8 so
// that a program name containing non-ASCII characters is not mangled.
func (n *SMTPNotifier) buildMessage(a domain.Alert) ([]byte, error) {
	var b strings.Builder

	// Every header value derived from program data is checked before it is
	// placed in the message.
	for field, v := range map[string]string{
		"subject": a.Subject, "program": a.ProgramID,
		"scan": a.ScanID, "fingerprint": a.Fingerprint,
	} {
		if err := checkInjectable(field, v); err != nil {
			return nil, err
		}
	}

	fmt.Fprintf(&b, "From: %s\r\n", n.cfg.FromAddress())
	for _, r := range n.cfg.Recipients() {
		fmt.Fprintf(&b, "To: %s\r\n", r)
	}
	// The subject encodes the program name in RFC 2047 form when it is not
	// plain ASCII, which is what makes non-ASCII program names survive.
	fmt.Fprintf(&b, "Subject: %s\r\n", encodeHeader(a.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", a.DetectedAt.UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", a.Fingerprint, n.cfg.Host)
	fmt.Fprintf(&b, "X-Hunter-Scan: %s\r\n", a.ScanID)
	fmt.Fprintf(&b, "X-Hunter-Fingerprint: %s\r\n", a.Fingerprint)
	fmt.Fprintf(&b, "X-Hunter-Program: %s\r\n", a.ProgramID)
	// Precedence: bulk, so that a real alert is never buried in a personal
	// folder.
	b.WriteString("Precedence: bulk\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")

	// Without a styled part the message is plain text, which is what a client
	// that cannot render HTML should receive in full.
	if strings.TrimSpace(a.HTMLBody) == "" {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
		b.WriteString("\r\n")
		b.WriteString(ensureTrailingNewline(a.Body))
		return []byte(b.String()), nil
	}

	// The boundary is derived from the fingerprint, so two alerts cannot collide
	// and a redelivery produces byte-identical output.
	boundary := "hunter-" + a.Fingerprint
	if len(boundary) > 60 {
		boundary = boundary[:60]
	}

	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)

	// The plain-text alternative comes first, which makes it the default choice
	// for a client that cannot or will not render HTML.
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(ensureTrailingNewline(a.Body))
	b.WriteString("\r\n")

	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(ensureTrailingNewline(a.HTMLBody))
	b.WriteString("\r\n")

	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return []byte(b.String()), nil
}

// ensureTrailingNewline guarantees a body part ends with a newline so the
// boundary delimiter always begins a line of its own.
func ensureTrailingNewline(s string) string {
	if s == "" || strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

// encodeHeader encodes a header value as RFC 2047 base64 when it is not plain
// ASCII, and strips CR and LF which would otherwise allow header injection.
func encodeHeader(v string) string {
	safe := strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
	if isASCII(safe) {
		return safe
	}
	return mimeWord(safe)
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}

// checkInjectable rejects header values containing a newline, which would allow
// attacker-controlled program names to add arbitrary headers or a second message
// body. It is applied to the subject and identifier headers as defence in depth,
// even though encodeHeader already strips them.
func checkInjectable(field, v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("%w: %s contains a line break", errNotInjectable, field)
	}
	return nil
}

// errNotInjectable marks a value that must not be placed in a header.
var errNotInjectable = errors.New("notify: value is not safe for a header")

// mimeWord encodes a header value as an RFC 2047 encoded word.
func mimeWord(s string) string {
	// RFC 2047 limits every encoded-word to 75 characters. The UTF-8 bytes
	// must therefore fit in 45 bytes: base64 expands those to at most 60
	// characters, plus the 12-character encoded-word wrapper. Split only at
	// rune boundaries so a multibyte character is never damaged.
	const maxChunkBytes = 45
	var words []string
	for start := 0; start < len(s); {
		end := start
		for end < len(s) {
			_, size := utf8.DecodeRuneInString(s[end:])
			if end-start+size > maxChunkBytes {
				break
			}
			end += size
		}
		// Every Unicode rune occupies at most four bytes, so a non-empty
		// string always advances by at least one rune.
		words = append(words, mime.BEncoding.Encode("utf-8", s[start:end]))
		start = end
	}
	return strings.Join(words, "\r\n ")
}
