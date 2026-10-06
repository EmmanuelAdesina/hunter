package notify

import (
	"context"
	"mime"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
)

func TestMimeWordChunksStayWithinRFC2047Limit(t *testing.T) {
	input := strings.Repeat("é🌍", 100)
	encoded := mimeWord(input)
	words := strings.Split(encoded, "\r\n ")
	if len(words) < 2 {
		t.Fatalf("encoded words = %d, want multiple chunks", len(words))
	}
	for i, word := range words {
		if len(word) > 75 {
			t.Errorf("encoded word %d has %d characters, RFC 2047 limit is 75", i, len(word))
		}
	}
	decoded, err := (&mime.WordDecoder{}).DecodeHeader(encoded)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if decoded != input {
		t.Errorf("decoded subject differs from input: got %q, want %q", decoded, input)
	}
}

func TestSMTPTimeoutBoundsGreetingAndExchange(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	releaseServer := make(chan struct{})
	defer close(releaseServer)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-releaseServer
	}()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	const timeout = 100 * time.Millisecond
	notifier := NewSMTPNotifier(SMTPConfig{
		Host: host, Port: port, Username: "sender@example.test",
		Password: "password", Recipient: "researcher@example.test",
	}, timeout)
	alert := domain.Alert{
		Fingerprint: "fp-timeout", ProgramID: "program:timeout", ScanID: "scan",
		Subject: "test notification", Body: "body", DetectedAt: time.Now(),
	}

	started := time.Now()
	err = notifier.Send(context.Background(), alert)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("Send succeeded despite the server never sending an SMTP greeting")
	}
	if elapsed > time.Second {
		t.Errorf("SMTP exchange took %s, want it bounded near %s", elapsed, timeout)
	}
}
