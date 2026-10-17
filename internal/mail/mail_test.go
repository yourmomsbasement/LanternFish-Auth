package mail

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestSettingsValidation(t *testing.T) {
	good := Settings{Enabled: true, Host: "127.0.0.1", Port: 25, FromEmail: "sender@example.com"}
	if good.Validate() != nil {
		t.Fatal("valid settings rejected")
	}
	for _, change := range []func(*Settings){func(s *Settings) { s.Host = "" }, func(s *Settings) { s.Port = 0 }, func(s *Settings) { s.FromEmail = "bad" }, func(s *Settings) { s.FromName = "x\r\nBcc: bad@example.com" }} {
		s := good
		change(&s)
		if s.Validate() == nil {
			t.Fatal("invalid settings accepted")
		}
	}
	for _, a := range []string{"bad", "a@example.com\r\nBcc: b@example.com", "Name <a@example.com>"} {
		if Address(a) {
			t.Fatalf("accepted %q", a)
		}
	}
}
func TestSMTPSubmission(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	done := make(chan string, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			done <- ""
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		fmt.Fprint(c, "220 relay ESMTP\r\n")
		var msg strings.Builder
		for {
			line, e := r.ReadString('\n')
			if e != nil {
				done <- msg.String()
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				fmt.Fprint(c, "250 relay\r\n")
			case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
				fmt.Fprint(c, "250 OK\r\n")
			case strings.HasPrefix(line, "DATA"):
				fmt.Fprint(c, "354 send\r\n")
				for {
					l, e := r.ReadString('\n')
					if e != nil {
						done <- ""
						return
					}
					if l == ".\r\n" {
						break
					}
					msg.WriteString(l)
				}
				fmt.Fprint(c, "250 queued\r\n")
			case strings.HasPrefix(line, "QUIT"):
				fmt.Fprint(c, "221 bye\r\n")
				done <- msg.String()
				return
			default:
				fmt.Fprint(c, "500 unknown\r\n")
			}
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	m := SMTPMailer{Settings: Settings{Enabled: true, Host: "127.0.0.1", Port: addr.Port, FromEmail: "sender@example.com", FromName: "LanternFish"}}
	if e = m.Send(context.Background(), Message{To: "user@example.com", Subject: "Test", TextBody: "Hello"}); e != nil {
		t.Fatal(e)
	}
	msg := <-done
	if !strings.Contains(msg, "Auto-Submitted: auto-generated") || !strings.Contains(msg, "Hello") {
		t.Fatal("missing message contents")
	}
	m.Settings.StartTLS = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if m.Send(ctx, Message{To: "user@example.com"}) == nil {
		t.Fatal("cancelled send succeeded")
	}
}
func TestSMTPConnectionFailure(t *testing.T) {
	m := SMTPMailer{Settings: Settings{Enabled: true, Host: "127.0.0.1", Port: 1, FromEmail: "sender@example.com"}}
	if m.Send(context.Background(), Message{To: "user@example.com"}) == nil {
		t.Fatal("expected connection error")
	}
}
